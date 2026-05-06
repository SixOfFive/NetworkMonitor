#!/usr/bin/env python3
"""LAN Monitor — pings every IP in a range, tracks MAC/hostname, serves a dashboard.

Pure stdlib. Cross-platform (Windows/Linux/macOS).

Example:
    python netmon.py --port 8081 --start 192.168.15.1 --end 192.168.15.254
"""
import argparse
import json
import os
import platform
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

IS_WINDOWS = platform.system().lower() == "windows"
LEAVE_AFTER_SECONDS = 300   # mark device as departed after this many seconds of silence
STALE_AFTER_SECONDS = 30    # mark dot yellow if silent this long but not yet departed

PING_TIME_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)
MAC_RE = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Hostname lookups can stall on missing PTR records; keep them snappy.
socket.setdefaulttimeout(2.0)


# ---------- network range helpers ----------

def ip_to_int(ip):
    a, b, c, d = (int(x) for x in ip.split("."))
    return (a << 24) | (b << 16) | (c << 8) | d


def int_to_ip(n):
    return f"{(n >> 24) & 0xff}.{(n >> 16) & 0xff}.{(n >> 8) & 0xff}.{n & 0xff}"


def ip_range(start, end):
    s, e = ip_to_int(start), ip_to_int(end)
    if e < s:
        raise ValueError("end IP must be >= start IP")
    return [int_to_ip(n) for n in range(s, e + 1)]


# ---------- probing ----------

def _popen_kwargs():
    if IS_WINDOWS:
        return {"creationflags": 0x08000000}  # CREATE_NO_WINDOW
    return {}


def ping_one(ip, timeout_ms=600):
    """Return ping time in ms, or None if no reply."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=(timeout_ms / 1000.0) + 1.5,
            **_popen_kwargs(),
        )
    except (subprocess.TimeoutExpired, OSError):
        return None
    out = result.stdout.decode("utf-8", errors="ignore")
    # Windows quirk: "Destination host unreachable" can return rc 0 with no Reply.
    has_reply = ("Reply from" in out) or ("bytes from" in out)
    if not has_reply:
        return None
    if "unreachable" in out.lower():
        return None
    m = PING_TIME_RE.search(out)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            pass
    return 0.5  # reply seen but no parseable time → assume sub-ms


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


# ---------- minimal mDNS (Avahi / Bonjour) PTR resolver ----------

def _encode_dns_name(name):
    out = bytearray()
    for label in name.split("."):
        if not label:
            continue
        b = label.encode("ascii", errors="ignore")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def _decode_dns_name(data, offset):
    """Decode possibly-compressed DNS name. Returns (name, offset_after_field)."""
    labels = []
    jumped = False
    after_jump = offset
    safety = 16
    while safety > 0:
        if offset >= len(data):
            return None, after_jump
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                after_jump = offset
            return ".".join(labels), after_jump
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                return None, after_jump
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                after_jump = offset + 2
            jumped = True
            offset = ptr
            safety -= 1
            continue
        offset += 1
        if offset + length > len(data):
            return None, after_jump
        labels.append(data[offset:offset + length].decode("ascii", errors="ignore"))
        offset += length
    return None, after_jump


def _parse_mdns_ptr_response(data):
    if len(data) < 12:
        return None
    qd = int.from_bytes(data[4:6], "big")
    an = int.from_bytes(data[6:8], "big")
    if an == 0:
        return None
    offset = 12
    for _ in range(qd):
        _, offset = _decode_dns_name(data, offset)
        if offset is None:
            return None
        offset += 4  # qtype + qclass
    for _ in range(an):
        _, offset = _decode_dns_name(data, offset)
        if offset is None or offset + 10 > len(data):
            return None
        rtype = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        offset += 2  # class
        offset += 4  # ttl
        rdlen = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        if rtype == 12:  # PTR
            name, _ = _decode_dns_name(data, offset)
            if name:
                return name.rstrip(".")
        offset += rdlen
    return None


def mdns_resolve(ip, timeout=0.6):
    """Ask the device on `ip` (and the LAN multicast group) for its mDNS PTR name."""
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    header = (b"\x00\x00"   # id (mDNS: 0)
              b"\x00\x00"   # flags: standard query
              b"\x00\x01"   # 1 question
              b"\x00\x00\x00\x00\x00\x00")
    qname = _encode_dns_name(rev)
    # qtype=PTR(12), qclass=IN(1) | QU bit (0x8000) → request unicast response
    packet = header + qname + b"\x00\x0c" + b"\x80\x01"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        # Unicast directly to the device (works for Bonjour/Avahi/most mDNS responders).
        try:
            sock.sendto(packet, (ip, 5353))
        except OSError:
            pass
        # Multicast fallback in case unicast is filtered.
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            sock.sendto(packet, ("224.0.0.251", 5353))
        except OSError:
            pass

        deadline = time.time() + timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(4096)
            except (socket.timeout, OSError):
                return None
            # Accept replies from the target IP, or from the multicast group relayed by it.
            if addr[0] != ip and addr[0] != "224.0.0.251":
                continue
            name = _parse_mdns_ptr_response(data)
            if name:
                return name
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ---------- mDNS service enumeration (catches iPhones, iPads, Apple TVs,
#            HomeKit, Chromecasts, AirPlay/Cast-enabled phones, etc.) ----------

# Service types whose instance names tend to embed the device's friendly name
# (e.g. "John's iPhone._companion-link._tcp.local").
_MDNS_SERVICES = (
    "_services._dns-sd._udp.local",     # meta: enumerate all advertised services
    "_companion-link._tcp.local",        # iPhone, iPad, Apple Watch, Mac
    "_homekit._tcp.local",               # HomeKit
    "_airplay._tcp.local",               # Apple TV, AirPlay receivers
    "_raop._tcp.local",                  # AirPlay audio
    "_apple-mobdev2._tcp.local",         # iOS sync
    "_rdlink._tcp.local",                # iOS Continuity
    "_googlecast._tcp.local",            # Chromecast / Cast-enabled phones
    "_googlezone._tcp.local",            # Google Home group
    "_workstation._tcp.local",           # Linux/Avahi
    "_device-info._tcp.local",
    "_smb._tcp.local",
    "_ssh._tcp.local",
    "_printer._tcp.local",
    "_ipp._tcp.local",
    "_ipps._tcp.local",
)


def _parse_mdns_all_ptr_targets(data):
    """Yield (qname, target) for every PTR record across answer/authority/additional sections."""
    if len(data) < 12:
        return
    qd = int.from_bytes(data[4:6], "big")
    an = int.from_bytes(data[6:8], "big")
    ns = int.from_bytes(data[8:10], "big")
    ar = int.from_bytes(data[10:12], "big")
    offset = 12
    for _ in range(qd):
        _, offset = _decode_dns_name(data, offset)
        if offset is None or offset + 4 > len(data):
            return
        offset += 4
    for _ in range(an + ns + ar):
        rname, offset = _decode_dns_name(data, offset)
        if offset is None or offset + 10 > len(data):
            return
        rtype = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        offset += 2  # class
        offset += 4  # ttl
        rdlen = int.from_bytes(data[offset:offset + 2], "big")
        offset += 2
        rdata_start = offset
        if rtype == 12:  # PTR
            target, _ = _decode_dns_name(data, offset)
            if target:
                yield (rname or "").rstrip("."), target.rstrip(".")
        offset = rdata_start + rdlen


def mdns_device_name(ip, timeout=1.0):
    """Probe `ip` via mDNS service-type queries and extract a friendly device name."""
    qcount = len(_MDNS_SERVICES)
    header = (b"\x00\x00"
              b"\x00\x00"
              + qcount.to_bytes(2, "big")
              + b"\x00\x00\x00\x00\x00\x00")
    questions = b""
    for svc in _MDNS_SERVICES:
        questions += _encode_dns_name(svc) + b"\x00\x0c" + b"\x80\x01"
    packet = header + questions

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.sendto(packet, (ip, 5353))
        except OSError:
            pass
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            sock.sendto(packet, ("224.0.0.251", 5353))
        except OSError:
            pass

        deadline = time.time() + timeout
        seen_targets = []
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                data, addr = sock.recvfrom(8192)
            except (socket.timeout, OSError):
                break
            if addr[0] != ip and addr[0] != "224.0.0.251":
                continue
            for _qname, target in _parse_mdns_all_ptr_targets(data):
                if target and target not in seen_targets:
                    seen_targets.append(target)
    finally:
        try:
            sock.close()
        except OSError:
            pass

    # Pull instance names out of "instance._service._proto.local" targets.
    candidates = []
    for tgt in seen_targets:
        low = tgt.lower()
        # Strip well-known service suffixes to recover the human-readable instance name.
        for svc in _MDNS_SERVICES:
            suffix = "." + svc.lower()
            if low.endswith(suffix) and len(tgt) > len(suffix):
                instance = tgt[:-len(suffix)]
                if instance and instance not in candidates:
                    candidates.append(instance)
                break
        else:
            # Bare hostname like "iPhone.local" — keep as-is.
            if low.endswith(".local") and tgt.count(".") == 1:
                if tgt not in candidates:
                    candidates.append(tgt)

    if not candidates:
        return None
    # Prefer the longest candidate (typically the friendly name vs an ID).
    candidates.sort(key=lambda s: (-len(s), s.lower()))
    return candidates[0]


# ---------- minimal NetBIOS / WINS Node Status query (UDP 137) ----------

def _nb_encode_name(name16):
    """Level-1 NetBIOS name encoding: each byte split into two nibbles + 0x41."""
    out = bytearray()
    for b in name16:
        out.append(((b >> 4) & 0xF) + 0x41)
        out.append((b & 0xF) + 0x41)
    return bytes(out)


# Wildcard name "*" padded with NULs, encoded once.
_NB_WILDCARD_ENCODED = _nb_encode_name(b"*" + b"\x00" * 15)


# Names that are well-known NetBIOS browser/workgroup junk, never useful as a host name.
_NB_JUNK_NAMES = {
    "WORKGROUP", "MSHOME", "HOME", "LOCAL", "DOMAIN",
    "__MSBROWSE__", "\x01\x02__MSBROWSE__\x02",
}


def _nb_clean_name(raw_bytes):
    """Decode a 15-byte NetBIOS name field; strip pad bytes and reject control chars."""
    s = raw_bytes.decode("ascii", errors="ignore")
    # NetBIOS pads with 0x20 (spaces); some implementations pad with NULs.
    s = s.rstrip(" \t\x00")
    # Reject if contains non-printables (after stripping pad).
    for c in s:
        if ord(c) < 0x20 or ord(c) > 0x7E:
            return ""
    return s


def nbns_name(ip, timeout=0.6):
    """Send a NetBIOS Node Status Request (NBSTAT) to ip:137. Returns the workstation name or None.

    Works against any host running NetBIOS-over-TCP (Windows file/print sharing, Samba).
    """
    header = (b"\x42\x42"        # transaction id
              b"\x00\x00"        # flags: standard query
              b"\x00\x01"        # 1 question
              b"\x00\x00\x00\x00\x00\x00")
    qname = bytes([0x20]) + _NB_WILDCARD_ENCODED + b"\x00"
    packet = header + qname + b"\x00\x21" + b"\x00\x01"  # qtype NBSTAT, qclass IN

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.sendto(packet, (ip, 137))
        except OSError:
            return None
        try:
            data, _addr = sock.recvfrom(4096)
        except (socket.timeout, OSError):
            return None
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if len(data) < 12:
        return None
    offset = 12
    # Skip question name (length-prefixed labels terminated by 0).
    while offset < len(data) and data[offset] != 0:
        if (data[offset] & 0xC0) == 0xC0:
            offset += 2
            break
        offset += data[offset] + 1
    else:
        offset += 1
    offset += 4  # qtype + qclass
    # Skip answer name.
    if offset >= len(data):
        return None
    while offset < len(data) and data[offset] != 0:
        if (data[offset] & 0xC0) == 0xC0:
            offset += 2
            break
        offset += data[offset] + 1
    else:
        offset += 1
    if offset + 10 > len(data):
        return None
    offset += 8  # type(2) + class(2) + ttl(4)
    rdlen = int.from_bytes(data[offset:offset + 2], "big")
    offset += 2
    rdata_end = min(offset + rdlen, len(data))
    if offset >= rdata_end:
        return None
    num_names = data[offset]
    offset += 1
    # Sanity: NUM_NAMES * 18 must fit inside RDATA. If not, we're misaligned — bail.
    if num_names == 0 or offset + num_names * 18 > rdata_end:
        return None

    # Pass 1: collect candidates from this response.
    workstation = None   # type 0x00, unique
    file_server = None   # type 0x20, unique  (fallback)
    for _ in range(num_names):
        raw = _nb_clean_name(data[offset:offset + 15])
        nb_type = data[offset + 15]
        nb_flags = int.from_bytes(data[offset + 16:offset + 18], "big")
        offset += 18
        is_group = bool(nb_flags & 0x8000)
        if not raw or len(raw) < 2:
            continue
        if raw.upper() in _NB_JUNK_NAMES:
            continue
        if is_group:
            continue  # workgroup / domain / browser election names
        if nb_type == 0x00 and workstation is None:
            workstation = raw
        elif nb_type == 0x20 and file_server is None:
            file_server = raw
    return workstation or file_server


def _name_is_useful(name):
    """Reject empty, junk, or workgroup-fragment names."""
    if not name:
        return False
    s = name.strip()
    if len(s) < 2:
        return False
    # The bare label of any name (strip domain suffix) shouldn't be a known group / fragment.
    head = s.split(".")[0].upper()
    if head in _NB_JUNK_NAMES:
        return False
    # Common workgroup-name truncations seen in the wild from misbehaving NBNS responders.
    if head in {"ROUP", "GROUP", "KGROUP", "ORKGROUP"}:
        return False
    return True


def resolve_names(ip):
    """Collect any names we can find for `ip`: reverse DNS + mDNS (Avahi/Bonjour) + NetBIOS/WINS."""
    names = []
    for source in (resolve_hostname, mdns_resolve, mdns_device_name, nbns_name):
        try:
            n = source(ip)
        except Exception:
            n = None
        if n and _name_is_useful(n) and n not in names:
            names.append(n)
    return names


def tcp_alive(ip, ports=(445, 135, 22, 3389), timeout=0.35):
    """Quick TCP-connect probe to common always-on Windows/Linux ports.
    Returns True if any port accepts a connection (i.e. the host is up)."""
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((ip, port)) == 0:
                try:
                    s.close()
                except OSError:
                    pass
                return True
        except OSError:
            pass
        finally:
            try:
                s.close()
            except OSError:
                pass
    return False


def _gather_names(ip):
    """Try every name source we have, return de-duped useful names."""
    names = []
    for src in (resolve_hostname, mdns_resolve, mdns_device_name, nbns_name):
        try:
            n = src(ip)
        except Exception:
            continue
        if n and _name_is_useful(n) and n not in names:
            names.append(n)
    return names


def probe_one(ip, do_names=True):
    """Probe an IP. Returns (ip, ping_ms_or_None, names, method).

    Method:
      "ping" - ICMP succeeded (best — gives RTT and confirms reachability).
      "nbns" - ICMP failed but NetBIOS Node Status answered (legacy Windows /
               Samba — also gives us the workstation name for free).
      "tcp"  - ICMP+NBNS both failed but a common service port (SMB/RPC/SSH/RDP)
               accepted a connection. Catches modern Windows hosts that block
               ICMP and have NetBIOS-over-TCP disabled but still expose SMB.
      None   - no signal at all.
    """
    ms = ping_one(ip)
    if ms is not None:
        names = resolve_names(ip) if do_names else []
        return ip, ms, names, "ping"
    # Ping failed — try NetBIOS Node Status first (cheap UDP, also gets a name).
    nbns = nbns_name(ip)
    if nbns and _name_is_useful(nbns):
        names = [nbns]
        if do_names:
            for n in _gather_names(ip):
                if n not in names:
                    names.append(n)
        return ip, None, names, "nbns"
    # NBNS silent too — try a TCP probe on a few well-known ports.
    if tcp_alive(ip):
        names = _gather_names(ip) if do_names else []
        return ip, None, names, "tcp"
    return ip, None, [], None


def get_arp_table():
    """Return {ip: mac} from the OS neighbor cache.

    Tries `ip neigh show` first (modern Linux — net-tools is no longer in the
    base install on Debian 13+, so legacy `arp` may be missing), then falls
    back to `arp -n` / `arp -a`. Output of all three is line-based with an IP
    and MAC token per row, which our regexes pick up uniformly.
    """
    if IS_WINDOWS:
        commands = [["arp", "-a"]]
    else:
        commands = [["ip", "neigh", "show"], ["arp", "-n"]]
    for cmd in commands:
        try:
            result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=8, **_popen_kwargs(),
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue
        if result.returncode != 0:
            continue
        out = result.stdout.decode("utf-8", errors="ignore")
        if not out.strip():
            continue
        table = {}
        for line in out.splitlines():
            ip_m = IP_RE.search(line)
            mac_m = MAC_RE.search(line)
            if not (ip_m and mac_m):
                continue
            mac = mac_m.group(0).lower().replace("-", ":")
            if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                continue
            table[ip_m.group(0)] = mac
        return table
    return {}


# ---------- monitor state ----------

class Monitor:
    def __init__(self, ips, workers, state_path=None):
        self.ips = ips
        self.workers = workers
        self.lock = threading.Lock()
        self.devices = {}  # ip -> dict
        self.events = deque(maxlen=250)
        self.stop_event = threading.Event()
        self.scan_count = 0
        self.last_scan_duration = 0.0
        self.start_time = time.time()
        self.state_path = state_path
        if state_path:
            self._load_state()

    def _load_state(self):
        try:
            with open(self.state_path, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return
        except (OSError, json.JSONDecodeError) as e:
            print(f"warn: could not load state {self.state_path}: {e}", file=sys.stderr, flush=True)
            return
        devices = data.get("devices") or {}
        events = data.get("events") or []
        # Restore device records as-is (includes last_seen, present, etc.).
        # On the next scan, devices that don't reply will be aged out by the normal
        # leave-after-5min logic; devices that do reply just refresh silently.
        with self.lock:
            self.devices = devices
            self.events = deque(events, maxlen=250)
            saved_at = data.get("saved_at", "?")
            online_was = sum(1 for d in devices.values() if d.get("present"))
            marker = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "kind": "info",
                "ip": "",
                "mac": "",
                "name": (f"--- restart: loaded {len(devices)} devices "
                         f"({online_was} online) from state saved {saved_at} ---"),
            }
            self.events.appendleft(marker)
        print(f"loaded {len(devices)} devices ({online_was} online), "
              f"{len(events)} events from {self.state_path}", flush=True)

    def _save_state(self):
        if not self.state_path:
            return
        with self.lock:
            devices_copy = {
                ip: {**d, "names": list(d.get("names") or [])}
                for ip, d in self.devices.items()
            }
            events_copy = list(self.events)
        data = {
            "saved_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "devices": devices_copy,
            "events": events_copy,
        }
        tmp = self.state_path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, self.state_path)
        except OSError as e:
            print(f"warn: state save failed: {e}", file=sys.stderr, flush=True)

    def _emit(self, kind, ip, mac, name):
        ev = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "kind": kind,
            "ip": ip,
            "mac": mac or "",
            "name": name or "",
        }
        # Caller must hold self.lock OR not — we lock here briefly.
        with self.lock:
            self.events.appendleft(ev)
        sym = "+" if kind == "arrived" else "-"
        print(f"[{ev['time']}] {sym} {ip:<15} {mac or '':<17} {name or ''}", flush=True)

    def scan_once(self):
        start = time.time()
        responding = {}  # ip -> (ms_or_None, names_list, method)

        # Fire all probes in parallel.
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            # Skip name lookups for IPs we already have a name for; keep trying for the rest.
            with self.lock:
                have_name = {ip: bool(d.get("names")) for ip, d in self.devices.items()}
            futures = [
                ex.submit(probe_one, ip, not have_name.get(ip))
                for ip in self.ips
            ]
            for fut in as_completed(futures):
                ip, ms, names, method = fut.result()
                if method:
                    responding[ip] = (ms, names, method)

        arp = get_arp_table()
        now = time.time()
        arrivals, departures = [], []

        with self.lock:
            for ip, (ms, names, method) in responding.items():
                mac = arp.get(ip)
                d = self.devices.get(ip)
                if d is None:
                    d = {
                        "ip": ip,
                        "mac": mac,
                        "names": list(names),
                        "first_seen": now,
                        "last_seen": now,
                        "last_recovered": now,   # treat first sighting as initial recovery
                        "last_ping_ms": ms,
                        "total_ping_ms": ms or 0.0,
                        "ping_count": 1 if ms is not None else 0,
                        "present": True,
                        "last_method": method,
                    }
                    self.devices[ip] = d
                    arrivals.append((ip, mac, list(names)))
                else:
                    was_absent = not d["present"]
                    d["last_seen"] = now
                    if ms is not None:
                        d["last_ping_ms"] = ms
                        d["total_ping_ms"] = (d.get("total_ping_ms") or 0.0) + ms
                        d["ping_count"] = (d.get("ping_count") or 0) + 1
                    d["present"] = True
                    d["last_method"] = method
                    if mac and not d.get("mac"):
                        d["mac"] = mac
                    if names:
                        existing = d.get("names") or []
                        for n in names:
                            if n not in existing:
                                existing.append(n)
                        d["names"] = existing
                    if was_absent:
                        d["last_recovered"] = now
                        arrivals.append((ip, d.get("mac"), list(d.get("names") or [])))

            # Departures: present devices not seen this scan, beyond grace window.
            for ip, d in self.devices.items():
                if d["present"] and ip not in responding:
                    if now - d["last_seen"] > LEAVE_AFTER_SECONDS:
                        d["present"] = False
                        departures.append((ip, d.get("mac"), list(d.get("names") or [])))

            self.scan_count += 1
            self.last_scan_duration = time.time() - start

        for ip, mac, names in arrivals:
            self._emit("arrived", ip, mac, " / ".join(names) if names else "")
        for ip, mac, names in departures:
            self._emit("left", ip, mac, " / ".join(names) if names else "")

        self._save_state()

    def run(self, interval):
        while not self.stop_event.is_set():
            try:
                self.scan_once()
            except Exception as e:
                print(f"scan error: {e!r}", file=sys.stderr, flush=True)
            self.stop_event.wait(interval)
        # Final save on graceful stop.
        self._save_state()

    def stop(self):
        self.stop_event.set()

    def snapshot(self):
        with self.lock:
            now = time.time()
            online = [d for d in self.devices.values() if d["present"]]
            ping_times = [d["last_ping_ms"] for d in online if d["last_ping_ms"] is not None]
            avg_ping = (sum(ping_times) / len(ping_times)) if ping_times else 0.0
            min_ping = min(ping_times) if ping_times else 0.0
            max_ping = max(ping_times) if ping_times else 0.0

            stale_count = 0
            devices_out = []
            for d in sorted(self.devices.values(), key=lambda x: ip_to_int(x["ip"])):
                pc = d.get("ping_count") or 0
                avg = (d.get("total_ping_ms") or 0.0) / pc if pc else 0.0
                names = d.get("names") or []
                last_seen_ago = now - d["last_seen"]
                if not d["present"]:
                    state = "offline"
                elif last_seen_ago > STALE_AFTER_SECONDS:
                    state = "stale"
                    stale_count += 1
                else:
                    state = "online"
                lr = d.get("last_recovered") or d.get("first_seen")
                devices_out.append({
                    "ip": d["ip"],
                    "mac": d.get("mac") or "",
                    "hostname": " / ".join(names),
                    "names": names,
                    "present": d["present"],
                    "state": state,
                    "last_method": d.get("last_method") or "",
                    "last_ping_ms": round(d["last_ping_ms"], 2) if d.get("last_ping_ms") is not None else None,
                    "avg_ping_ms": round(avg, 2),
                    "ping_count": pc,
                    "last_seen_ago": round(last_seen_ago, 1),
                    "first_seen": datetime.fromtimestamp(d["first_seen"]).strftime("%Y-%m-%d %H:%M:%S"),
                    "last_recovered": datetime.fromtimestamp(lr).strftime("%Y-%m-%d %H:%M:%S") if lr else "",
                })

            return {
                "devices": devices_out,
                "events": list(self.events),
                "stats": {
                    "total_known": len(self.devices),
                    "online": len(online) - stale_count,
                    "stale": stale_count,
                    "offline": len(self.devices) - len(online),
                    "avg_ping_ms": round(avg_ping, 2),
                    "min_ping_ms": round(min_ping, 2),
                    "max_ping_ms": round(max_ping, 2),
                    "scan_count": self.scan_count,
                    "last_scan_duration": round(self.last_scan_duration, 2),
                    "uptime_seconds": round(now - self.start_time, 1),
                    "range_size": len(self.ips),
                    "range_start": self.ips[0],
                    "range_end": self.ips[-1],
                    "leave_after_s": LEAVE_AFTER_SECONDS,
                    "stale_after_s": STALE_AFTER_SECONDS,
                },
            }


# ---------- HTTP server ----------

INDEX_HTML = r"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>LAN Monitor</title>
<style>
* { box-sizing: border-box; }
body { font-family: ui-monospace, "Cascadia Code", Consolas, monospace; background: #0a0e14; color: #c0c5ce; margin: 0; padding: 16px; }
h1 { color: #5fb3b3; margin: 0 0 4px 0; font-size: 18px; }
.sub { color: #768390; font-size: 11px; margin-bottom: 14px; }
.stats { display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; }
.stat { background: #141a21; padding: 10px 14px; border-radius: 4px; border-left: 3px solid #5fb3b3; min-width: 120px; }
.stat .label { font-size: 10px; color: #768390; text-transform: uppercase; letter-spacing: 0.5px; }
.stat .value { font-size: 22px; color: #c0c5ce; font-weight: 600; }
.section h2 { color: #fac863; font-size: 13px; margin: 14px 0 6px 0; text-transform: uppercase; letter-spacing: 0.5px; }
.tablewrap { background: #141a21; border: 1px solid #232a32; border-radius: 4px; max-height: 50vh; overflow-y: auto; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 5px 10px; border-bottom: 1px solid #1c232b; font-size: 12px; white-space: nowrap; }
th { background: #1a2129; color: #5fb3b3; position: sticky; top: 0; font-weight: 600; }
th.sortable { cursor: pointer; user-select: none; }
th.sortable:hover { color: #99e0e0; }
th .arrow { color: #768390; font-size: 10px; margin-left: 4px; }
th.sortable.active .arrow { color: #fac863; }
tr:hover td { background: #181f26; }
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; }
.dot.on { background: #99c794; box-shadow: 0 0 6px #99c794aa; }
.dot.stale { background: #fac863; box-shadow: 0 0 6px #fac86399; }
.dot.off { background: #ec5f67; }
.row-off td { color: #5a6470; }
.row-stale td { color: #c8b075; }
.via-tag  { font-size: 10px; margin-left: 4px; opacity: 0.85; }
.via-nbns { color: #c594c5; }
.via-tcp  { color: #6699cc; }
#events { background: #0d1218; border: 1px solid #232a32; border-radius: 4px; height: 250px; overflow-y: auto; padding: 6px 10px; font-size: 11px; }
.ev { padding: 1px 0; white-space: pre; }
.ev.arrived { color: #99c794; }
.ev.left { color: #ec5f67; }
.ev.info { color: #5fb3b3; font-style: italic; }
.ev .t { color: #768390; }
.muted { color: #768390; }
</style></head>
<body>
<h1>LAN Monitor</h1>
<div class="sub" id="sub">connecting…</div>
<div class="stats" id="stats"></div>

<div class="section">
  <h2>Devices</h2>
  <div class="tablewrap">
    <table>
      <thead><tr>
        <th></th>
        <th class="sortable" data-sort="ip">IP<span class="arrow"></span></th>
        <th class="sortable" data-sort="mac">MAC<span class="arrow"></span></th>
        <th class="sortable" data-sort="hostname">Name<span class="arrow"></span></th>
        <th class="sortable" data-sort="last_ping_ms">Last ping<span class="arrow"></span></th>
        <th class="sortable" data-sort="avg_ping_ms">Avg ping<span class="arrow"></span></th>
        <th class="sortable" data-sort="ping_count">Pings<span class="arrow"></span></th>
        <th class="sortable" data-sort="last_seen_ago">Last seen<span class="arrow"></span></th>
        <th class="sortable" data-sort="last_recovered">Recovered<span class="arrow"></span></th>
        <th class="sortable" data-sort="first_seen">First seen<span class="arrow"></span></th>
      </tr></thead>
      <tbody id="devices"></tbody>
    </table>
  </div>
</div>

<div class="section">
  <h2>Events <span class="muted" id="evcount"></span></h2>
  <div id="events"></div>
</div>

<script>
function pad(s, n) { s = String(s); return s + " ".repeat(Math.max(0, n - s.length)); }
function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

const sortState = { key: 'ip', dir: 'asc' };

function ipKey(ip) {
  const p = String(ip).split('.').map(n => parseInt(n, 10) || 0);
  return ((p[0]<<24)>>>0) + (p[1]<<16) + (p[2]<<8) + p[3];
}

function sortDevices(devs) {
  const k = sortState.key, dir = sortState.dir === 'asc' ? 1 : -1;
  const numeric = new Set(['last_ping_ms', 'avg_ping_ms', 'ping_count', 'last_seen_ago']);
  const cmp = (a, b) => {
    let av, bv;
    if (k === 'ip')          { av = ipKey(a.ip);            bv = ipKey(b.ip); }
    else if (numeric.has(k)) { av = a[k] == null ?  Infinity : a[k];
                               bv = b[k] == null ?  Infinity : b[k]; }
    else                     { av = String(a[k] ?? '').toLowerCase();
                               bv = String(b[k] ?? '').toLowerCase();
                               // empty strings sort last
                               if (!av && bv) return  1 * dir;
                               if (av && !bv) return -1 * dir; }
    if (av < bv) return -1 * dir;
    if (av > bv) return  1 * dir;
    return 0;
  };
  return devs.slice().sort(cmp);
}

document.addEventListener('click', (e) => {
  const th = e.target.closest('th.sortable');
  if (!th) return;
  const key = th.dataset.sort;
  if (sortState.key === key) {
    sortState.dir = sortState.dir === 'asc' ? 'desc' : 'asc';
  } else {
    sortState.key = key;
    sortState.dir = 'asc';
  }
  refresh();
});

function paintHeaderArrows() {
  document.querySelectorAll('th.sortable').forEach(th => {
    const arrow = th.querySelector('.arrow');
    if (th.dataset.sort === sortState.key) {
      th.classList.add('active');
      arrow.textContent = sortState.dir === 'asc' ? '▲' : '▼';
    } else {
      th.classList.remove('active');
      arrow.textContent = '';
    }
  });
}

async function refresh() {
  let s;
  try {
    const r = await fetch('/api/state', { cache: 'no-store' });
    s = await r.json();
  } catch (e) {
    document.getElementById('sub').textContent = 'connection lost — retrying…';
    return;
  }
  const st = s.stats;
  document.getElementById('sub').textContent =
    `range ${st.range_start} – ${st.range_end} (${st.range_size} addresses) · scan #${st.scan_count} took ${st.last_scan_duration}s · uptime ${st.uptime_seconds}s · stale-after ${st.stale_after_s}s · leave-after ${st.leave_after_s}s`;

  const cards = [
    ['Online now',     st.online],
    ['Stale',          st.stale],
    ['Known total',    st.total_known],
    ['Offline',        st.offline],
    ['Avg ping (ms)',  st.avg_ping_ms],
    ['Min ping (ms)',  st.min_ping_ms],
    ['Max ping (ms)',  st.max_ping_ms],
    ['Scans',          st.scan_count],
    ['Last scan (s)',  st.last_scan_duration],
  ];
  document.getElementById('stats').innerHTML = cards
    .map(([l, v]) => `<div class="stat"><div class="label">${esc(l)}</div><div class="value">${esc(v)}</div></div>`)
    .join('');

  paintHeaderArrows();
  document.getElementById('devices').innerHTML = sortDevices(s.devices).map(d => {
    const dotCls = d.state === 'online' ? 'on' : (d.state === 'stale' ? 'stale' : 'off');
    const rowCls = d.state === 'online' ? '' : (d.state === 'stale' ? 'row-stale' : 'row-off');
    let viaTag = '';
    if (d.last_method === 'nbns') viaTag = '<span class="via-tag via-nbns">[NBNS]</span>';
    else if (d.last_method === 'tcp')  viaTag = '<span class="via-tag via-tcp">[TCP]</span>';
    const pingCell = d.last_ping_ms !== null
      ? esc(d.last_ping_ms) + ' ms' + viaTag
      : (viaTag ? '<span class="muted">no ICMP</span>' + viaTag : '<span class="muted">—</span>');
    return `
    <tr class="${rowCls}">
      <td><span class="dot ${dotCls}"></span></td>
      <td>${esc(d.ip)}</td>
      <td>${esc(d.mac) || '<span class="muted">—</span>'}</td>
      <td>${esc(d.hostname) || '<span class="muted">—</span>'}</td>
      <td>${pingCell}</td>
      <td>${esc(d.avg_ping_ms)} ms</td>
      <td>${esc(d.ping_count)}</td>
      <td>${esc(d.last_seen_ago)}s ago</td>
      <td>${esc(d.last_recovered)}</td>
      <td>${esc(d.first_seen)}</td>
    </tr>`;
  }).join('');

  const evs = s.events;
  document.getElementById('evcount').textContent = `(${evs.length}/250, newest on top)`;
  document.getElementById('events').innerHTML = evs.map(e => {
    const sym = e.kind === 'arrived' ? '+' : (e.kind === 'left' ? '-' : '*');
    return `<div class="ev ${esc(e.kind)}"><span class="t">[${esc(e.time)}]</span> ${sym} ${esc(pad(e.ip, 15))}  ${esc(pad(e.mac, 17))}  ${esc(e.name)}</div>`;
  }).join('');
}
refresh();
setInterval(refresh, 2000);
</script>
</body></html>
"""


def make_handler(monitor):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # silence default access log

        def _send(self, code, body, content_type):
            data = body if isinstance(body, (bytes, bytearray)) else body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/" or self.path.startswith("/index"):
                self._send(200, INDEX_HTML, "text/html; charset=utf-8")
            elif self.path == "/api/state":
                payload = json.dumps(monitor.snapshot())
                self._send(200, payload, "application/json")
            else:
                self._send(404, "not found", "text/plain")

    return Handler


# ---------- main ----------

def parse_args():
    p = argparse.ArgumentParser(description="LAN device monitor with web dashboard.")
    p.add_argument("--port", type=int, required=True,
                   help="HTTP port for the dashboard (e.g. 8081)")
    p.add_argument("--start", required=True, help="First IP in scan range")
    p.add_argument("--end", required=True, help="Last IP in scan range")
    p.add_argument("--interval", type=float, default=1.0,
                   help="Seconds between scan cycles (default 1.0)")
    p.add_argument("--workers", type=int, default=256,
                   help="Concurrent ping workers (default 256)")
    p.add_argument("--bind", default="0.0.0.0",
                   help="HTTP bind address (default 0.0.0.0)")
    p.add_argument("--state", default="netmon-state.json",
                   help="Path to state cache file. Persists devices and event log "
                        "across restarts so changes-during-downtime show up in the "
                        "event panel. Set to '' to disable. (default: netmon-state.json)")
    return p.parse_args()


def main():
    args = parse_args()
    ips = ip_range(args.start, args.end)
    workers = min(args.workers, max(1, len(ips)))
    state_path = args.state.strip() or None
    monitor = Monitor(ips, workers, state_path=state_path)

    print(f"scanning {len(ips)} addresses {args.start} -> {args.end} "
          f"with {workers} workers, interval {args.interval}s "
          f"(state: {state_path or 'disabled'})", flush=True)

    scan_thread = threading.Thread(target=monitor.run, args=(args.interval,), daemon=True)
    scan_thread.start()

    server = ThreadingHTTPServer((args.bind, args.port), make_handler(monitor))
    print(f"dashboard:  http://{args.bind}:{args.port}/", flush=True)

    def shutdown(signum=None, frame=None):
        print("\nshutting down...", flush=True)
        monitor.stop()
        try:
            server.shutdown()
        except Exception:
            pass

    signal.signal(signal.SIGINT, shutdown)
    if not IS_WINDOWS:
        signal.signal(signal.SIGTERM, shutdown)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        shutdown()
    finally:
        server.server_close()
        monitor.stop()
        scan_thread.join(timeout=5)
        print("done.", flush=True)


if __name__ == "__main__":
    main()
