# NetworkMonitor

A single-file LAN device monitor with a built-in web dashboard. Pure Python
standard library — no `pip install`, no virtualenv, no config files.
Cross-platform (Linux, Windows, macOS).

```
python netmon.py --port 8081 --start 192.168.15.1 --end 192.168.15.254
```

Open `http://localhost:8081/` and watch your network.

---

## What it does

- Pings every IP in the range you give it, in parallel (up to 256 concurrent
  workers by default — a /24 sweep takes 2-4 seconds).
- Resolves device names from up to four sources and shows whichever ones
  answer:
  - **Reverse DNS** via `socket.gethostbyaddr` (catches anything your router
    publishes a PTR record for, including most DHCP-named devices).
  - **mDNS / Bonjour / Avahi** reverse PTR (Macs, Linux hosts running Avahi,
    HomeKit / Cast / AirPlay devices).
  - **mDNS service-instance enumeration** (catches iPhones, iPads, Apple TVs,
    HomeKit accessories, Chromecasts, AirPlay speakers, network printers, and
    Cast-enabled Android phones — they advertise their friendly name as part
    of service instances like `John's iPhone._companion-link._tcp.local`).
  - **NetBIOS / WINS** Node Status query on UDP/137 (legacy Windows hosts and
    Samba — gives the workstation name with junk-name filtering for
    `WORKGROUP`/`__MSBROWSE__` and similar).
- Reads MAC addresses from the OS neighbor cache (`ip neigh show` on modern
  Linux, falls back to `arp -n` / `arp -a`). Local-interface MACs are
  injected separately because the kernel doesn't ARP itself.
- Discovers ping-blocked hosts. If ICMP fails, the script falls back to
  - NBNS Node Status on UDP/137 (catches Windows boxes with NetBIOS-over-TCP
    enabled).
  - TCP probe to ports 445 (SMB), 135 (RPC), 22 (SSH), 3389 (RDP) — catches
    modern Windows hosts that block ICMP and NetBIOS but still expose SMB.
  - Devices found this way are tagged `[NBNS]` or `[TCP]` in the dashboard.
- Persists state to a JSON cache. Restart the script and it picks up where
  it left off; changes that happened during downtime show up in the event
  panel as proper arrival / departure events.

## Dashboard

- **Stats cards:** online / stale / offline / total known / avg-min-max ping /
  scan count / last scan duration.
- **Device table** with sortable columns (click any header):
  IP · MAC · Name · Last ping · Avg ping · Pings · Last seen · Recovered · First seen.
  - Green dot = currently responding.
  - Yellow dot = stale (silent for >30 seconds but inside the 5-min grace).
  - Red dot   = offline (silent past the 5-min mark).
- **Event log** at the bottom — 250-line ring buffer, newest on top, scrollable.
  Green `+` for arrivals, red `-` for departures, italic `*` for restart markers.
- Auto-refresh every 2 seconds.

## Command-line options

| Flag | Default | What it does |
|---|---|---|
| `--port`     | required        | HTTP port for the dashboard. |
| `--start`    | required        | First IP in the scan range. |
| `--end`      | required        | Last IP in the scan range (inclusive). |
| `--interval` | `1.0`           | Seconds between scan cycles. |
| `--workers`  | `256`           | Concurrent ping workers. |
| `--bind`     | `0.0.0.0`       | HTTP bind address. |
| `--state`    | `netmon-state.json` | Path to the persistent device + event cache. Pass `--state ''` to disable. |

## Requirements

- Python 3.7 or newer (uses `ThreadingHTTPServer` and `as_completed`).
- `ping` in `$PATH` (Windows: built-in; Debian/Ubuntu: `iputils-ping`; usually
  preinstalled).
- `ip` from iproute2 (Debian 13 default) **or** `arp` from net-tools — whichever
  is available will be used for the neighbor cache.
- No third-party Python packages.

## Running as a systemd service (Debian / Ubuntu)

```ini
# /etc/systemd/system/netmon.service
[Unit]
Description=LAN Network Monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=node
Group=node
WorkingDirectory=/home/node
ExecStart=/usr/bin/python3 /home/node/netmon.py --port 8081 --start 192.168.15.1 --end 192.168.15.254 --state /home/node/netmon-state.json --bind 0.0.0.0
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now netmon
sudo journalctl -u netmon -f          # follow logs
sudo systemctl restart netmon         # clean restart (~1s)
```

The unprivileged `node` user can ping because Linux's setuid `ping` binary
handles the raw-socket privilege itself; no extra capabilities or sysctl
tweaks are required.

## How it works

- One scan cycle = N parallel `ThreadPoolExecutor` workers, each running
  `probe_one(ip)` which tries ICMP, then NBNS, then TCP if the previous
  failed. Name lookups happen in the same worker thread but only on the
  first scan that sees a device (cached afterwards).
- A device is **stale** when `last_seen_ago > STALE_AFTER_SECONDS` (30s).
- A device is **departed** when `last_seen_ago > LEAVE_AFTER_SECONDS` (5 min)
  — at which point it flips to red and a `-` event is appended.
- The state cache is rewritten atomically (`tmp` + `os.replace`) at the end
  of every scan and once more during graceful shutdown.

## Limitations

- Pure Android devices (no Cast services running) usually don't answer mDNS,
  NBNS, or any of the fallback TCP ports, so naming relies on whatever your
  router publishes via reverse DNS.
- The mDNS service enumeration adds ~1s per first-time scan per IP; subsequent
  scans skip naming for IPs we already named, so steady-state cost is just the
  ping itself.
- The neighbor cache only fills as the OS observes traffic; on a freshly-booted
  box you may briefly see a few `—` MAC entries before the kernel populates
  the cache.

## License

No license stated; treat as personal-use.
