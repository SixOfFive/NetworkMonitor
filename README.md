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
- **Names are re-resolved every hour** (`NAME_REFRESH_INTERVAL_S`) so that
  renamed devices (DHCP hostname change, iPhone rename, joined a domain, etc.)
  eventually show their new label. Empty results are treated as transient
  hiccups and the previous name is kept — no flapping.
- Reads MAC addresses from the OS neighbor cache (`ip neigh show` on modern
  Linux, falls back to `arp -n` / `arp -a`). Local-interface MACs are
  injected separately (`ip -j addr show` / `ipconfig /all`) because the
  kernel doesn't ARP itself, so the host running netmon shows its own MAC.
- Discovers ping-blocked hosts. If ICMP fails, the script falls back to
  - NBNS Node Status on UDP/137 (catches Windows boxes with NetBIOS-over-TCP
    enabled).
  - TCP probe to ports 445 (SMB), 135 (RPC), 22 (SSH), 3389 (RDP) — catches
    modern Windows hosts that block ICMP and NetBIOS but still expose SMB.
  - Devices found this way are tagged `[NBNS]` or `[TCP]` in the dashboard.
- Persists state to a JSON cache. Restart the script and it picks up where
  it left off; changes that happened during downtime show up in the event
  panel as proper arrival / departure events.
- **Drops device records after 24h offline.** A device that's been gone for
  longer than `DROP_AFTER_SECONDS` (24h) is removed from the table and an
  `info` event (`dropped (offline >24h) <name>`) is logged. If the same IP
  comes back later it's re-added as a fresh arrival.

## Dashboard

### Top of page

- **Stats cards:** online / stale / offline / total known / avg-min-max ping /
  scan count / last scan duration.
- **Device table** with sortable columns (click any header):
  IP · MAC · Name · Last ping · Avg ping · Pings · Last seen · Recovered · First seen.
  - Green dot = currently responding.
  - Yellow dot = stale (silent for >30 seconds but inside the 5-min grace).
  - Red dot   = offline (silent past the 5-min mark).
  - `[NBNS]` / `[TCP]` tag next to the ping cell indicates the device was
    discovered through a fallback (no ICMP reply).
- **Event log** at the bottom — 250-line ring buffer, newest on top,
  scrollable. Green `+` for arrivals, red `-` for departures, italic `*` for
  restart and drop markers. Auto-refresh every 2 seconds.

### Click-to-open per-MAC chart

Click any row in the device table — or any line in the event log — that has a
MAC, and a modal opens showing the full history for that MAC:

- **Inline SVG chart** of ping ms over the last 24 hours (sampling throttled
  to one point per 30 s so the chart never grows past 2880 points per MAC).
- **IP color coding.** Each unique IP a MAC has held over the window gets a
  distinct palette color. The chart's trace, dots, vertical IP-change marker
  lines, the "IPs seen" chips at the top, the IP-changes list, and the
  samples list all use the same color for the same IP. DHCP changes are
  obvious at a glance.
- **Hover for the exact ms reading** on any data point.
- **Yellow dashed vertical lines** mark the moment a MAC switched IPs, with
  the new IP labeled at the top.
- **Click any IP chip to filter** the chart, IP-change list, and samples
  list to just that IP. Click again to clear.
- **Samples list** (left-border-striped by IP color) and **IP-changes list**
  scroll independently below the chart.
- **`(current)` badge** is awarded to the device record currently active and
  most-recently-seen for that MAC (picks the right one even when DHCP has
  parked the same MAC on several IPs over time).

### SSH into any device

The chart modal has an **SSH access** panel at the bottom. Per-MAC
credentials let you pull live system info (uptime / OS / kernel / CPU / load /
memory / disk / temperatures via `sensors` or `/sys/class/thermal` / GPU via
`nvidia-smi`) on demand, and launch an interactive PuTTY session with a
single click.

Three action buttons after credentials are saved:

| Button | What it does |
|---|---|
| **Get system info** | SSHes to the host, runs a fixed read-only info command, renders the output in the panel. |
| **Open in PuTTY** | An `<a href="ssh://user@ip">` styled as a button. Your local PuTTY (or whatever is registered for the `ssh:` URL scheme) opens straight to the right login prompt. |
| **Download PuTTY key** | Streams a zip containing `netmon.ppk` (the PuTTY-format conversion of netmon's auto-generated ed25519 key), a Pageant loader `.bat`, and a `README.txt`. Double-click the `.bat` after extracting — Pageant launches into your tray with the key loaded, and PuTTY sessions skip the password prompt forever after. |
| **Forget credentials** | Deletes the per-MAC entry from the credential store. |

**Auth flow on first save:** username, password, and a checkbox (on by
default) to **generate and install an SSH key** on the target. If the key
install succeeds, the password is discarded and future probes use key auth.
If it fails (target doesn't accept the key, firewall blocks, etc.), the
encrypted password is kept as a fallback. Future visits to that MAC show the
three-button row instead of the form.

**puttygen auto-install.** The Download PuTTY key button is only useful when
`puttygen` is installed on the netmon host. If it's missing but `apt` is
available, the button is replaced with an **Install puttygen** button — one
click runs `sudo -n apt-get install -y putty-tools` via the netmon host's
existing passwordless sudo, then the SSH section reloads with the real
download button enabled.

### Credential storage and security

Per-MAC SSH credentials live in `<state>.ssh-creds.json` (alongside the main
state file), keyed by MAC. Passwords are AES-256-CBC encrypted via
`openssl enc` with a per-install random key kept in `<state>.enc-key`. Both
files are written with mode `0600`.

**What this protects against:** casual file reads, accidental commits, an
attacker with read access to the JSON but not the key file.

**What this does NOT protect against:** an attacker with shell access as the
netmon user. They can read both the key file and the ciphertext. There is
no way around this without prompting for a passphrase at every netmon
startup, which kills the headless-systemd-service property.

**The bulletproof answer is key auth.** Tick the "install SSH key" checkbox
on first save. The password is discarded and the only secret left on disk
is netmon's ed25519 private key under `<state>.ssh-key` (chmod 0600), used
the same way you'd use any SSH private key.

The browser-side `Download PuTTY key` button generates the PPK on demand —
it is never written to the netmon server's disk. It is built in memory,
streamed to your browser as a zip download, then garbage-collected.

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

## Files written at runtime

All sidecar files derive their names from `--state`. With the default
`netmon-state.json` you get:

| File | Contents | When written |
|---|---|---|
| `netmon-state.json` | Device list + 250-line event ring. | After every scan + on graceful shutdown. |
| `netmon-state.history.json` | Per-MAC ping samples + IP-change events for the modal chart. | On graceful shutdown only — keeps the per-scan save cheap. |
| `netmon-state.ssh-creds.json` | Per-MAC SSH credentials. | When you save credentials in the UI. mode 0600. |
| `netmon-state.enc-key` | 32 random bytes — AES key for the cred file. | First time you save credentials. mode 0600. |
| `netmon-state.ssh-key`, `.ssh-key.pub` | netmon's ed25519 keypair, used for key-auth SSH to LAN devices. | First time you tick "install SSH key". mode 0600. |

All of these are excluded from git in the project `.gitignore` (`*.ppk` and
`netmon-ssh-key.zip` are also blocked so the local Windows download can't
accidentally end up in a checkout). Generic `id_rsa` / `id_ed25519` /
`*.pem` / `*.key` patterns are blocked too as a belt-and-suspenders.

## Requirements

- Python 3.7 or newer (uses `ThreadingHTTPServer` and `as_completed`).
- `ping` in `$PATH` (Windows: built-in; Debian/Ubuntu: `iputils-ping`; usually
  preinstalled).
- `ip` from iproute2 (Debian 13 default) **or** `arp` from net-tools — whichever
  is available will be used for the neighbor cache.
- No third-party Python packages.

**Optional, only needed for the SSH-into-device features:**

- `ssh` (OpenSSH client) **or** `plink` (PuTTY's CLI). Either works — netmon
  prefers plink when present because it accepts `-pw` natively, but falls back
  to OpenSSH with `sshpass` for password auth.
- `sshpass` — only required if you authenticate by stored password and have
  OpenSSH instead of plink. Already installed on Debian 13.
- `ssh-keygen` — for generating the key-auth keypair. Part of OpenSSH.
- `openssl` — for AES-256-CBC encryption of stored passwords. Default on
  Debian/Ubuntu.
- `puttygen` (Debian: `apt install putty-tools`) — only for the **Download
  PuTTY key** button. The UI offers a one-click install if it's missing.
- `sudo` with passwordless access for the netmon user — only required by the
  auto-install button.

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

## API

The dashboard is backed by a small JSON API. Useful for scripting:

| Method | Path | What it returns |
|---|---|---|
| `GET` | `/` | The dashboard HTML. |
| `GET` | `/api/state` | All devices, recent events, stats. Polled by the dashboard every 2 s. |
| `GET` | `/api/mac/<mac>` | Per-MAC chart data: samples (last 24h), IP-change events, current IP, names, state. |
| `GET` | `/api/ssh/capability` | What SSH client + helpers are installed on the netmon host. |
| `GET` | `/api/ssh/<mac>/status` | Whether credentials are stored for this MAC, and which auth method. |
| `POST` | `/api/ssh/<mac>/creds` | Save credentials. Body: `{user, password, install_key, ip}`. |
| `POST` | `/api/ssh/<mac>/forget` | Delete stored credentials for a MAC. |
| `POST` | `/api/ssh/<mac>/probe` | SSH to the host and run the system-info command. Body: `{ip}`. |
| `POST` | `/api/ssh/install-puttygen` | Run `sudo -n apt-get install -y putty-tools` on the netmon host. |
| `GET` | `/api/ssh/ppk-bundle` | Stream a zip with `netmon.ppk`, the Pageant loader `.bat`, and a `README.txt`. |

## How it works

- One scan cycle = N parallel `ThreadPoolExecutor` workers, each running
  `probe_one(ip)` which tries ICMP, then NBNS, then TCP if the previous
  failed. Name lookups happen in the same worker thread but only on devices
  with no cached name yet OR whose cached name is older than 1h
  (`NAME_REFRESH_INTERVAL_S`).
- A device is **stale** when `last_seen_ago > STALE_AFTER_SECONDS` (30s),
  **departed** when `last_seen_ago > LEAVE_AFTER_SECONDS` (5 min), and
  **dropped** entirely when `last_seen_ago > DROP_AFTER_SECONDS` (24h).
- The main state cache is rewritten atomically (`tmp` + `os.replace`) at the
  end of every scan and once more during graceful shutdown. The mac_history
  sidecar is saved only on graceful shutdown so the per-scan write stays
  small (a 24h sweep at 30s sampling is ~12 MB JSON).
- The shutdown signal handler dispatches `server.shutdown()` to a daemon
  thread instead of calling it inline, because OpenSSH's HTTPServer
  deadlocks if `shutdown()` runs on the same thread as `serve_forever()`.
  This is what makes `systemctl restart netmon` return in ~1 second instead
  of waiting out the systemd kill timeout.

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
- The dashboard has no authentication. It's designed for a trusted LAN. Anyone
  who can reach `http://<host>:<port>/` can read every device, fetch the PPK
  download, and trigger SSH probes (within the stored credentials). Don't
  expose it past your firewall.

## License

No license stated; treat as personal-use.
