# NetSentry (Shell Edition)

**NetSentry** is a lightweight command-line vulnerability scanner written in
pure Bash. It checks a target host against a curated list of commonly
exploited ports, reports what's open, and grabs a quick service banner where
possible — no dependencies required.

> ⚠️ **Authorized use only.** Only scan hosts you own or have explicit
> permission to test. NetSentry only *detects and reports* open ports/banners
> — it never attempts to exploit, crack, or gain unauthorized access.

## Features

- Checks 15 commonly-exploited ports (FTP, SSH, Telnet, SMB, RDP, VNC, etc.)
  by default, or a custom list you supply.
- Quick banner grab on open ports using Bash's built-in `/dev/tcp`.
- Optional JSON report output for audit records.
- Zero dependencies — runs with just Bash, no `nc`, `nmap`, or Python needed.

## Requirements

- Bash 4+ (Linux/macOS; on macOS run via `bash netsentry.sh ...` since the
  default shell may be older)
- `getent` for hostname resolution (optional — falls back to the raw target
  name if unavailable)

## Installation

```bash
git clone https://github.com/bangladeshcyberspectre/Net-Sentry.git
cd netsentry
chmod +x netsentry.sh
```

## Usage

```bash
./netsentry.sh <target> [-p port1,port2,...] [-o report.json] [-t timeout_seconds]
```

### Examples

```bash
# Scan a host against the default common-ports list
./netsentry.sh 192.168.1.1

# Scan specific ports only
./netsentry.sh example.com -p 22,80,443

# Save a JSON report, with a 2-second per-port timeout
./netsentry.sh 192.168.1.1 -o scan_report.json -t 2
```

## Example output

```
[*] Scanning 192.168.1.1 (192.168.1.1) — 15 port(s)...

  [OPEN] port 80     HTTP - check for outdated server banners / missing HTTPS
         banner: HTTP/1.1 200 OK
  [OPEN] port 443    HTTPS - check certificate validity separately

[*] Scan complete: 2 open port(s) found.
```

## Roadmap ideas

- Router default-credential fingerprinting (detection only)
- CVE lookups for identified service banners
- Parallel scanning for large port lists
- HTML report export

## License

MIT License — see [LICENSE](LICENSE).

## Credit

Built by **Ochena Gamer**.
