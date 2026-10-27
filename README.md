<h1 align="center">ARP PROTECT</h1>
<p align="center"><b>Gateway ARP-spoofing defense for Windows</b></p>
<p align="center">by <b>Syed Sadam Hussain Shah</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0a84ff" alt="platform">
  <img src="https://img.shields.io/badge/python-3.7%2B-3776AB" alt="python">
  <img src="https://img.shields.io/badge/license-MIT-51cf66" alt="license">
</p>

---

## What it is

**ARP Protect** defends a Windows host against ARP spoofing / man-in-the-middle attacks on the
local network by pinning the gateway's real MAC address as a permanent, unspoofable entry — so
an attacker's forged ARP replies are simply ignored by the OS.

Most "ARP protection" scripts just run `arp -s`, which is unreliable on Windows 10/11 and gets
silently overwritten. ARP Protect instead:

- **Verifies the real gateway MAC with a live probe** — it flushes any existing (possibly
  poisoned) cache entry, forces a fresh ARP exchange, and falls back to a raw Scapy ARP request
  if the OS resolution comes back empty — so it never trusts a cache that may already be
  compromised.
- **Pins the entry as genuinely permanent** using `New-NetNeighbor -State Permanent` (the only
  method that reliably survives on Windows 10/11), with `netsh store=persistent` and `arp -s`
  as fallbacks.
- **Verifies the result** by reading the entry back and confirming the `Permanent` state.
- **Supports clean rollback** — an unprotect mode removes the static entry and restores normal
  dynamic ARP resolution.

## Requirements

- Windows 10 or 11
- Python 3.7+
- [Npcap](https://npcap.com) (installs the packet-capture driver Scapy needs)
- Administrator privileges (required to modify the system ARP/neighbor table)

## Installation

```bash
git clone https://github.com/Pwned007/arp-protect.git
cd arp-protect
pip install -r requirements.txt
```

Install [Npcap](https://npcap.com) if you don't already have it (Wireshark installs it too).

## Usage

Run from an **Administrator** terminal.

**Interactive mode** — prompts you to choose protect / unprotect:
```bash
python arp_protect.py --ip 192.168.1.68
```

**Protect** — pin the real gateway MAC (non-interactive, scriptable):
```bash
python arp_protect.py --ip 192.168.1.68 --protect
```

**Unprotect** — remove the static entry and restore dynamic ARP:
```bash
python arp_protect.py --ip 192.168.1.68 --unprotect
```

**Explicit gateway** (skips auto-detection):
```bash
python arp_protect.py --ip 192.168.1.68 --gateway 192.168.1.1 --protect
```

| Flag | Meaning |
|---|---|
| `--ip` | **Required.** Your machine's local IP on the interface to protect |
| `--gateway` | Gateway IP; auto-detected from the routing table if omitted |
| `--protect` | Apply protection non-interactively |
| `--unprotect` | Remove protection non-interactively |

## How it works

1. **Resolve the real gateway MAC.** The cached ARP entry for the gateway is deleted, a fresh
   ping forces the OS to re-resolve it over the wire, and the newly learned entry is read back
   from `arp -a`. If that comes back empty, a raw Scapy ARP request/reply is sent as a fallback.
   This matters because if an attacker is already poisoning the cache, trusting the existing
   entry would just pin the *attacker's* MAC.
2. **Pin it permanently.** `New-NetNeighbor -InterfaceAlias <iface> -IPAddress <gw> -LinkLayerAddress <mac> -State Permanent`
   tells Windows to stop accepting ARP updates for that IP. If that fails, it falls back to
   `netsh interface ipv4 add neighbors ... store=persistent`, then plain `arp -s` as a last resort.
3. **Verify.** `Get-NetNeighbor` is queried and the output is checked for `State: Permanent`
   before reporting success.
4. **Unprotect** reverses it: removes the static/permanent entry via `Remove-NetNeighbor`
   (falling back to `netsh`/`arp -d`), then pings the gateway once to let normal dynamic ARP
   resolution take over again.

## Limitations

- Windows-only (uses `New-NetNeighbor`/`netsh`/`arp`, PowerShell cmdlets, and `route print`
  parsing specific to the Windows routing table format).
- Protects **your own host's** view of the gateway — it does not detect or stop an attacker from
  poisoning *other* hosts on the network.
- If the real gateway MAC legitimately changes (e.g. router replaced), the permanent entry must
  be removed (`--unprotect`) and re-applied, since the whole point is that it's no longer
  auto-updating.

## License

MIT — see [LICENSE](LICENSE). Contributions and issues welcome.

**Author:** Syed Sadam Hussain Shah — [LinkedIn](https://qa.linkedin.com/in/syed-sadam-h-950a62336)
