#!/usr/bin/env python3
"""
ARP Protection Script
Finds the real router MAC via a live ARP probe (bypasses any poisoned cache)
and sets it as a permanent static ARP entry so spoofing cannot overwrite it.

Requires: pip install scapy
Windows:  Npcap (https://npcap.com) + run as Administrator
"""

import sys
import subprocess
from datetime import datetime

try:
    from scapy.all import ARP, Ether, srp
except ImportError:
    print("[!] Scapy not found. Run: pip install scapy")
    sys.exit(1)

if sys.platform == "win32":
    import os; os.system("")


class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


def get_default_gateway() -> str:
    """Parse `route print` to find the default gateway IP."""
    try:
        out = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True).stdout
        for line in out.splitlines():
            parts = line.split()
            # route print format: Network  Mask  Gateway  Interface  Metric
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                return parts[2]
    except Exception:
        pass
    return ""


def get_interface_name(ip: str) -> str:
    """Return the friendly interface name for the interface that owns the given IP."""
    try:
        from scapy.all import conf as sc
        for _, iface in sc.ifaces.items():
            if getattr(iface, "ip", "") == ip:
                return getattr(iface, "description", "") or getattr(iface, "name", "Wi-Fi")
    except Exception:
        pass
    return "Wi-Fi"


def get_interface_alias(ip: str) -> str:
    """
    Return the Windows interface alias (e.g. 'Wi-Fi') used by PowerShell cmdlets.
    This is different from the Scapy description — PowerShell needs the short alias.
    """
    try:
        r = subprocess.run(
            ["powershell", "-Command",
             f"Get-NetIPAddress -IPAddress {ip} | Select-Object -ExpandProperty InterfaceAlias"],
            capture_output=True, text=True
        )
        alias = r.stdout.strip()
        if alias:
            return alias
    except Exception:
        pass
    return "Wi-Fi"


def get_npf_device(ip: str) -> str:
    """Return the NPF device path for the interface that owns the given IP."""
    try:
        from scapy.all import conf as sc
        for dev, iface in sc.ifaces.items():
            if getattr(iface, "ip", "") == ip:
                return dev
    except Exception:
        pass
    return None


def live_arp_probe(gateway_ip: str, iface: str) -> str:
    """
    Resolve the real gateway MAC without trusting the OS ARP cache:
      1. Delete the cached entry for gateway_ip.
      2. Ping gateway to force the OS to do a fresh ARP exchange.
      3. Read the newly-learned entry from `arp -a`.
    Falls back to Scapy srp() if the OS method returns nothing.
    """
    # Step 1: flush cached entry
    subprocess.run(["arp", "-d", gateway_ip], capture_output=True)

    # Step 2: ping to trigger fresh ARP resolution by the OS
    subprocess.run(
        ["ping", "-n", "3", "-w", "1000", gateway_ip],
        capture_output=True
    )

    # Step 3: read freshly-resolved entry from OS ARP cache
    try:
        out = subprocess.run(["arp", "-a", gateway_ip], capture_output=True, text=True).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == gateway_ip:
                mac = parts[1].replace("-", ":").lower()
                if mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                    return mac
    except Exception:
        pass

    # Step 4: fallback — Scapy raw ARP request
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip)
        answered, _ = srp(pkt, iface=iface, timeout=3, verbose=False)
        for _, reply in answered:
            return reply.hwsrc.lower()
    except Exception:
        pass

    return ""


def set_permanent_arp(alias: str, ip: str, mac: str) -> bool:
    """
    Add a truly permanent static ARP entry. Tries in order:
      1. PowerShell New-NetNeighbor -State Permanent  (Windows 10/11, best)
      2. netsh store=persistent
      3. arp -s  (last resort — gets overwritten on Win10/11, unreliable)
    """
    mac_dashes = mac.replace(":", "-")

    # Method 1: PowerShell — the only reliable way on Windows 10/11
    # -State Permanent means the OS ignores incoming ARP replies for this IP
    remove_existing_static(alias, ip)
    r = subprocess.run(
        ["powershell", "-Command",
         f"New-NetNeighbor -InterfaceAlias '{alias}' "
         f"-IPAddress {ip} -LinkLayerAddress {mac_dashes} -State Permanent"],
        capture_output=True, text=True
    )
    if r.returncode == 0:
        print(f"  Method : PowerShell New-NetNeighbor (Permanent)")
        return True

    # Method 2: netsh persistent
    r = subprocess.run(
        ["netsh", "interface", "ipv4", "add", "neighbors",
         alias, ip, mac_dashes, "store=persistent"],
        capture_output=True, text=True
    )
    if r.returncode == 0:
        print(f"  Method : netsh store=persistent")
        return True

    # Method 3: arp -s (unreliable on Win10/11 — warns user)
    r = subprocess.run(["arp", "-s", ip, mac_dashes], capture_output=True, text=True)
    if r.returncode == 0:
        print(f"  Method : arp -s (WARNING: may be overwritten on Windows 10/11)")
        return True

    print(f"  Error  : {r.stderr.strip() or r.stdout.strip()}")
    return False


def remove_existing_static(alias: str, ip: str):
    """Remove any existing static/permanent entry before adding the new one."""
    # PowerShell remove (handles Permanent state entries)
    subprocess.run(
        ["powershell", "-Command",
         f"Remove-NetNeighbor -InterfaceAlias '{alias}' -IPAddress {ip} -Confirm:$false"],
        capture_output=True
    )
    # Also netsh remove as fallback
    subprocess.run(
        ["netsh", "interface", "ipv4", "delete", "neighbors", alias, ip],
        capture_output=True
    )


def verify_arp_table(ip: str) -> str:
    """Read back the ARP table to confirm the entry was set."""
    out = subprocess.run(["arp", "-a", ip], capture_output=True, text=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == ip:
            return parts[1].replace("-", ":").lower(), parts[2]  # mac, type
    return "", ""


def do_protect(your_ip: str, gateway_ip: str):
    """Apply permanent static ARP entry for the gateway."""
    iface_dev   = get_npf_device(your_ip)
    iface_alias = get_interface_alias(your_ip)   # e.g. "Wi-Fi" for PowerShell

    if not iface_dev:
        print(f"{C.RED}[!] No interface found for IP {your_ip}{C.RESET}")
        sys.exit(1)

    print(f"\n  Your IP    : {your_ip}")
    print(f"  Gateway    : {gateway_ip}")
    print(f"  Alias      : {iface_alias}")
    print(f"{'─'*50}")

    # Live probe — flush cache first so we get the real MAC
    print(f"\n{C.CYAN}[*] Probing for real gateway MAC (bypasses cache)...{C.RESET}")
    real_mac = live_arp_probe(gateway_ip, iface_dev)
    if not real_mac:
        print(f"{C.RED}[!] ARP probe failed — is the gateway reachable?{C.RESET}")
        sys.exit(1)
    print(f"{C.GREEN}[+] Real MAC confirmed: {real_mac}{C.RESET}")

    # Set permanent entry via PowerShell
    print(f"{C.CYAN}[*] Writing permanent static ARP entry...{C.RESET}")
    if not set_permanent_arp(iface_alias, gateway_ip, real_mac):
        print(f"{C.RED}[!] Failed — run as Administrator{C.RESET}")
        sys.exit(1)
    print(f"{C.GREEN}[+] Done.{C.RESET}")

    # Verify — check with PowerShell Get-NetNeighbor for accurate state
    ps_check = subprocess.run(
        ["powershell", "-Command",
         f"Get-NetNeighbor -IPAddress {gateway_ip} | Select-Object IPAddress,LinkLayerAddress,State | Format-List"],
        capture_output=True, text=True
    ).stdout.strip()

    print(f"\n{'─'*50}")
    print(f"  VERIFICATION (PowerShell Get-NetNeighbor)")
    print(f"{'─'*50}")
    print(f"  {ps_check.replace(chr(10), chr(10)+'  ')}")

    if "Permanent" in ps_check or "permanent" in ps_check.lower():
        print(f"\n{C.GREEN}{C.BOLD}  State: Permanent — ARP spoofing CANNOT overwrite this.{C.RESET}")
        print(f"  The OS will ignore any ARP reply claiming to own {gateway_ip}.")
    else:
        print(f"\n{C.YELLOW}  Entry set but state is not Permanent — check above output.{C.RESET}")
    print(f"{'─'*50}\n")


def do_unprotect(your_ip: str, gateway_ip: str):
    """Remove the static ARP entry and restore dynamic ARP for the gateway."""
    iface_alias = get_interface_alias(your_ip)

    if not iface_alias:
        print(f"{C.RED}[!] No interface found for IP {your_ip}{C.RESET}")
        sys.exit(1)

    print(f"\n  Your IP    : {your_ip}")
    print(f"  Gateway    : {gateway_ip}")
    print(f"  Alias      : {iface_alias}")
    print(f"{'─'*50}")

    # Show current entry before removal
    entry_mac, entry_type = verify_arp_table(gateway_ip)
    if entry_mac:
        print(f"\n  Current entry : {gateway_ip} -> {entry_mac}  [{entry_type}]")
    else:
        print(f"\n{C.YELLOW}  No ARP entry found for {gateway_ip} — nothing to remove.{C.RESET}\n")
        return

    if "static" not in entry_type.lower():
        print(f"{C.YELLOW}  Entry is already dynamic — no static protection was set.{C.RESET}\n")
        return

    # Remove via PowerShell (handles Permanent state) + netsh fallback
    print(f"{C.CYAN}[*] Removing permanent ARP entry...{C.RESET}")
    r = subprocess.run(
        ["powershell", "-Command",
         f"Remove-NetNeighbor -IPAddress {gateway_ip} -Confirm:$false"],
        capture_output=True, text=True
    )
    if r.returncode != 0:
        r = subprocess.run(
            ["netsh", "interface", "ipv4", "delete", "neighbors", iface_alias, gateway_ip],
            capture_output=True, text=True
        )
    if r.returncode != 0:
        subprocess.run(["arp", "-d", gateway_ip], capture_output=True)

    print(f"{C.GREEN}[+] Entry removed.{C.RESET}")

    # Trigger a fresh dynamic ARP resolution
    subprocess.run(["ping", "-n", "1", "-w", "1000", gateway_ip], capture_output=True)
    entry_mac, entry_type = verify_arp_table(gateway_ip)

    print(f"\n{'─'*50}")
    print(f"  STATUS      : {C.YELLOW}UNPROTECTED{C.RESET} (dynamic ARP restored)")
    print(f"  Gateway IP  : {gateway_ip}")
    print(f"  Current MAC : {entry_mac or 'not yet resolved'}")
    print(f"  Entry type  : {entry_type or 'dynamic'}")
    print(f"\n{C.YELLOW}  ARP entries for {gateway_ip} can now be updated by the network.{C.RESET}")
    print(f"{'─'*50}\n")


def ask_action() -> str:
    """Interactive menu when no action flag is given."""
    print(f"\n  {C.BOLD}What do you want to do?{C.RESET}")
    print(f"  {C.GREEN}[1]{C.RESET} Protect   — pin real router MAC (block ARP spoofing)")
    print(f"  {C.YELLOW}[2]{C.RESET} Unprotect — remove static entry (restore dynamic ARP)")
    print(f"  {C.RED}[3]{C.RESET} Exit")
    try:
        choice = input(f"\n  Choice [1/2/3]: ").strip()
    except (EOFError, KeyboardInterrupt):
        choice = "3"
    return choice


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="ARP Protection — pin real router MAC or restore dynamic ARP"
    )
    parser.add_argument("--ip",        required=True,
                        help="Your machine's IP (e.g. 192.168.2.68)")
    parser.add_argument("--gateway",   default="",
                        help="Gateway IP — auto-detected if omitted")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--protect",   action="store_true",
                       help="Apply protection (non-interactive)")
    group.add_argument("--unprotect", action="store_true",
                       help="Remove protection (non-interactive)")
    args = parser.parse_args()

    print(f"\n{C.BOLD}╔══════════════════════════════════════════╗")
    print(f"║       ARP Gateway Protection Tool       ║")
    print(f"╚══════════════════════════════════════════╝{C.RESET}")

    gateway_ip = args.gateway or get_default_gateway()
    if not gateway_ip:
        print(f"{C.RED}[!] Could not auto-detect gateway. Pass --gateway <ip>{C.RESET}")
        sys.exit(1)

    # Determine action
    if args.protect:
        action = "1"
    elif args.unprotect:
        action = "2"
    else:
        action = ask_action()

    if action == "1":
        do_protect(args.ip, gateway_ip)
    elif action == "2":
        do_unprotect(args.ip, gateway_ip)
    else:
        print("  Exiting.\n")


if __name__ == "__main__":
    main()
