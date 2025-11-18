#!/usr/bin/env python3
import os
import subprocess
import time
import argparse
from datetime import datetime

# ===== SETTINGS =====
# Hardcode to your normal user so sudo doesn't redirect to /root/Desktop
BASE_DIR = "/home/kali/Desktop/Passive Recon"

DELAY_BETWEEN_STEPS = 5  # seconds between major steps
DNSENUM_TIMEOUT = 180    # seconds (3 minutes)
AMASS_TIMEOUT = 300      # seconds (5 minutes)
# ====================


def normalize_domain(raw: str) -> str:
    """Strip scheme and path, return just the domain."""
    raw = raw.strip()
    if raw.startswith("http://"):
        raw = raw[len("http://"):]
    elif raw.startswith("https://"):
        raw = raw[len("https://"):]
    # Drop path/query/etc
    if "/" in raw:
        raw = raw.split("/")[0]
    return raw


def run_command(cmd, verbose=False, timeout=None):
    """Run a command and return combined stdout/stderr with the command prepended."""
    if verbose:
        print(f"\n[+] Executing: {cmd}\n")

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = f"$ {cmd}\n\n"
        if result.stdout:
            output += result.stdout
        if result.stderr:
            output += "\n[stderr]\n" + result.stderr
        return output

    except subprocess.TimeoutExpired as e:
        output = f"$ {cmd}\n\n[ERROR] Command timed out after {timeout} seconds.\n"
        if e.stdout:
            output += e.stdout
        if e.stderr:
            output += "\n[stderr]\n" + e.stderr
        return output

    except FileNotFoundError as e:
        return f"$ {cmd}\n\n[ERROR] Command not found: {e}\n"


def write_output(project_dir, project_name, scan_name, content, verbose=False):
    """Write content to <project>_<scan>.txt in the project directory."""
    filename = f"{project_name}_{scan_name}.txt"
    path = os.path.join(project_dir, filename)

    header = f"=== {scan_name} ===\nGenerated: {datetime.utcnow()} UTC\n\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(header)
        f.write(content)

    if verbose:
        print(f"[✓] Output saved → {path}")


def banner(text):
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(description="ParishSec Passive Recon Engine")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output in real time"
    )
    args = parser.parse_args()
    verbose = args.verbose

    # Don't run this as root; not needed and messes with paths
    if os.geteuid() == 0:
        print("[-] Do not run this script with sudo/root. Exiting.")
        return

    banner("ParishSec Passive Recon Automation")

    project_name = input("Project name (e.g., TandemPT): ").strip()
    if not project_name:
        print("[-] Project name required, exiting.")
        return

    target_raw = input("Target domain or URL (e.g., example.com or https://example.com): ").strip()
    if not target_raw:
        print("[-] Domain required, exiting.")
        return

    target_domain = normalize_domain(target_raw)
    print(f"[+] Normalized domain: {target_domain}")

    # Prepare directories
    os.makedirs(BASE_DIR, exist_ok=True)
    project_dir = os.path.join(BASE_DIR, project_name)
    os.makedirs(project_dir, exist_ok=True)

    print(f"\n[+] Output Directory: {project_dir}")
    print("[+] Starting passive recon…\n")

    # ===== 1. WHOIS =====
    banner("[1] WHOIS Lookup")
    whois_out = run_command(f"whois {target_domain}", verbose)
    write_output(project_dir, project_name, "whois", whois_out, verbose)
    time.sleep(DELAY_BETWEEN_STEPS)

    # ===== 2. DIG Queries =====
    banner("[2] DNS Enumeration (dig)")
    dig_out = ""
    dig_cmds = [
        f"dig {target_domain} SOA",
        f"dig {target_domain} NS",
        f"dig {target_domain} MX",
        f"dig {target_domain} TXT",
        f"dig {target_domain} ANY",
    ]
    for cmd in dig_cmds:
        dig_out += run_command(cmd, verbose)
        dig_out += "\n\n" + ("-" * 60) + "\n\n"
        time.sleep(1)

    write_output(project_dir, project_name, "dig_dns", dig_out, verbose)
    time.sleep(DELAY_BETWEEN_STEPS)

    # ===== 3. dnsenum =====
    banner("[3] dnsenum Passive Sweep")
    dnsenum_out = run_command(
        f"dnsenum --enum {target_domain}",
        verbose,
        timeout=DNSENUM_TIMEOUT
    )
    write_output(project_dir, project_name, "dnsenum", dnsenum_out, verbose)
    time.sleep(DELAY_BETWEEN_STEPS)

    # ===== 4. Amass (passive) =====
    banner("[4] Amass Passive Enumeration")
    amass_out = run_command(
        f"amass enum -passive -d {target_domain}",
        verbose,
        timeout=AMASS_TIMEOUT
    )
    write_output(project_dir, project_name, "amass_passive", amass_out, verbose)
    time.sleep(DELAY_BETWEEN_STEPS)

    # ===== 5. crt.sh via curl =====
    banner("[5] Certificate Transparency Lookup (crt.sh)")
    crt_cmd = f'curl -s "https://crt.sh/?q=%25.{target_domain}&output=json"'
    crt_out = run_command(crt_cmd, verbose)
    write_output(project_dir, project_name, "crtsh", crt_out, verbose)
    time.sleep(DELAY_BETWEEN_STEPS)

    # ===== 6. HTTP/HTTPS header fingerprinting =====
    banner("[6] HTTP/HTTPS Headers (curl -I)")
    curl_out = ""
    curl_targets = [
        f"http://{target_domain}",
        f"https://{target_domain}",
        f"http://www.{target_domain}",
        f"https://www.{target_domain}",
    ]
    for url in curl_targets:
        curl_out += run_command(f"curl -I {url}", verbose)
        curl_out += "\n\n" + ("-" * 60) + "\n\n"
        time.sleep(1)

    write_output(project_dir, project_name, "curl_headers", curl_out, verbose)
    time.sleep(DELAY_BETWEEN_STEPS)

    # ===== 7. host lookups =====
    banner("[7] Host Resolution Checks")
    host_out = run_command(f"host {target_domain}", verbose)
    host_out += "\n" + run_command(f"host www.{target_domain}", verbose)
    write_output(project_dir, project_name, "host_lookup", host_out, verbose)
    time.sleep(DELAY_BETWEEN_STEPS)

    banner("Passive Recon Complete")
    print(f"[✓] All results saved in → {project_dir}")
    print("[✓] You can now review outputs and build your report.\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user (Ctrl+C).")
        print("[!] Partial results (if any) are saved in the project directory.\n")