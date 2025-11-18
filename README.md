# PRecon.py
Automated passive reconnaissance engine for security assessments.  Generates OSINT reports using whois, dig, dnsenum (with timeout), Amass passive, crt.sh, and HTTP header fingerprinting.

This tool runs a series of **safe, OSINT-only checks** against a target domain and saves all output into a structured folder for later analysis and reporting.

Passive Recon

Automated **passive reconnaissance engine** for security assessments.

This tool runs a series of **safe, OSINT-only checks** against a target domain and saves all output into a structured folder for later analysis and reporting.

> No ports touched. No active exploitation.  
> Just “what an attacker can see without ever logging in.”

---

## Features

-  Accepts a domain *or* full URL (e.g. `example.com` or `https://example.com/path`)
-  Normalizes input to a clean domain (`example.com`)
-  Runs a passive recon chain:
  - `whois` – ownership and registrar info
  - `dig` – SOA, NS, MX, TXT, ANY records
  - `dnsenum` – DNS sweep (with timeout)
  - `amass enum -passive` – passive subdomain enumeration
  - `crt.sh` – Certificate Transparency log lookup (via `curl`)
  - `curl -I` – HTTP/HTTPS header fingerprinting (root + `www.`)
  - `host` – basic resolution checks
-  Adds built-in **timeouts** so long-running tools don’t hang forever
-  Writes each stage’s output to its own `.txt` file
-  “Run and forget” design – kick off multiple projects and review later
-  Verbose mode to see what’s happening in real time

---

##How It Works (High-Level)

For a given domain, the tool:

1. Normalizes the input (strips `http://`, `https://`, paths, etc.)
2. Creates an output directory:
3. Runs a series of passive recon commands
4. Saves each phase into a file named:
    Examples:
      ACME_whois.txt
      ACME_dig_dns.txt
      ACME_dnsenum.txt
      ACME_amass_passive.txt
      ACME_crtsh.txt
      ACME_curl_headers.txt
      ACME_host_lookup.txt
6. Exits cleanly, leaving everything ready for analysis and reporting.

PRecon is designed for Kali-style environments, but works anywhere with the right tools installed.

Runtime
Python 3.8+
External CLI tools (installed via apt / package manager)
You’ll want at least:
whois
dnsutils        # for dig & host
dnsenum
amass
curl

sudo apt update
sudo apt install whois dnsutils dnsenum amass curl

### Usage ###
From Kali box:
   python3 precon.py,
   Enter Name and Domain when prompted,
   Go make coffee while you wait


