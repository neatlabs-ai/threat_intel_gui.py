# NEATLABS Threat Intel Enricher

A standalone desktop GUI for enriching IP addresses and domains extracted from network traffic with threat intelligence from VirusTotal, AbuseIPDB, and WHOIS registries.

Load a `.pcap` or `.pcapng` capture file, or paste indicators manually, run enrichment, and get a color-coded risk report you can export as HTML or JSON — all from a single Python file with no pip dependencies.

---

## Features

- **Direct PCAP/PCAPng parsing** — no Wireshark or external tools needed. Extracts external IPs and domain names from DNS queries, TLS SNI extensions, and HTTP Host headers
- **VirusTotal** — IP and domain reputation, detection ratio across 70+ engines, categories, ASN info
- **AbuseIPDB** — abuse confidence score, total reports, Tor node detection, ISP
- **WHOIS** — domain age analysis using direct registry queries (stdlib only, no python-whois). Flags newly registered domains that fall under your configurable threshold
- **Live results** — rows populate in real time as each indicator finishes, no waiting for the full batch
- **Cancellable** — Stop button actually interrupts in-flight requests via a threading event
- **HTML and JSON export** — dark-themed, print-ready HTML report; machine-readable JSON
- **Zero dependencies** — pure Python 3.9+ stdlib. tkinter is the only requirement beyond the standard library

---

## Screenshots

> Add screenshots here once you have them — suggest: main window after enrichment, HTML report, Config tab

---

## Requirements

- Python 3.9 or newer
- tkinter

On most systems tkinter is included. If you get `ModuleNotFoundError: No module named 'tkinter'` on Linux:

```bash
sudo apt install python3-tk        # Debian / Ubuntu
sudo dnf install python3-tkinter   # Fedora / RHEL
```

macOS and Windows ship with tkinter included in the standard Python installer.

---

## Installation

No install step — it's a single file.

```bash
git clone https://github.com/YOUR_USERNAME/threat-intel-enricher.git
cd threat-intel-enricher
python3 threat_intel_gui.py
```

---

## Usage

### Launch the GUI

```bash
python3 threat_intel_gui.py
```

### Pre-load a PCAP file at startup

```bash
python3 threat_intel_gui.py capture.pcap
python3 threat_intel_gui.py capture.pcapng
```

### Pre-load a previous JSON export

```bash
python3 threat_intel_gui.py results.json
```

### Basic workflow

1. **Load** a `.pcap` / `.pcapng` file, or paste IPs and domains into the Input tab manually
2. **Configure** API keys in the Config tab (VirusTotal and AbuseIPDB are optional — WHOIS always runs)
3. **Click Run Enrichment** — results populate live as each indicator finishes
4. **Review** findings in the IP Results, Domain Results, and WHOIS tabs
5. **Export** an HTML report or JSON file

---

## API Keys

All three services work without any keys configured — WHOIS runs entirely via direct socket queries to IANA and registrar servers. VirusTotal and AbuseIPDB require free API keys to use their respective lookups.

| Service | Required | Free Tier | Link |
|---|---|---|---|
| VirusTotal | No | 4 requests/min, 500/day | https://www.virustotal.com/gui/sign-in |
| AbuseIPDB | No | 1,000 requests/day | https://www.abuseipdb.com/register |
| WHOIS | — | Always free, no key | Built in |

### Configuring keys

**Option 1 — GUI Config tab** (recommended for desktop use):  
Open the Config tab, paste your keys, click Save. Keys are written to `neatlabs_config.json` in the tool directory.

**Option 2 — Config file** (for scripting or CI):  
Create `neatlabs_config.json` next to the script:

```json
{
    "virustotal_api_key": "YOUR_VT_KEY_HERE",
    "abuseipdb_api_key": "YOUR_ABUSEIPDB_KEY_HERE",
    "whois_new_domain_days": 60
}
```

**Option 3 — Environment variables** (takes priority over config file):

```bash
export NEATLABS_VT_KEY="YOUR_VT_KEY_HERE"
export NEATLABS_ABUSEIPDB_KEY="YOUR_ABUSEIPDB_KEY_HERE"
export NEATLABS_WHOIS_AGE_DAYS=60
```

> ⚠️ **Never commit `neatlabs_config.json` to version control.** It contains your API keys in plaintext. The `.gitignore` in this repo excludes it automatically.

---

## PCAP Parsing

The built-in parser handles:

| Format | Notes |
|---|---|
| `.pcap` | Little-endian and big-endian, standard and nanosecond timestamp variants |
| `.pcapng` | Section Header, Interface Description, Enhanced Packet, Simple Packet, and Obsolete Packet blocks |

**Link layers:** Ethernet, Raw IP (linktype 101), BSD loopback, Linux cooked capture (SLL), 802.1Q VLAN tagged frames

**Extraction methods:**
- DNS (UDP/53) — query names decoded with full label compression pointer support
- TLS SNI (TCP/443) — ClientHello extension parsing to extract `server_name`
- HTTP Host header (TCP/80) — plaintext request parsing

**Known limitations:**
- QUIC / HTTP/3 traffic (UDP/443) is not parsed — SNI in QUIC uses a different encrypted format
- Only IPv4 and IPv6 unicast traffic is processed; tunnel encapsulation (GRE, VXLAN, etc.) is not unwrapped
- Malformed or truncated packets are silently skipped

---

## Verdict Definitions

### IP Verdicts

| Verdict | Meaning |
|---|---|
| `MALICIOUS` | 5+ VirusTotal engines flagged, or AbuseIPDB score ≥ 80% |
| `LIKELY_MALICIOUS` | 2–4 VT engines flagged |
| `HIGH_RISK` | AbuseIPDB score 50–79% |
| `SUSPICIOUS` | 1 VT engine flagged, or AbuseIPDB score 25–49% |
| `LOW_RISK` | AbuseIPDB score 5–24% |
| `CLEAN` | No flags from any service |
| `UNCHECKED` | No API keys configured |

### Domain Verdicts

| Verdict | Meaning |
|---|---|
| `MALICIOUS` | 5+ VT engines flagged |
| `LIKELY_MALICIOUS` | 2–4 VT engines flagged, or new domain + VT suspicious |
| `NEW_DOMAIN` | Registered within your configured threshold (default: 60 days) |
| `SUSPICIOUS` | 1 VT engine flagged |
| `CLEAN` / `ESTABLISHED` | No flags, domain age above threshold |

---

## What to Look For

A few high-signal combinations that often indicate malicious activity:

- **High VT detection ratio** (5+/90) on an IP your endpoints are talking to
- **AbuseIPDB score > 80%** — particularly reliable for C2 infrastructure and scanners
- **Newly registered domain + suspicious TLD** (`.xyz`, `.top`, `.icu`, `.club`) — extremely common pattern for phishing and C2 staging domains
- **New domain + any VT detection** — even a single engine hit on a brand-new domain is worth investigating
- **Tor exit node** (flagged in AbuseIPDB) combined with outbound connections from an endpoint

---

## Files

```
threat_intel_gui.py     # The entire application — run this
neatlabs_config.json    # Your API keys — created by the app, never commit this
neatlabs_crash.log      # Written automatically if the app crashes on startup
README.md
.gitignore
LICENSE
```

---

## License

MIT License — see [LICENSE](LICENSE) for full text.

Copyright (c) 2025 NEATLABS / Security 360, LLC
