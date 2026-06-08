# 🕵️ Tracepoint – Blue Team DFIR & OSINT Toolkit

A modular investigation assistant for **cybersecurity analysts**, **incident responders**, 
and anyone who needs to quickly triage a file, IP, domain, or log snippet.

Tracepoint packs EXIF deep‑dive, file hashing, OSINT lookups, IOC extraction, 
unified investigations, and threat scoring into a single interactive menu. 
Everything is exportable to JSON/CSV so your findings are ready for a report.


---

## 🧭 What Tracepoint does

I built this because I wanted **one tool** that could handle the first 10 minutes 
of any investigation without bouncing between websites and scripts.  
With Tracepoint you can:

- Analyse an image’s provenance (EXIF + geolocation)
- Hash a suspicious file and record MD5, SHA1, SHA256
- Enrich an IP with: geolocation, reverse DNS, VirusTotal, AbuseIPDB, Shodan
- Check a domain’s WHOIS history and run URL reputation
- **Run a unified investigation** – feed it an IP, domain, or file and let it 
  chain every relevant module automatically
- **Extract IOCs from raw text** (logs, emails, threat reports) and enrich them 
  in bulk
- Get a **suspiciousness score** (0–100) with a threat level explanation
- Export everything to a timestamped JSON or CSV report, named by case

Everything is controlled from a **coloured interactive menu** – no flags, 
no confusion.

---

## ✨ Features at a glance

### 🔍 Evidence Triage
- **EXIF analysis** – dual engine (`PIL` + `exifread`) with device, software, 
  and timestamp extraction
- **Geolocation** – if GPS is embedded, convert to decimal and open in Google Maps
- **File hashing** – MD5, SHA1, SHA256 for integrity checks and reputation lookups

### 🌐 OSINT & Reputation
- **IP geolocation** (ip‑api.com)
- **Reverse DNS** (system resolver)
- **VirusTotal IP scan** (malicious/suspicious/harmless breakdown)
- **AbuseIPDB** confidence score
- **Shodan** – open ports, organisation, OS
- **URL reputation** via VirusTotal
- **WHOIS** with registration dates, registrant info, etc.

### ⚙️ Analyst Workflows
- **Unified Investigation** – pick an IP, domain, or file and run all relevant 
  modules in one shot
- **IOC extraction** – paste a log snippet or load a text file; Tracepoint 
  finds IPs, URLs, domains, and hashes automatically and enriches them
- **Suspiciousness scoring** – after a unified scan, get a weighted risk score 
  (0‑100) with contributing factors (malicious VT detections, abuse score, 
  risky ports, domain age, etc.)
- **Case management** – set a case name at startup; all exports are prefixed 
  and the menu header reminds you which case you’re working

### 📊 Reporting
- JSON export – complete structured data
- CSV export – flat key/value pairs for spreadsheets
- Every module run is timestamped in the report

---

    Install dependencies
    bash

    pip install -r requirements.txt

    Set up API keys
    Create a .env file in the same folder (or set environment variables):
    text

    VT_API_KEY=your_virustotal_key
    ABUSEIPDB_API_KEY=your_abuseipdb_key
    SHODAN_API_KEY=your_shodan_key

    All keys are optional – Tracepoint will skip lookups for which no key
    is provided and tell you what’s missing.

    🔐 .env is already in .gitignore – never commit real keys.

🚀 Usage

Run the script:
bash

python3 tracepoint.py

You’ll be asked for a case name (optional – just press Enter for "unnamed").
Then the main menu appears:
text

===== TRACEPOINT DFIR TOOLKIT [Case: phishing_campaign_01] =====

1. EXIF Analysis
2. File Hashing
3. IP Lookup
4. Reverse DNS
5. VirusTotal IP
6. AbuseIPDB
7. Shodan
8. URL Reputation
9. WHOIS
10. Unified Investigation
11. IOC Extraction & Analysis
12. Export JSON
13. Export CSV
14. Reset case / clear data
15. Exit

Typical workflows

Quick IP check


3 → enter IP
(optional) run 4,5,6,7 individually

Full automated investigation


10 → choose IP, domain, or file
→ gets geolocation, reverse DNS, VT, AbuseIPDB, Shodan, WHOIS, URL reputation
→ prints a threat score with explanation
→ export with 12 or 13

Bulk analysis from an email or log

11 → paste the raw text (or type 'file' to load a log file)
→ Tracepoint extracts all IPs, URLs, domains, hashes
→ automatically runs lookups on each one
→ all results stored in the report

Export


12 (JSON) or 13 (CSV)
→ file saved as: <case_name>_report_YYYYMMDD_HHMMSS.json

🧪 Suspiciousness Scoring

After a unified investigation, Tracepoint calculates a weighted threat score:
Factor	Max contribution
VT malicious detections	40 points
VT suspicious detections	20 points
AbuseIPDB confidence (0‑100%)	40 points
Risky open ports (Shodan)	10 points
Domain registered < 30 days	10 points
URL flagged as malicious	30 points

Score capped at 100. Level breakdown:
Score	Level	Colour
85‑100	CRITICAL	Red
60‑84	HIGH	Magenta
30‑59	MEDIUM	Yellow
0‑29	LOW	Green


⚠️ Important notes

    Responsible use only.
    Only run Tracepoint against IPs/domains/files you own or have explicit
    permission to investigate. AbuseIPDB and VirusTotal have their own terms
    of service – make sure you comply.

    API keys are free tier.
    VirusTotal free API is rate‑limited (4 requests/min). AbuseIPDB and Shodan
    have daily limits. Tracepoint does not implement queuing – don’t hammer them.

    Geolocation accuracy depends on the image metadata; many social media
    platforms strip EXIF. Tracepoint will tell you if no metadata is found.

    This is a helper, not a final verdict.
    The suspiciousness score is an estimate based on open‑source intelligence.
    Always correlate with other evidence.

    ip‑api.com – IP geolocation

    VirusTotal – IP/URL reputation

    AbuseIPDB – abuse confidence scoring

    Shodan – internet scanning data

    python‑whois – WHOIS parsing

    exifread – low‑level EXIF extraction

    Pillow – image handling

    colorama – terminal colours

🛠️ Author

Made by sudo-scorpion
I’m a cybersecurity enthusiast building tools that make an analyst’s day easier.
If Tracepoint helped you, drop a ⭐ on the repo or open an issue with ideas.
