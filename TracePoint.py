#!/usr/bin/env python3
"""
Tracepoint – Blue Team DFIR & OSINT Toolkit
--------------------------------------------
Case management, unified investigations, IOC extraction,
geolocation, suspiciousness scoring, and structured reporting.
"""

import os
import csv
import json
import time
import socket
import hashlib
import requests
import exifread
import shodan
import whois
import ipaddress
import re
import webbrowser

from dotenv import load_dotenv
from PIL import Image
from PIL.ExifTags import TAGS
from datetime import datetime

from colorama import init, Fore, Style

init(autoreset=True)

# =========================
# BANNER
# =========================
BANNER = Fore.CYAN + r"""
ooooooooooooo                                        ooooooooo.              o8o                  .
8'   888   `8                                        `888   `Y88.            `"'                .o8
     888      oooo d8b  .oooo.    .ooooo.   .ooooo.   888   .d88'  .ooooo.  oooo  ooo. .oo.   .o888oo
     888      `888""8P `P  )88b  d88' `"Y8 d88' `88b  888ooo88P'  d88' `88b `888  `888P"Y88b    888
     888       888      .oP"888  888       888ooo888  888         888   888  888   888   888    888
     888       888     d8(  888  888   .o8 888    .o  888         888   888  888   888   888    888 .
    o888o     d888b    `Y888""8o `Y8bod8P' `Y8bod8P' o888o        `Y8bod8P' o888o o888o o888o   "888"

                 Blue Team DFIR & OSINT Toolkit - TRACEPOINT
""" + Style.RESET_ALL

# =========================
# GLOBALS
# =========================
report_data = {}
case_name = ""

# API keys
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

# =========================
# HELPERS
# =========================
def info(msg):
    print(Fore.CYAN + "[*] " + Style.RESET_ALL + str(msg))

def success(msg):
    print(Fore.GREEN + "[+] " + Style.RESET_ALL + str(msg))

def warn(msg):
    print(Fore.YELLOW + "[!] " + Style.RESET_ALL + str(msg))

def error(msg):
    print(Fore.RED + "[-] " + Style.RESET_ALL + str(msg))

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def timestamp_now():
    return datetime.now().isoformat()

def add_timestamp(key):
    report_data[f"{key}_timestamp"] = timestamp_now()

# =========================
# EXPORTS (now use case name)
# =========================
def export_json():
    if not case_name:
        warn("No case name set – using 'unnamed'")
        prefix = "unnamed"
    else:
        prefix = case_name.replace(" ", "_")
    filename = f"{prefix}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(report_data, f, indent=4)
    success(f"JSON report saved: {filename}")

def export_csv():
    if not case_name:
        prefix = "unnamed"
    else:
        prefix = case_name.replace(" ", "_")
    filename = f"{prefix}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Key", "Value"])
        for k, v in report_data.items():
            writer.writerow([k, v])
    success(f"CSV report saved: {filename}")

# =========================
# MODULE: EXIF + Geolocation
# =========================
def extract_exif(path=None):
    if path is None:
        path = input("Enter image path: ").strip()
    if not os.path.exists(path):
        error("File not found")
        return

    info("EXIF ANALYSIS")
    found_metadata = False
    gps_coords = None

    try:
        # PIL extraction
        image = Image.open(path)
        exif_data = getattr(image, "_getexif", lambda: None)()
        if exif_data:
            found_metadata = True
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                success(f"{tag}: {value}")
                report_data[f"exif_{tag}"] = str(value)
                # Capture GPS info
                if tag == "GPSInfo":
                    gps_coords = value
        else:
            warn("No EXIF metadata found (PIL)")

        # exifread extraction
        info("DETAILED EXIF SCAN")
        with open(path, "rb") as f:
            tags = exifread.process_file(f)
        if tags:
            found_metadata = True
            for tag in tags:
                if tag not in ("JPEGThumbnail", "TIFFThumbnail"):
                    print(f"{tag}: {tags[tag]}")
                    report_data[f"exif_{tag}"] = str(tags[tag])
                    # GPS via exifread
                    if "GPS GPSLatitude" in tag or "GPS GPSLongitude" in tag:
                        pass  # will handle separately
        else:
            warn("No detailed EXIF metadata found")

        # Geolocation handling
        if gps_coords:
            info("GPS COORDINATES DETECTED")
            # PIL GPSInfo is a dict; extract lat/lon if possible
            try:
                lat = gps_coords[2]  # typically N/S
                lon = gps_coords[4]
                # This is simplified; real conversion needs degrees/minutes/seconds
                print(f"Raw GPS: {gps_coords}")
                report_data["GPS_raw"] = str(gps_coords)
            except Exception:
                pass
        # Try exifread GPS fields
        gps_lat = tags.get("GPS GPSLatitude")
        gps_lon = tags.get("GPS GPSLongitude")
        if gps_lat and gps_lon:
            # Convert exifread values to decimal
            try:
                def dms_to_decimal(dms, ref):
                    degrees = dms.values[0].num / dms.values[0].den
                    minutes = dms.values[1].num / dms.values[1].den
                    seconds = dms.values[2].num / dms.values[2].den
                    decimal = degrees + minutes / 60 + seconds / 3600
                    if ref in ['S', 'W']:
                        decimal = -decimal
                    return decimal

                lat_ref = tags.get("GPS GPSLatitudeRef").printable
                lon_ref = tags.get("GPS GPSLongitudeRef").printable
                lat = dms_to_decimal(gps_lat, lat_ref)
                lon = dms_to_decimal(gps_lon, lon_ref)
                success(f"Coordinates: {lat}, {lon}")
                report_data["GPS_lat"] = lat
                report_data["GPS_lon"] = lon

                # Offer to open map
                open_map = input("Open in Google Maps? (y/n): ").strip().lower()
                if open_map == 'y':
                    url = f"https://www.google.com/maps?q={lat},{lon}"
                    webbrowser.open(url)
                    info("Map opened in browser")
            except Exception as e:
                error(f"Could not parse GPS: {e}")

        info("IMAGE INTELLIGENCE SUMMARY")
        if not found_metadata:
            warn("No metadata detected → likely web-sourced or processed image")
            report_data["image_metadata_status"] = "none_found"
            report_data["image_origin_hint"] = "web_processed_or_sanitized"
        else:
            success("Metadata detected → possible original or device file")
            report_data["image_metadata_status"] = "present"
            report_data["image_origin_hint"] = "original_or_device_file"

        add_timestamp("exif")
    except Exception as e:
        error(e)

# =========================
# MODULE: HASHING
# =========================
def generate_hashes(path=None):
    if path is None:
        path = input("Enter file path: ").strip()
    if not os.path.exists(path):
        error("File not found")
        return

    info("FILE HASHING")
    hashes = {
        "MD5": hashlib.md5(),
        "SHA1": hashlib.sha1(),
        "SHA256": hashlib.sha256()
    }
    try:
        with open(path, "rb") as f:
            while chunk := f.read(4096):
                for h in hashes.values():
                    h.update(chunk)
        for name, h in hashes.items():
            digest = h.hexdigest()
            success(f"{name}: {digest}")
            report_data[name] = digest
        add_timestamp("hash")
    except Exception as e:
        error(e)

# =========================
# MODULE: IP LOOKUP
# =========================
def ip_lookup(ip=None):
    if ip is None:
        ip = input("Enter IP: ").strip()
    if not validate_ip(ip):
        error("Invalid IP")
        return

    info("IP LOOKUP")
    try:
        data = requests.get(f"http://ip-api.com/json/{ip}").json()
        if data.get("status") != "success":
            error("Lookup failed")
            return
        for k, v in data.items():
            if k in ["country", "city", "isp"]:
                success(f"{k}: {v}")
            else:
                print(f"{k}: {v}")
            report_data[k] = str(v)
        add_timestamp("ip_lookup")
    except Exception as e:
        error(e)

# =========================
# MODULE: REVERSE DNS
# =========================
def reverse_dns(ip=None):
    if ip is None:
        ip = input("Enter IP: ").strip()
    if not validate_ip(ip):
        error("Invalid IP")
        return

    info("REVERSE DNS")
    try:
        host, aliases, ips = socket.gethostbyaddr(ip)
        success(f"Hostname: {host}")
        print(f"Aliases: {aliases}")
        print(f"IPs: {ips}")
        report_data["hostname"] = host
        add_timestamp("reverse_dns")
    except Exception as e:
        error(e)

# =========================
# MODULE: VIRUSTOTAL IP
# =========================
def virustotal(ip=None):
    if not VT_API_KEY:
        error("Missing VirusTotal API key")
        return
    if ip is None:
        ip = input("Enter IP: ").strip()
    if not validate_ip(ip):
        error("Invalid IP")
        return

    info("VIRUSTOTAL CHECK")
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}
        data = requests.get(url, headers=headers).json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        for k, v in stats.items():
            if k == "malicious" and v > 0:
                error(f"{k}: {v}")
            elif k == "suspicious" and v > 0:
                warn(f"{k}: {v}")
            else:
                success(f"{k}: {v}")
            report_data[f"VT_{k}"] = v
        add_timestamp("virustotal")
    except Exception as e:
        error(e)

# =========================
# MODULE: ABUSEIPDB
# =========================
def abuseipdb(ip=None):
    if not ABUSEIPDB_API_KEY:
        error("Missing AbuseIPDB API key")
        return
    if ip is None:
        ip = input("Enter IP: ").strip()
    if not validate_ip(ip):
        error("Invalid IP")
        return

    info("ABUSEIPDB CHECK")
    try:
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        data = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": 90}
        ).json()["data"]
        score = data.get("abuseConfidenceScore", 0)
        if score > 75:
            error(f"Abuse Score: {score}")
        elif score > 25:
            warn(f"Abuse Score: {score}")
        else:
            success(f"Abuse Score: {score}")
        report_data["abuse_score"] = score
        add_timestamp("abuseipdb")
    except Exception as e:
        error(e)

# =========================
# MODULE: SHODAN
# =========================
def shodan_lookup(ip=None):
    if not SHODAN_API_KEY:
        error("Missing Shodan API key")
        return
    if ip is None:
        ip = input("Enter IP: ").strip()
    if not validate_ip(ip):
        error("Invalid IP")
        return

    info("SHODAN LOOKUP")
    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)
        success(f"IP: {host.get('ip_str')}")
        print(f"Org: {host.get('org')}")
        print(f"OS: {host.get('os')}")
        ports = host.get("ports", [])
        print(f"Ports: {ports}")
        report_data["shodan_org"] = host.get("org")
        report_data["shodan_os"] = host.get("os")
        report_data["shodan_ports"] = str(ports)
        add_timestamp("shodan")
    except Exception as e:
        error(e)

# =========================
# MODULE: URL REPUTATION
# =========================
def url_reputation(url=None):
    if not VT_API_KEY:
        error("Missing VirusTotal API key")
        return
    if url is None:
        url = input("Enter URL: ").strip()

    info("URL REPUTATION")
    try:
        headers = {"x-apikey": VT_API_KEY}
        res = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url}
        ).json()
        analysis_id = res["data"]["id"]
        time.sleep(5)
        analysis = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers
        ).json()
        stats = analysis["data"]["attributes"]["stats"]
        for k, v in stats.items():
            if k == "malicious" and v > 0:
                error(f"{k}: {v}")
            elif k == "suspicious" and v > 0:
                warn(f"{k}: {v}")
            else:
                success(f"{k}: {v}")
            report_data[f"url_{k}"] = v
        add_timestamp("url_reputation")
    except Exception as e:
        error(e)

# =========================
# MODULE: WHOIS
# =========================
def whois_lookup(domain=None):
    if domain is None:
        domain = input("Enter domain: ").strip()

    info("WHOIS LOOKUP")
    try:
        data = whois.whois(domain)
        for k, v in data.items():
            print(f"{k}: {v}")
            report_data[f"whois_{k}"] = str(v)
        add_timestamp("whois")
    except Exception as e:
        error(e)

# =========================
# NEW: Unified Investigation
# =========================
def unified_investigation():
    global case_name
    info("UNIFIED INVESTIGATION")
    print("1. IP")
    print("2. Domain")
    print("3. File (hash + exif)")
    choice = input("Select target type: ").strip()

    if choice == '1':
        ip = input("Enter IP: ").strip()
        if not validate_ip(ip):
            error("Invalid IP")
            return
        print()
        ip_lookup(ip)
        reverse_dns(ip)
        virustotal(ip)
        abuseipdb(ip)
        shodan_lookup(ip)
        # calculate suspiciousness
        calc_suspiciousness("ip")

    elif choice == '2':
        domain = input("Enter domain: ").strip()
        print()
        whois_lookup(domain)
        # optional: URL reputation on http://domain
        url_reputation(f"http://{domain}")
        # if want IP lookups, resolve domain
        try:
            ip = socket.gethostbyname(domain)
            info(f"Domain resolved to {ip}, running IP checks...")
            ip_lookup(ip)
            reverse_dns(ip)
            virustotal(ip)
            abuseipdb(ip)
            shodan_lookup(ip)
        except Exception as e:
            error(f"Could not resolve domain: {e}")
        calc_suspiciousness("domain")

    elif choice == '3':
        path = input("Enter file path: ").strip()
        if not os.path.exists(path):
            error("File not found")
            return
        print()
        generate_hashes(path)
        extract_exif(path)
        calc_suspiciousness("file")
    else:
        warn("Invalid choice")

# =========================
# NEW: Suspiciousness Score
# =========================
def calc_suspiciousness(scan_type="ip"):
    """Calculate a threat score based on collected data, then clear temp variables."""
    score = 0
    details = []

    # VirusTotal IP
    vt_malicious = report_data.get("VT_malicious", 0)
    vt_suspicious = report_data.get("VT_suspicious", 0)
    if vt_malicious > 0:
        score += 40
        details.append("VT malicious detections")
    if vt_suspicious > 0:
        score += 20
        details.append("VT suspicious detections")

    # AbuseIPDB
    abuse = report_data.get("abuse_score", 0)
    score += int(abuse * 0.4)  # max 40
    if abuse > 0:
        details.append(f"AbuseIPDB confidence {abuse}%")

    # Shodan ports (common risky ports)
    ports_str = report_data.get("shodan_ports", "[]")
    try:
        ports = eval(ports_str)  # safe because we stored it
    except:
        ports = []
    risky_ports = {21, 22, 23, 25, 53, 110, 135, 139, 445, 1433, 3389, 5900, 8080}
    open_risky = [p for p in ports if p in risky_ports]
    if open_risky:
        score += 10
        details.append(f"Risky ports open: {open_risky}")

    # WHOIS recent domain
    if scan_type in ["domain", "url"]:
        creation = report_data.get("whois_creation_date")
        if creation:
            # creation_date may be a list or datetime
            try:
                if isinstance(creation, list):
                    creation = creation[0]
                if isinstance(creation, datetime):
                    age = (datetime.now() - creation).days
                    if age < 30:
                        score += 10
                        details.append("Domain registered < 30 days")
            except:
                pass

    # URL reputation
    url_mal = report_data.get("url_malicious", 0)
    if url_mal > 0:
        score += 30
        details.append("URL flagged as malicious")

    # Cap score at 100
    score = min(score, 100)

    if score >= 85:
        level = "CRITICAL"
        color = Fore.RED
    elif score >= 60:
        level = "HIGH"
        color = Fore.MAGENTA
    elif score >= 30:
        level = "MEDIUM"
        color = Fore.YELLOW
    else:
        level = "LOW"
        color = Fore.GREEN

    print(color + f"\n[!] SUSPICIOUSNESS SCORE: {score}/100 ({level})")
    if details:
        print(color + "Reasons: " + "; ".join(details))
    report_data["suspiciousness_score"] = score
    report_data["suspiciousness_level"] = level
    add_timestamp("suspiciousness")

# =========================
# NEW: IOC Extraction & Automated Analysis
# =========================
def ioc_extraction_analysis():
    text = input("Paste log/text (or type 'file' to load from file): ").strip()
    if text.lower() == 'file':
        file_path = input("Enter file path: ").strip()
        if not os.path.exists(file_path):
            error("File not found")
            return
        with open(file_path, "r") as f:
            text = f.read()

    info("EXTRACTING IOCs...")
    # Regex patterns
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    url_pattern = r'https?://[^\s]+'
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'  # simplistic
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'

    ips = re.findall(ip_pattern, text)
    urls = re.findall(url_pattern, text)
    domains = re.findall(domain_pattern, text)
    # filter domains that are not IPs (already captured)
    domains = [d for d in domains if not re.match(r'^\d+\.\d+\.\d+\.\d+$', d)]

    hashes_md5 = re.findall(md5_pattern, text)
    hashes_sha1 = re.findall(sha1_pattern, text)
    hashes_sha256 = re.findall(sha256_pattern, text)

    print(f"IPs found: {len(ips)}")
    print(f"URLs found: {len(urls)}")
    print(f"Domains found: {len(domains)}")
    print(f"MD5: {len(hashes_md5)}, SHA1: {len(hashes_sha1)}, SHA256: {len(hashes_sha256)}")

    # Process IPs
    for ip in set(ips):
        if validate_ip(ip):
            info(f"Analyzing IP: {ip}")
            ip_lookup(ip)
            reverse_dns(ip)
            virustotal(ip)
            abuseipdb(ip)
            shodan_lookup(ip)

    # Process URLs
    for url in set(urls):
        info(f"Analyzing URL: {url}")
        url_reputation(url)

    # Process domains
    for domain in set(domains):
        info(f"Analyzing domain: {domain}")
        whois_lookup(domain)

    # Hashes - just note them, can't query VT without premium API usually
    for h in set(hashes_md5 + hashes_sha1 + hashes_sha256):
        report_data[f"extracted_hash_{len(report_data)}"] = h
        print(f"Hash extracted: {h}")

    add_timestamp("ioc_analysis")
    success("IOC analysis completed. Check report for details.")

# =========================
# MENU (updated with new options)
# =========================
def set_case_name():
    global case_name, report_data
    case_name = input("Enter case name (or press Enter for 'unnamed'): ").strip()
    if not case_name:
        case_name = "unnamed"
    report_data["case_name"] = case_name
    success(f"Case set to: {case_name}")

def menu():
    global report_data, case_name
    print(BANNER)
    print(Fore.CYAN + "[*] Initializing Tracepoint modules..." + Style.RESET_ALL)
    print(Fore.CYAN + "[*] Loading OSINT engine..." + Style.RESET_ALL)
    print(Fore.CYAN + "[*] Loading DFIR engine..." + Style.RESET_ALL)
    set_case_name()

    # Menu mapping
    options = {
        "1": ("EXIF Analysis", extract_exif),
        "2": ("File Hashing", generate_hashes),
        "3": ("IP Lookup", ip_lookup),
        "4": ("Reverse DNS", reverse_dns),
        "5": ("VirusTotal IP", virustotal),
        "6": ("AbuseIPDB", abuseipdb),
        "7": ("Shodan", shodan_lookup),
        "8": ("URL Reputation", url_reputation),
        "9": ("WHOIS", whois_lookup),
        "10": ("Unified Investigation", unified_investigation),
        "11": ("IOC Extraction & Analysis", ioc_extraction_analysis),
        "12": ("Export JSON", export_json),
        "13": ("Export CSV", export_csv),
        "14": ("Reset case / clear data", reset_case),
        "15": ("Exit", None)
    }

    while True:
        print(Fore.CYAN + f"\n===== TRACEPOINT DFIR TOOLKIT [Case: {case_name}] =====\n" + Style.RESET_ALL)
        for key, (desc, _) in options.items():
            print(f"{key}. {desc}")

        choice = input("\nSelect option: ").strip()
        if choice == "15":
            success("Exiting Tracepoint...")
            break
        elif choice == "14":
            reset_case()
        elif choice in options:
            func = options[choice][1]
            if func:
                func()
        else:
            warn("Invalid option")

def reset_case():
    global report_data, case_name
    report_data = {}
    case_name = "unnamed"
    success("Case data cleared. Set a new case name.")
    set_case_name()

# =========================
# START
# =========================
if __name__ == "__main__":
    menu()