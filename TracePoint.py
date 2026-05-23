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


def banner():
    print(BANNER)
    print(Fore.CYAN + "[*] Initializing Tracepoint modules..." + Style.RESET_ALL)
    print(Fore.CYAN + "[*] Loading OSINT engine..." + Style.RESET_ALL)
    print(Fore.CYAN + "[*] Loading DFIR engine..." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Ready.\n" + Style.RESET_ALL)


# =========================
# COLORS HELPERS
# =========================

def info(msg):
    print(Fore.CYAN + "[*] " + Style.RESET_ALL + str(msg))


def success(msg):
    print(Fore.GREEN + "[+] " + Style.RESET_ALL + str(msg))


def warn(msg):
    print(Fore.YELLOW + "[!] " + Style.RESET_ALL + str(msg))


def error(msg):
    print(Fore.RED + "[-] " + Style.RESET_ALL + str(msg))


# =========================
# LOAD ENV
# =========================

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

report_data = {}


# =========================
# VALIDATION
# =========================

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


# =========================
# EXPORTS
# =========================

def export_json():
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    with open(filename, "w") as f:
        json.dump(report_data, f, indent=4)

    success(f"JSON report saved: {filename}")


def export_csv():
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Key", "Value"])

        for k, v in report_data.items():
            writer.writerow([k, v])

    success(f"CSV report saved: {filename}")


# =========================
# EXIF + IMAGE TRIAGE
# =========================

def extract_exif():
    path = input("Enter image path: ").strip()

    if not os.path.exists(path):
        error("File not found")
        return

    info("EXIF ANALYSIS")

    found_metadata = False

    try:

        image = Image.open(path)
        exif_data = getattr(image, "_getexif", lambda: None)()

        if exif_data:

            found_metadata = True

            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)

                success(f"{tag}: {value}")
                report_data[f"exif_{tag}"] = str(value)

        else:
            warn("No EXIF metadata found")

        info("DETAILED EXIF SCAN")

        with open(path, "rb") as f:

            tags = exifread.process_file(f)

            if tags:

                found_metadata = True

                for tag in tags:

                    if tag not in ("JPEGThumbnail", "TIFFThumbnail"):
                        print(f"{tag}: {tags[tag]}")
                        report_data[f"exif_{tag}"] = str(tags[tag])

            else:
                warn("No detailed EXIF metadata found")

        info("IMAGE INTELLIGENCE SUMMARY")

        if not found_metadata:
            warn("No metadata detected → likely web-sourced or processed image")
            report_data["image_metadata_status"] = "none_found"
            report_data["image_origin_hint"] = "web_processed_or_sanitized"
        else:
            success("Metadata detected → possible original or device file")
            report_data["image_metadata_status"] = "present"
            report_data["image_origin_hint"] = "original_or_device_file"

    except Exception as e:
        error(e)


# =========================
# HASHING
# =========================

def generate_hashes():
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

    except Exception as e:
        error(e)


# =========================
# IP LOOKUP
# =========================

def ip_lookup():
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

    except Exception as e:
        error(e)


# =========================
# REVERSE DNS
# =========================

def reverse_dns():
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

    except Exception as e:
        error(e)


# =========================
# VIRUSTOTAL
# =========================

def virustotal():
    if not VT_API_KEY:
        error("Missing VirusTotal API key")
        return

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

    except Exception as e:
        error(e)


# =========================
# ABUSEIPDB
# =========================

def abuseipdb():
    if not ABUSEIPDB_API_KEY:
        error("Missing AbuseIPDB API key")
        return

    ip = input("Enter IP: ").strip()

    if not validate_ip(ip):
        error("Invalid IP")
        return

    info("ABUSEIPDB CHECK")

    try:

        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }

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

    except Exception as e:
        error(e)


# =========================
# SHODAN
# =========================

def shodan_lookup():
    if not SHODAN_API_KEY:
        error("Missing Shodan API key")
        return

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
        print(f"Ports: {host.get('ports')}")

    except Exception as e:
        error(e)


# =========================
# URL REPUTATION
# =========================

def url_reputation():
    if not VT_API_KEY:
        error("Missing VirusTotal API key")
        return

    url_input = input("Enter URL: ").strip()

    info("URL REPUTATION")

    try:

        headers = {"x-apikey": VT_API_KEY}

        res = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url_input}
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

    except Exception as e:
        error(e)


# =========================
# WHOIS
# =========================

def whois_lookup():
    domain = input("Enter domain: ").strip()

    info("WHOIS LOOKUP")

    try:

        data = whois.whois(domain)

        for k, v in data.items():
            print(f"{k}: {v}")
            report_data[f"whois_{k}"] = str(v)

    except Exception as e:
        error(e)


# =========================
# MENU
# =========================

def menu():
    banner()

    while True:

        print(Fore.CYAN + "\n===== TRACEPOINT DFIR TOOLKIT =====\n" + Style.RESET_ALL)

        print("1. EXIF Analysis")
        print("2. File Hashing")
        print("3. IP Lookup")
        print("4. Reverse DNS")
        print("5. VirusTotal")
        print("6. AbuseIPDB")
        print("7. Shodan")
        print("8. URL Reputation")
        print("9. WHOIS")
        print("10. Export JSON")
        print("11. Export CSV")
        print("12. Exit")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            extract_exif()
        elif choice == "2":
            generate_hashes()
        elif choice == "3":
            ip_lookup()
        elif choice == "4":
            reverse_dns()
        elif choice == "5":
            virustotal()
        elif choice == "6":
            abuseipdb()
        elif choice == "7":
            shodan_lookup()
        elif choice == "8":
            url_reputation()
        elif choice == "9":
            whois_lookup()
        elif choice == "10":
            export_json()
        elif choice == "11":
            export_csv()
        elif choice == "12":
            success("Exiting Tracepoint...")
            break
        else:
            warn("Invalid option")


# =========================
# START
# =========================

if __name__ == "__main__":
    menu()