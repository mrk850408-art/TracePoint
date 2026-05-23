# Tracepoint

Tracepoint is a Blue Team DFIR & OSINT command-line tool used for basic investigation and threat intelligence enrichment.

It provides a single interface for analyzing files, IP addresses, domains, and URLs.

---

## Overview of Functions

### EXIF Analysis
Extracts metadata from image files, including camera data, timestamps, and embedded information.  
Also performs a basic triage to indicate whether an image likely retains original metadata or has been stripped/processed.

---

### File Hashing
Generates cryptographic hashes (MD5, SHA1, SHA256) for any file.  
Used for file integrity checking and malware identification.

---

### IP Lookup
Retrieves geolocation and network information for a given IP address, including ISP, country, and region data.

---

### Reverse DNS
Performs a reverse DNS lookup to identify hostnames associated with an IP address.

---

### VirusTotal (IP Analysis)
Queries VirusTotal for reputation data on an IP address, returning detection statistics from multiple security vendors.

---

### AbuseIPDB Check
Checks whether an IP address has been reported for malicious activity and returns an abuse confidence score.

---

### Shodan Lookup
Queries Shodan to retrieve exposed services, ports, operating system information, and other publicly available host data.

---
