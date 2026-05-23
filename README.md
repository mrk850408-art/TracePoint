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
