#!/usr/bin/env python3
"""
Domain Reconnaissance Tool
Author: José Carol Lemus Reyes
Training: Ekoparty OSINT Workshop
LEGAL: Only use on domains you own or have written authorization
"""
import socket
import subprocess
import sys
import json
from datetime import datetime

def banner():
    print("=" * 55)
    print("  DOMAIN RECONNAISSANCE TOOL")
    print("  OSINT Toolkit | José Carol Lemus Reyes")
    print("  ⚠️  Authorized use only")
    print("=" * 55)

def dns_lookup(domain):
    """Basic DNS resolution"""
    print(f"\n[DNS] Resolving {domain}...")
    try:
        ips = socket.getaddrinfo(domain, None)
        unique_ips = set()
        for ip in ips:
            addr = ip[4][0]
            if addr not in unique_ips:
                unique_ips.add(addr)
                family = "IPv4" if ip[0] == socket.AF_INET else "IPv6"
                print(f"  ✅ {addr} ({family})")
        return list(unique_ips)
    except socket.gaierror:
        print(f"  ❌ Cannot resolve {domain}")
        return []

def reverse_dns(ip):
    """Reverse DNS lookup"""
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0]
    except:
        return "N/A"

def whois_lookup(domain):
    """WHOIS information"""
    print(f"\n[WHOIS] Querying {domain}...")
    try:
        result = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=10)
        important_fields = ["Registrar:", "Creation Date:", "Expiry Date:", 
                          "Name Server:", "Status:", "Organization:"]
        for line in result.stdout.split("\n"):
            for field in important_fields:
                if field.lower() in line.lower():
                    print(f"  {line.strip()}")
                    break
    except FileNotFoundError:
        print("  ⚠️  whois not installed (apt install whois)")
    except subprocess.TimeoutExpired:
        print("  ⚠️  WHOIS timeout")

def dns_records(domain):
    """Query various DNS record types"""
    print(f"\n[DNS RECORDS] {domain}")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    
    for rtype in record_types:
        try:
            result = subprocess.run(
                ["dig", "+short", domain, rtype],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    print(f"  [{rtype:5}] {line}")
        except FileNotFoundError:
            print("  ⚠️  dig not installed (apt install dnsutils)")
            break
        except:
            pass

def subdomain_enum(domain, wordlist=None):
    """Basic subdomain enumeration"""
    print(f"\n[SUBDOMAINS] Enumerating {domain}...")
    
    common_subs = ["www", "mail", "ftp", "remote", "vpn", "admin", "portal",
                   "webmail", "api", "dev", "staging", "test", "blog", "shop",
                   "cdn", "media", "static", "app", "m", "mobile", "ns1", "ns2",
                   "smtp", "imap", "pop", "mx", "dns", "secure", "login"]
    
    found = []
    for sub in common_subs:
        subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            print(f"  ✅ {subdomain} → {ip}")
            found.append({"subdomain": subdomain, "ip": ip})
        except socket.gaierror:
            pass
    
    print(f"\n  Found {len(found)} subdomains out of {len(common_subs)} tested")
    return found

def generate_report(domain, results):
    """Export results to JSON"""
    report = {
        "target": domain,
        "timestamp": datetime.now().isoformat(),
        "tool": "OSINT Domain Recon",
        "author": "José Carol Lemus Reyes",
        "results": results
    }
    filename = f"recon_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n📄 Report saved: {filename}")

if __name__ == "__main__":
    banner()
    if len(sys.argv) < 2:
        print("\nUsage: python3 domain-recon.py <domain>")
        print("Example: python3 domain-recon.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"\nTarget: {target}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    ips = dns_lookup(target)
    whois_lookup(target)
    dns_records(target)
    subs = subdomain_enum(target)
    
    generate_report(target, {"ips": ips, "subdomains": subs})
    print("\n✅ Reconnaissance complete")
