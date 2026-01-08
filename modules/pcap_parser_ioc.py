#!/usr/bin/env python3
import pyshark
import argparse
import csv
from collections import defaultdict

def parse_pcap(pcap_file: str) -> dict:
    """Extrait IOC d'un PCAP"""
    cap = pyshark.FileCapture(pcap_file)
    
    suspicious_ips = defaultdict(int)
    dns_queries = []
    http_user_agents = []
    
    for packet in cap:
        try:
            # IP suspects (connexions multiples)
            if 'ip' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                suspicious_ips[src_ip] += 1
                suspicious_ips[dst_ip] += 1
            
            # DNS queries suspects
            if 'dns' in packet:
                if hasattr(packet.dns, 'qry_name'):
                    dns_queries.append(packet.dns.qry_name)
            
            # User agents suspects
            if 'http' in packet:
                if hasattr(packet.http, 'user_agent'):
                    ua = packet.http.user_agent
                    if any(tool in ua.lower() for tool in ['sqlmap', 'nikto', 'gobuster']):
                        http_user_agents.append(ua)
                        
        except AttributeError:
            pass
    
    cap.close()
    return {
        "suspicious_ips": dict(suspicious_ips),
        "dns_queries": dns_queries,
        "scan_ua": http_user_agents
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap_file")
    args = parser.parse_args()
    
    results = parse_pcap(args.pcap_file)
    
    print("IPs suspectes (top 10):")
    for ip, count in sorted(results["suspicious_ips"].items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"{ip}: {count}")
    
    print(f"\nDNS queries: {len(results['dns_queries'])}")
    print(f"Scan UAs: {len(results['scan_ua'])}")

if __name__ == "__main__":
    main()
