#!/usr/bin/env python3
import requests
import csv
import argparse
import logging
from typing import List, Dict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def enrich_ioc(ioc: str, vt_api: str, shodan_api: str) -> Dict:
    """Enrichit un IOC avec VT et Shodan : python ioc_enrich.py iocs.txt -o results.csv --vt-api YOUR_KEY --shodan-api YOUR_KEY"""
    result = {"ioc": ioc, "vt_detections": 0, "vt_last_seen": "", 
              "shodan_open_ports": [], "shodan_org": ""}
    
    # VirusTotal
    vt_url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
    params = {"apikey": vt_api, "ip": ioc}
    vt_resp = requests.get(vt_url, params=params).json()
    result["vt_detections"] = vt_resp.get("detects", 0)
    result["vt_last_seen"] = vt_resp.get("scan_date", "")
    
    # Shodan
    shodan_url = f"https://api.shodan.io/shodan/host/{ioc}"
    shodan_resp = requests.get(shodan_url, params={"key": shodan_api}).json()
    if "data" in shodan_resp:
        result["shodan_open_ports"] = [d["port"] for d in shodan_resp["data"]]
        result["shodan_org"] = shodan_resp.get("org", "")
    
    return result

def main():
    parser = argparse.ArgumentParser(description="Enrich IOC avec VT/Shodan")
    parser.add_argument("input_file", help="Fichier liste IOC (1 par ligne)")
    parser.add_argument("-o", "--output", default="ioc_enriched.csv")
    parser.add_argument("--vt-api", required=True)
    parser.add_argument("--shodan-api", required=True)
    args = parser.parse_args()
    
    iocs = []
    with open(args.input_file) as f:
        iocs = [line.strip() for line in f if line.strip()]
    
    results = []
    for ioc in iocs:
        try:
            result = enrich_ioc(ioc, args.vt_api, args.shodan_api)
            results.append(result)
            logger.info(f"Enrichi: {ioc}")
        except Exception as e:
            logger.error(f"Erreur {ioc}: {e}")
    
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    
    logger.info(f"CSV sauvé: {args.output}")

if __name__ == "__main__":
    main()
