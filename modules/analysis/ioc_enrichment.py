#!/usr/bin/env python3
"""
Module d'enrichissement IOC avec VirusTotal et Shodan
Pour API Flask
"""

import requests
import logging
from typing import Dict, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def enrich_ioc_api(ioc: str, ioc_type: str = 'ip', 
                   vt_api: str = '', shodan_api: str = '') -> Dict:
    """
    Enrichit un IOC avec VirusTotal et Shodan
    
    Args:
        ioc: IP ou domaine à enrichir
        ioc_type: 'ip' ou 'domain'
        vt_api: Clé API VirusTotal (optionnel)
        shodan_api: Clé API Shodan (optionnel)
    
    Returns:
        dict: Données enrichies
    """
    result = {
        'ioc': ioc,
        'type': ioc_type,
        'virustotal': {},
        'shodan': {},
        'status': 'success'
    }
    
    # VirusTotal enrichment
    if vt_api:
        try:
            vt_data = enrich_with_virustotal(ioc, ioc_type, vt_api)
            result['virustotal'] = vt_data
        except Exception as e:
            logger.error(f"VirusTotal error for {ioc}: {e}")
            result['virustotal'] = {'error': str(e)}
    else:
        result['virustotal'] = {'note': 'Clé API non fournie'}
    
    # Shodan enrichment (uniquement pour les IPs)
    if shodan_api and ioc_type == 'ip':
        try:
            shodan_data = enrich_with_shodan(ioc, shodan_api)
            result['shodan'] = shodan_data
        except Exception as e:
            logger.error(f"Shodan error for {ioc}: {e}")
            result['shodan'] = {'error': str(e)}
    else:
        result['shodan'] = {'note': 'Clé API non fournie ou type non IP'}
    
    return result


def enrich_with_virustotal(ioc: str, ioc_type: str, api_key: str) -> Dict:
    """Enrichir avec VirusTotal API v3"""
    headers = {
        'x-apikey': api_key
    }
    
    if ioc_type == 'ip':
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == 'domain':
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    else:
        return {'error': 'Type IOC non supporté'}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            
            last_analysis = attributes.get('last_analysis_stats', {})
            
            return {
                'detections': {
                    'malicious': last_analysis.get('malicious', 0),
                    'suspicious': last_analysis.get('suspicious', 0),
                    'harmless': last_analysis.get('harmless', 0),
                    'undetected': last_analysis.get('undetected', 0)
                },
                'reputation': attributes.get('reputation', 0),
                'country': attributes.get('country', 'Unknown'),
                'asn': attributes.get('asn', 'Unknown'),
                'as_owner': attributes.get('as_owner', 'Unknown'),
                'last_analysis_date': attributes.get('last_analysis_date', 'Unknown')
            }
        elif response.status_code == 404:
            return {'error': 'IOC non trouvé dans VirusTotal'}
        elif response.status_code == 401:
            return {'error': 'Clé API VirusTotal invalide'}
        else:
            return {'error': f'Erreur VirusTotal: {response.status_code}'}
    
    except requests.exceptions.RequestException as e:
        return {'error': f'Erreur réseau VirusTotal: {str(e)}'}


def enrich_with_shodan(ip: str, api_key: str) -> Dict:
    """Enrichir une IP avec Shodan"""
    url = f"https://api.shodan.io/shodan/host/{ip}"
    params = {'key': api_key}
    
    try:
        response = requests.get(url, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extraire les ports ouverts
            open_ports = [service.get('port') for service in data.get('data', [])]
            
            # Extraire les vulnérabilités
            vulns = []
            for service in data.get('data', []):
                if 'vulns' in service:
                    vulns.extend(list(service['vulns'].keys()))
            
            return {
                'ip': data.get('ip_str', ip),
                'org': data.get('org', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'country': data.get('country_name', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'open_ports': open_ports,
                'total_ports': len(open_ports),
                'hostnames': data.get('hostnames', []),
                'vulns': list(set(vulns)),
                'total_vulns': len(set(vulns)),
                'os': data.get('os', 'Unknown'),
                'last_update': data.get('last_update', 'Unknown')
            }
        elif response.status_code == 404:
            return {'error': 'IP non trouvée dans Shodan'}
        elif response.status_code == 401:
            return {'error': 'Clé API Shodan invalide'}
        else:
            return {'error': f'Erreur Shodan: {response.status_code}'}
    
    except requests.exceptions.RequestException as e:
        return {'error': f'Erreur réseau Shodan: {str(e)}'}


# Pour usage CLI (optionnel)
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='IOC Enrichment Tool')
    parser.add_argument('ioc', help='IOC à enrichir (IP ou domaine)')
    parser.add_argument('--type', choices=['ip', 'domain'], default='ip', help='Type d\'IOC')
    parser.add_argument('--vt-api', help='Clé API VirusTotal')
    parser.add_argument('--shodan-api', help='Clé API Shodan')
    
    args = parser.parse_args()
    
    result = enrich_ioc_api(args.ioc, args.type, args.vt_api or '', args.shodan_api or '')
    
    import json
    print(json.dumps(result, indent=2))
