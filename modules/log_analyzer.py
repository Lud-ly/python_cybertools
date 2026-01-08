#!/usr/bin/env python3
"""
Log Analyzer - Analyse de logs Apache/Nginx pour détection d'attaques
Author: Ludovic Mouly
"""

import re
import logging
from collections import Counter
from typing import Dict, List
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class LogAnalyzer:
    """Analyseur de logs pour détecter les attaques"""
    
    def __init__(self):
        self.brute_pattern = re.compile(
            r'Failed password|401 Unauthorized|POST /login|403 Forbidden'
        )
        self.scan_paths = [
            '/wp-admin/', '/phpmyadmin', '/.env', '/config.php',
            '/.git/', '/admin/', '/backup/', '/db/', '/.aws/',
            '/wp-config.php', '/xmlrpc.php', '/shell.php'
        ]
        self.suspicious_agents = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'metasploit',
            'burp', 'havij', 'acunetix', 'nessus'
        ]
    
    def parse_apache_log(self, line: str) -> Dict:
        """Parse une ligne de log Apache/Nginx"""
        try:
            # Format: IP - - [date] "METHOD PATH HTTP/1.1" status size "referer" "user-agent"
            pattern = r'(\S+) - - \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\S+) "(.*?)" "(.*?)"'
            match = re.match(pattern, line)
            
            if match:
                return {
                    'ip': match.group(1),
                    'date': match.group(2),
                    'method': match.group(3),
                    'path': match.group(4),
                    'protocol': match.group(5),
                    'status': match.group(6),
                    'size': match.group(7),
                    'referer': match.group(8),
                    'user_agent': match.group(9)
                }
            return None
        except Exception:
            return None
    
    def analyze_logs(self, log_content: str) -> Dict:
        """Analyse complète des logs"""
        brute_ips = Counter()
        suspicious_paths = Counter()
        user_agents_suspicious = Counter()
        status_codes = Counter()
        methods = Counter()
        top_ips = Counter()
        
        lines = log_content.split('\n')
        total_lines = 0
        
        for line in lines:
            if not line.strip():
                continue
            
            total_lines += 1
            parsed = self.parse_apache_log(line)
            
            if not parsed:
                continue
            
            ip = parsed['ip']
            path = parsed['path']
            status = parsed['status']
            method = parsed['method']
            ua = parsed['user_agent']
            
            # Compteurs généraux
            top_ips[ip] += 1
            status_codes[status] += 1
            methods[method] += 1
            
            # Détection brute force
            if self.brute_pattern.search(line) or status in ['401', '403']:
                brute_ips[ip] += 1
            
            # Détection scan de chemins suspects
            for scan_path in self.scan_paths:
                if scan_path in path:
                    suspicious_paths[path] += 1
                    break
            
            # Détection User-Agent suspects
            ua_lower = ua.lower()
            for suspicious_agent in self.suspicious_agents:
                if suspicious_agent in ua_lower:
                    user_agents_suspicious[ua[:50]] += 1
                    break
        
        # Calcul des statistiques
        return {
            'summary': {
                'total_requests': total_lines,
                'unique_ips': len(top_ips),
                'suspicious_requests': sum(brute_ips.values()) + sum(suspicious_paths.values())
            },
            'brute_force_ips': [
                {'ip': ip, 'attempts': count} 
                for ip, count in brute_ips.most_common(10)
            ],
            'suspicious_paths': [
                {'path': path, 'count': count}
                for path, count in suspicious_paths.most_common(10)
            ],
            'suspicious_user_agents': [
                {'user_agent': ua, 'count': count}
                for ua, count in user_agents_suspicious.most_common(10)
            ],
            'top_ips': [
                {'ip': ip, 'requests': count}
                for ip, count in top_ips.most_common(10)
            ],
            'status_codes': dict(status_codes.most_common()),
            'methods': dict(methods.most_common())
        }


def analyze_log_file(data: dict) -> dict:
    """Fonction pour l'API Flask"""
    try:
        log_content = data.get('log_content', '')
        
        if not log_content:
            return {'error': 'Contenu de log manquant'}
        
        analyzer = LogAnalyzer()
        results = analyzer.analyze_logs(log_content)
        
        return {
            'success': True,
            'analysis': results
        }
    
    except Exception as e:
        logger.error(f"Erreur analyse logs: {e}")
        return {'error': str(e)}


def main():
    """Test CLI"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyse de logs')
    parser.add_argument('log_file', help='Fichier de log à analyser')
    args = parser.parse_args()
    
    with open(args.log_file) as f:
        log_content = f.read()
    
    result = analyze_log_file({'log_content': log_content})
    
    if result.get('error'):
        print(f"Erreur: {result['error']}")
        return
    
    analysis = result['analysis']
    
    print("\n=== RÉSUMÉ ===")
    print(f"Total requêtes: {analysis['summary']['total_requests']}")
    print(f"IPs uniques: {analysis['summary']['unique_ips']}")
    print(f"Requêtes suspectes: {analysis['summary']['suspicious_requests']}")
    
    print("\n=== TOP IPs BRUTE FORCE ===")
    for item in analysis['brute_force_ips']:
        print(f"{item['ip']}: {item['attempts']} tentatives")
    
    print("\n=== CHEMINS SUSPECTS ===")
    for item in analysis['suspicious_paths']:
        print(f"{item['path']}: {item['count']} accès")
    
    print("\n=== USER-AGENTS SUSPECTS ===")
    for item in analysis['suspicious_user_agents']:
        print(f"{item['user_agent']}: {item['count']} fois")


if __name__ == "__main__":
    main()