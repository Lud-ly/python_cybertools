#!/usr/bin/env python3
"""
Threat Intel Scanner - Analyse d'URLs malveillantes avec VirusTotal API v3
Author: Ludovic Mouly
GitHub: https://github.com/Lud-ly/python_cybertools
"""

import requests
import base64
import hashlib
import json
import time
import sqlite3
import argparse
from datetime import datetime
from typing import Dict, List, Optional
from dotenv import load_dotenv
import os
from rich.console import Console
from rich.table import Table
from rich.progress import track
from rich import print as rprint

load_dotenv()

class ThreatScanner:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": api_key,
            "Accept": "application/json"
        }
        self.console = Console()
        self.init_database()
    
    def init_database(self):
        """Initialiser la base de données SQLite locale"""
        self.conn = sqlite3.connect('threat_intel.db')
        self.cursor = self.conn.cursor()
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                url_id TEXT NOT NULL,
                scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                malicious INTEGER,
                suspicious INTEGER,
                harmless INTEGER,
                undetected INTEGER,
                threat_label TEXT,
                threat_category TEXT,
                result_json TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                reason TEXT,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.conn.commit()
    
    def encode_url(self, url: str) -> str:
        """Encoder l'URL en base64 pour l'API VirusTotal"""
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        return url_id
    
    def check_cache(self, url: str) -> Optional[Dict]:
        """Vérifier si l'URL a déjà été scannée dans les dernières 24h"""
        self.cursor.execute('''
            SELECT * FROM scans 
            WHERE url = ? 
            AND datetime(scan_date) > datetime('now', '-1 day')
            ORDER BY scan_date DESC LIMIT 1
        ''', (url,))
        
        result = self.cursor.fetchone()
        if result:
            return {
                'cached': True,
                'malicious': result[4],
                'suspicious': result[5],
                'harmless': result[6],
                'undetected': result[7],
                'threat_label': result[8],
                'threat_category': result[9],
                'scan_date': result[3]
            }
        return None
    
    def scan_url(self, url: str, force_rescan: bool = False) -> Dict:
        """Scanner une URL avec VirusTotal API v3"""
        
        # Vérifier le cache
        if not force_rescan:
            cached = self.check_cache(url)
            if cached:
                self.console.print(f"[yellow]📦 Résultat en cache pour {url}[/yellow]")
                return cached
        
        url_id = self.encode_url(url)
        
        try:
            # Soumettre l'URL pour analyse
            self.console.print(f"[cyan]🔍 Scan de {url}...[/cyan]")
            
            # Récupérer le rapport
            report_url = f"{self.base_url}/urls/{url_id}"
            response = requests.get(report_url, headers=self.headers)
            
            if response.status_code == 404:
                # URL jamais scannée, la soumettre
                submit_url = f"{self.base_url}/urls"
                submit_response = requests.post(
                    submit_url, 
                    headers=self.headers,
                    data={"url": url}
                )
                
                if submit_response.status_code == 200:
                    self.console.print("[yellow]⏳ URL soumise, attente des résultats...[/yellow]")
                    time.sleep(15)  # Attendre que le scan se termine
                    response = requests.get(report_url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                return self._parse_results(url, url_id, data)
            else:
                return {
                    'error': f"Erreur API: {response.status_code}",
                    'url': url
                }
                
        except Exception as e:
            return {
                'error': str(e),
                'url': url
            }
    
    def _parse_results(self, url: str, url_id: str, data: Dict) -> Dict:
        """Parser les résultats de VirusTotal"""
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        results = attributes.get('last_analysis_results', {})
        
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        undetected = stats.get('undetected', 0)
        
        # Déterminer la catégorie de menace
        threat_label = "SAFE"
        threat_category = "Clean"
        
        if malicious > 0:
            threat_label = "MALICIOUS"
            # Extraire la catégorie depuis les résultats
            for engine, result in results.items():
                if result.get('category') == 'malicious':
                    threat_category = result.get('result', 'Malware')
                    break
        elif suspicious > 0:
            threat_label = "SUSPICIOUS"
            threat_category = "Potentially unwanted"
        
        result_data = {
            'url': url,
            'malicious': malicious,
            'suspicious': suspicious,
            'harmless': harmless,
            'undetected': undetected,
            'threat_label': threat_label,
            'threat_category': threat_category,
            'total_engines': malicious + suspicious + harmless + undetected,
            'reputation': attributes.get('reputation', 0),
            'times_submitted': attributes.get('times_submitted', 0),
            'categories': attributes.get('categories', {}),
            'engines_details': results
        }
        
        # Sauvegarder dans la DB
        self._save_to_database(url, url_id, result_data)
        
        return result_data
    
    def _save_to_database(self, url: str, url_id: str, result: Dict):
        """Sauvegarder les résultats dans SQLite"""
        self.cursor.execute('''
            INSERT INTO scans (
                url, url_id, malicious, suspicious, harmless, 
                undetected, threat_label, threat_category, result_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            url, url_id, result['malicious'], result['suspicious'],
            result['harmless'], result['undetected'], result['threat_label'],
            result['threat_category'], json.dumps(result['engines_details'])
        ))
        self.conn.commit()
    
    def batch_scan(self, urls: List[str]) -> List[Dict]:
        """Scanner plusieurs URLs"""
        results = []
        
        for url in track(urls, description="Scan en cours..."):
            result = self.scan_url(url)
            results.append(result)
            time.sleep(1)  # Rate limiting API
        
        return results
    
    def display_results(self, result: Dict):
        """Afficher les résultats avec Rich"""
        table = Table(title=f"🛡️  Analyse de {result.get('url', 'URL')}")
        
        table.add_column("Métrique", style="cyan", no_wrap=True)
        table.add_column("Valeur", style="magenta")
        
        if 'error' in result:
            table.add_row("❌ Erreur", result['error'])
        else:
            # Déterminer la couleur selon le risque
            threat_color = "green"
            if result['threat_label'] == "MALICIOUS":
                threat_color = "red"
            elif result['threat_label'] == "SUSPICIOUS":
                threat_color = "yellow"
            
            table.add_row("🎯 Statut", f"[{threat_color}]{result['threat_label']}[/{threat_color}]")
            table.add_row("🦠 Malveillants", f"[red]{result['malicious']}[/red]")
            table.add_row("⚠️  Suspects", f"[yellow]{result['suspicious']}[/yellow]")
            table.add_row("✅ Sains", f"[green]{result['harmless']}[/green]")
            table.add_row("❓ Non détectés", str(result['undetected']))
            table.add_row("🏷️  Catégorie", result['threat_category'])
            table.add_row("📊 Total moteurs", str(result['total_engines']))
            
            if 'reputation' in result:
                table.add_row("⭐ Réputation", str(result['reputation']))
        
        self.console.print(table)
    
    def export_to_csv(self, filename: str = "threat_report.csv"):
        """Exporter l'historique en CSV"""
        import csv
        
        self.cursor.execute('SELECT * FROM scans ORDER BY scan_date DESC LIMIT 100')
        rows = self.cursor.fetchall()
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'ID', 'URL', 'URL_ID', 'Date Scan', 'Malveillants', 
                'Suspects', 'Sains', 'Non détectés', 'Label', 'Catégorie'
            ])
            
            for row in rows:
                writer.writerow(row[:10])
        
        self.console.print(f"[green]✅ Export CSV: {filename}[/green]")
    
    def add_to_blacklist(self, url: str, reason: str):
        """Ajouter une URL à la blacklist locale"""
        try:
            self.cursor.execute(
                'INSERT INTO blacklist (url, reason) VALUES (?, ?)',
                (url, reason)
            )
            self.conn.commit()
            self.console.print(f"[red]🚫 {url} ajouté à la blacklist[/red]")
        except sqlite3.IntegrityError:
            self.console.print(f"[yellow]⚠️  {url} déjà dans la blacklist[/yellow]")
    
    def check_blacklist(self, url: str) -> bool:
        """Vérifier si une URL est dans la blacklist"""
        self.cursor.execute('SELECT * FROM blacklist WHERE url = ?', (url,))
        return self.cursor.fetchone() is not None

def main():
    parser = argparse.ArgumentParser(
        description="Threat Intel Scanner - Analyse d'URLs malveillantes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
python threat_scanner.py -u https://example.com
python threat_scanner.py -f urls.txt
python threat_scanner.py -u https://suspicious-site.com --export report.csv
python threat_scanner.py --history
        """
    )
    
    parser.add_argument('-u', '--url', help='URL unique à scanner')
    parser.add_argument('-f', '--file', help='Fichier contenant des URLs (une par ligne)')
    parser.add_argument('--export', help='Exporter les résultats en CSV')
    parser.add_argument('--history', action='store_true', help='Afficher historique')
    parser.add_argument('--blacklist', help='Ajouter une URL à la blacklist')
    parser.add_argument('--api-key', help='Clé API VirusTotal (ou via .env)')
    
    args = parser.parse_args()
    
    # Récupérer la clé API
    api_key = args.api_key or os.getenv('VT_API_KEY')
    
    if not api_key:
        print("❌ Erreur: Clé API VirusTotal requise")
        print("Définissez VT_API_KEY dans .env ou utilisez --api-key")
        return
    
    scanner = ThreatScanner(api_key)
    
    if args.blacklist:
        scanner.add_to_blacklist(args.blacklist, "Ajout manuel")
        return
    
    if args.history:
        scanner.export_to_csv("history.csv")
        return
    
    if args.url:
        result = scanner.scan_url(args.url)
        scanner.display_results(result)
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
            
            results = scanner.batch_scan(urls)
            
            for result in results:
                scanner.display_results(result)
                print()
        except FileNotFoundError:
            print(f"❌ Fichier introuvable: {args.file}")
    
    if args.export:
        scanner.export_to_csv(args.export)

if __name__ == "__main__":
    main()