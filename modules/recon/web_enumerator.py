#!/usr/bin/env python3
"""
Web Enumerator - Crawl et recherche de formulaires vulnérables
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re


def find_forms_func(data):
    """Crawl et trouve des formulaires potentiellement vulnérables"""
    try:
        base_url = data.get('url', '').strip()
        max_depth = data.get('max_depth', 2)
        
        if not base_url:
            return {'error': 'URL manquante'}
        
        visited = set()
        forms = []
        
        def crawl(url, depth):
            if depth > max_depth or url in visited:
                return
            
            visited.add(url)
            
            try:
                resp = requests.get(url, timeout=5, headers={
                    'User-Agent': 'Mozilla/5.0'
                })
                soup = BeautifulSoup(resp.text, 'html.parser')
                
                # Recherche de formulaires
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    method = form.get('method', 'get').upper()
                    inputs = [inp.get('name', '') for inp in form.find_all('input')]
                    
                    vuln_indicators = []
                    
                    # Détection de formulaires d'authentification
                    if any('pass' in i.lower() or 'login' in i.lower() for i in inputs):
                        vuln_indicators.append("auth")
                    
                    # Détection de patterns suspects
                    if any(re.search(r'(xss|union|select|script)', str(form), re.I)):
                        vuln_indicators.append("sqli/xss")
                    
                    forms.append({
                        'url': urljoin(base_url, action) if action else url,
                        'method': method,
                        'inputs': inputs,
                        'vulnerable_indicators': vuln_indicators
                    })
                
                # Crawl des liens (si pas trop profond)
                if depth < max_depth:
                    for link in soup.find_all('a', href=True):
                        next_url = urljoin(url, link['href'])
                        if urlparse(next_url).netloc == urlparse(base_url).netloc:
                            crawl(next_url, depth + 1)
            
            except Exception as e:
                pass  # Ignore les erreurs de crawl individuelles
        
        crawl(base_url, 0)
        
        return {
            'total_forms': len(forms),
            'pages_visited': len(visited),
            'forms': forms
        }
    
    except Exception as e:
        return {'error': f'Erreur lors de l\'énumération: {str(e)}'}