#!/usr/bin/env python3
"""
OSINT Recon Tool - Collecte de renseignements
Author: Ludovic Mouly
"""
import requests


class OSINTRecon:  # ✅ Nom de classe corrigé
    def __init__(self):
        self.results = {}
    
    def domain_recon(self, domain):
        """Reconnaissance de domaine (simplifié sans whois)"""
        try:
            # Test de disponibilité
            response = requests.get(f'http://{domain}', timeout=5)
            self.results['domain'] = {
                'status': 'active',
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'Unknown')
            }
        except Exception as e:
            self.results['domain'] = {
                'status': 'error',
                'error': str(e)
            }
        
        return self.results
    
    def username_search(self, username):
        """Recherche de pseudonymes sur réseaux sociaux"""
        platforms = {
            'GitHub': f'https://github.com/{username}',
            'Twitter': f'https://twitter.com/{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'Reddit': f'https://reddit.com/user/{username}'
        }
        
        found_profiles = {}
        
        for platform, url in platforms.items():
            try:
                response = requests.get(url, timeout=5, headers={
                    'User-Agent': 'Mozilla/5.0'
                })
                if response.status_code == 200:
                    found_profiles[platform] = {
                        'url': url,
                        'found': True
                    }
            except:
                pass
        
        self.results['social_profiles'] = found_profiles
        return self.results


# Fonction pour l'API
def osint_search_func(data):
    """Effectue une recherche OSINT"""
    try:
        target = data.get('target', '').strip()
        search_type = data.get('type', 'username')
        
        if not target:
            return {'error': 'Cible manquante'}
        
        osint = OSINTRecon()
        
        if search_type == 'domain':
            results = osint.domain_recon(target)
        elif search_type == 'username':
            results = osint.username_search(target)
        else:
            return {'error': f'Type de recherche inconnu: {search_type}'}
        
        return results
    
    except Exception as e:
        return {'error': f'Erreur OSINT: {str(e)}'}