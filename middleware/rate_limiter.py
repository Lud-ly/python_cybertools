#!/usr/bin/env python3
"""
Rate Limiter Middleware - Protection contre le spam et DDoS
"""

from functools import wraps
from flask import request, jsonify
from collections import defaultdict
from datetime import datetime, timedelta
import threading


class RateLimiter:
    """Simple in-memory rate limiter"""
    
    def __init__(self):
        self.requests = defaultdict(list)
        self.lock = threading.Lock()
    
    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> tuple:
        """Vérifie si la requête est autorisée"""
        now = datetime.now()
        window_start = now - timedelta(seconds=window_seconds)
        
        with self.lock:
            # Nettoyer les anciennes requêtes
            self.requests[key] = [
                req_time for req_time in self.requests[key]
                if req_time > window_start
            ]
            
            # Vérifier le nombre de requêtes
            if len(self.requests[key]) >= max_requests:
                retry_after = int((self.requests[key][0] - window_start).total_seconds())
                return False, retry_after
            
            # Ajouter la nouvelle requête
            self.requests[key].append(now)
            return True, 0
    
    def cleanup(self):
        """Nettoyer périodiquement la mémoire"""
        now = datetime.now()
        with self.lock:
            for key in list(self.requests.keys()):
                self.requests[key] = [
                    req_time for req_time in self.requests[key]
                    if (now - req_time).total_seconds() < 3600
                ]
                if not self.requests[key]:
                    del self.requests[key]


# Instance globale
limiter = RateLimiter()


def rate_limit(max_requests: int = 60, window_seconds: int = 60, key_func=None):
    """
    Decorator pour limiter le nombre de requêtes
    
    Args:
        max_requests: Nombre maximum de requêtes
        window_seconds: Fenêtre de temps en secondes
        key_func: Fonction pour générer la clé (par défaut: IP)
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Générer la clé de rate limiting
            if key_func:
                key = key_func()
            else:
                key = request.remote_addr or 'unknown'
            
            # Vérifier le rate limit
            allowed, retry_after = limiter.is_allowed(key, max_requests, window_seconds)
            
            if not allowed:
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'message': f'Too many requests. Max {max_requests} per {window_seconds}s',
                    'retry_after': retry_after
                }), 429
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def rate_limit_by_user(max_requests: int = 100, window_seconds: int = 60):
    """Rate limit basé sur l'utilisateur authentifié"""
    def key_func():
        if hasattr(request, 'user') and request.user:
            return f"user:{request.user.get('user_id', 'anonymous')}"
        return f"ip:{request.remote_addr}"
    
    return rate_limit(max_requests, window_seconds, key_func)
