#!/usr/bin/env python3
"""
Input Sanitizer Middleware - Nettoyage et validation des entrées
"""

from functools import wraps
from flask import request, jsonify
import re
import html


class InputSanitizer:
    """Nettoyage et validation des entrées utilisateur"""
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000) -> str:
        """Nettoie une chaîne de caractères"""
        if not isinstance(value, str):
            return str(value)
        
        # Limiter la longueur
        value = value[:max_length]
        
        # Échapper HTML
        value = html.escape(value)
        
        # Supprimer les caractères de contrôle
        value = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', value)
        
        return value.strip()
    
    @staticmethod
    def sanitize_email(email: str) -> str:
        """Valide et nettoie un email"""
        email = email.strip().lower()
        
        # Regex basique pour email
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(pattern, email):
            raise ValueError('Invalid email format')
        
        return email
    
    @staticmethod
    def sanitize_url(url: str) -> str:
        """Valide et nettoie une URL"""
        url = url.strip()
        
        # Vérifier le protocole
        if not url.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        
        # Limiter la longueur
        if len(url) > 2048:
            raise ValueError('URL too long')
        
        return url
    
    @staticmethod
    def sanitize_ip(ip: str) -> str:
        """Valide une adresse IP"""
        ip = ip.strip()
        
        # IPv4
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, ip):
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                return ip
        
        # IPv6 (basique)
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$'
        if re.match(ipv6_pattern, ip):
            return ip
        
        raise ValueError('Invalid IP address')
    
    @staticmethod
    def sanitize_dict(data: dict, schema: dict = None) -> dict:
        """Nettoie un dictionnaire selon un schéma"""
        sanitized = {}
        
        for key, value in data.items():
            # Nettoyer la clé
            clean_key = InputSanitizer.sanitize_string(key, 100)
            
            # Nettoyer la valeur selon son type
            if isinstance(value, str):
                sanitized[clean_key] = InputSanitizer.sanitize_string(value)
            elif isinstance(value, (int, float, bool)):
                sanitized[clean_key] = value
            elif isinstance(value, dict):
                sanitized[clean_key] = InputSanitizer.sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[clean_key] = [
                    InputSanitizer.sanitize_string(str(item)) 
                    if isinstance(item, str) else item
                    for item in value[:100]  # Limiter à 100 éléments
                ]
            else:
                sanitized[clean_key] = str(value)
        
        return sanitized


def sanitize_input(fields: list = None, max_length: int = 1000):
    """
    Decorator pour nettoyer automatiquement les inputs JSON
    
    Args:
        fields: Liste des champs à nettoyer (None = tous)
        max_length: Longueur max des strings
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.is_json:
                data = request.get_json()
                sanitizer = InputSanitizer()
                
                if fields:
                    # Nettoyer seulement les champs spécifiés
                    for field in fields:
                        if field in data and isinstance(data[field], str):
                            data[field] = sanitizer.sanitize_string(data[field], max_length)
                else:
                    # Nettoyer tout le dictionnaire
                    data = sanitizer.sanitize_dict(data)
                
                # Stocker dans un attribut custom de request
                request._sanitized_json = data
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def validate_json_schema(required_fields: list = None, optional_fields: list = None):
    """Valide que les champs requis sont présents dans le JSON"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({'error': 'Content-Type must be application/json'}), 400
            
            data = request.get_json()
            
            # Vérifier les champs requis
            if required_fields:
                missing = [field for field in required_fields if field not in data]
                if missing:
                    return jsonify({
                        'error': 'Missing required fields',
                        'missing_fields': missing
                    }), 400
            
            # Vérifier les champs non autorisés
            if optional_fields is not None:
                allowed = set(required_fields or []) | set(optional_fields)
                extra = [field for field in data.keys() if field not in allowed]
                if extra:
                    return jsonify({
                        'error': 'Unexpected fields',
                        'extra_fields': extra
                    }), 400
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator
