#!/usr/bin/env python3
"""
Authentication Middleware - JWT/API Key validation
"""

from functools import wraps
from flask import request, jsonify
import os
import jwt
from datetime import datetime, timedelta


SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')
API_KEY = os.getenv('API_KEY', None)


def auth_required(f):
    """Decorator pour protéger les routes avec JWT ou API Key"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Vérifier API Key dans les headers
        api_key = request.headers.get('X-API-Key')
        if api_key and api_key == API_KEY:
            return f(*args, **kwargs)
        
        # Vérifier JWT Token
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Authentication required', 'code': 'NO_TOKEN'}), 401
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            request.user = data  # Ajouter les données utilisateur à la requête
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired', 'code': 'TOKEN_EXPIRED'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token', 'code': 'INVALID_TOKEN'}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function


def generate_token(user_id: str, expires_in: int = 3600) -> str:
    """Générer un JWT token"""
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(seconds=expires_in),
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')


def optional_auth(f):
    """Decorator pour auth optionnelle (ne bloque pas si pas de token)"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            try:
                data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
                request.user = data
            except:
                request.user = None
        else:
            request.user = None
        
        return f(*args, **kwargs)
    
    return decorated_function
