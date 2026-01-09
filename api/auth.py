#!/usr/bin/env python3
"""
Routes d'authentification : Login, Register, Token Refresh
"""
from flask import Blueprint, request, jsonify
from middleware.rate_limiter import rate_limit
from middleware.input_sanitizer import sanitize_input, validate_json_schema
from middleware.auth_middleware import generate_token
import hashlib
import os
import json
from datetime import datetime

auth_bp = Blueprint("auth", __name__)

# Fichier simple pour stocker les users (remplacer par BDD en prod)
USERS_FILE = 'data/users.json'


def load_users():
    """Charge les utilisateurs depuis le fichier"""
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}


def save_users(users):
    """Sauvegarde les utilisateurs dans le fichier"""
    os.makedirs('data', exist_ok=True)
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)


def hash_password(password: str) -> str:
    """Hash un mot de passe avec SHA256 + salt"""
    salt = os.getenv('PASSWORD_SALT', 'default-salt-change-me')
    return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()


@auth_bp.route('/auth/register', methods=['POST'])
@rate_limit(max_requests=5, window_seconds=300)  # 5 inscriptions/5min
@validate_json_schema(required_fields=['username', 'password'], optional_fields=['email'])
@sanitize_input(fields=['username', 'email'])
def register():
    """Créer un nouveau compte utilisateur"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        email = data.get('email', '').strip()
        
        # Validation
        if len(username) < 3:
            return jsonify({'error': 'Username doit avoir au moins 3 caractères'}), 400
        
        if len(password) < 8:
            return jsonify({'error': 'Password doit avoir au moins 8 caractères'}), 400
        
        # Charger les users existants
        users = load_users()
        
        if username in users:
            return jsonify({'error': 'Username déjà utilisé'}), 409
        
        # Créer le nouvel utilisateur
        users[username] = {
            'password_hash': hash_password(password),
            'email': email,
            'created_at': datetime.now().isoformat(),
            'active': True
        }
        
        save_users(users)
        
        # Générer un token immédiatement
        token = generate_token(username, expires_in=3600)
        
        return jsonify({
            'success': True,
            'message': 'Compte créé avec succès',
            'username': username,
            'token': token,
            'expires_in': 3600
        }), 201
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/auth/login', methods=['POST'])
@rate_limit(max_requests=10, window_seconds=60)  # 10 tentatives/min
@validate_json_schema(required_fields=['username', 'password'])
@sanitize_input(fields=['username'])
def login():
    """Connexion et génération de token JWT"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        # Charger les users
        users = load_users()
        
        # Vérifier si l'user existe
        if username not in users:
            return jsonify({'error': 'Username ou password incorrect'}), 401
        
        user = users[username]
        
        # Vérifier le password
        if user['password_hash'] != hash_password(password):
            return jsonify({'error': 'Username ou password incorrect'}), 401
        
        # Vérifier si le compte est actif
        if not user.get('active', True):
            return jsonify({'error': 'Compte désactivé'}), 403
        
        # Générer le token
        token = generate_token(username, expires_in=3600)
        
        return jsonify({
            'success': True,
            'message': 'Connexion réussie',
            'username': username,
            'token': token,
            'expires_in': 3600
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/auth/verify', methods=['GET'])
@rate_limit(max_requests=100, window_seconds=60)
def verify_token():
    """Vérifier si un token est valide"""
    try:
        from middleware.auth_middleware import auth_required
        
        # Le decorator auth_required fait la vérification
        @auth_required
        def verify():
            return jsonify({
                'valid': True,
                'user': request.user
            })
        
        return verify()
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/auth/refresh', methods=['POST'])
@rate_limit(max_requests=30, window_seconds=60)
def refresh_token():
    """Rafraîchir un token expiré"""
    try:
        from middleware.auth_middleware import auth_required
        
        @auth_required
        def refresh():
            username = request.user.get('user_id')
            new_token = generate_token(username, expires_in=3600)
            
            return jsonify({
                'success': True,
                'token': new_token,
                'expires_in': 3600
            })
        
        return refresh()
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@auth_bp.route('/auth/me', methods=['GET'])
@rate_limit(max_requests=60, window_seconds=60)
def get_current_user():
    """Récupérer les infos de l'utilisateur connecté"""
    try:
        from middleware.auth_middleware import auth_required
        
        @auth_required
        def get_user():
            username = request.user.get('user_id')
            users = load_users()
            
            if username not in users:
                return jsonify({'error': 'User not found'}), 404
            
            user = users[username]
            
            return jsonify({
                'username': username,
                'email': user.get('email'),
                'created_at': user.get('created_at'),
                'active': user.get('active', True)
            })
        
        return get_user()
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
