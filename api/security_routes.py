#!/usr/bin/env python3
"""
Routes de sécurité : Hash, génération de mots de passe, validation email
"""
from flask import Blueprint, request, jsonify

# ========== IMPORTER LES MIDDLEWARES ==========
from middleware.rate_limiter import rate_limit
from middleware.input_sanitizer import sanitize_input, validate_json_schema

from modules.security.hashing import hash_password_func
from modules.security.password_manager import generate_password_func, check_password_strength_func
from modules.security.email_validator import validate_email_func


security_bp = Blueprint("security", __name__)


@security_bp.route('/hash', methods=['POST'])
@rate_limit(max_requests=30, window_seconds=60)  # Max 30 requêtes/min
@validate_json_schema(required_fields=['password'], optional_fields=['algo'])
@sanitize_input(fields=['algo'])  # Nettoyer algo mais PAS le password
def hash_password():
    """Hacher un mot de passe"""
    data = getattr(request, 'sanitized_data', None) or request.get_json()
    password = data.get('password', '')
    algo = data.get('algo', 'sha256')
    
    if not password:
        return jsonify({'error': 'Password requis'}), 400
    
    result = hash_password_func(password, algo)
    return jsonify({'hash': result, 'algo': algo})


@security_bp.route("/generate-password", methods=["POST"])
@rate_limit(max_requests=50, window_seconds=60)  # Plus permissif pour génération
def generate_password():
    """Génère un mot de passe aléatoire sécurisé"""
    data = getattr(request, 'sanitized_data', None) or request.get_json()
    return jsonify(generate_password_func(data))


@security_bp.route("/check-strength", methods=["POST"])
@rate_limit(max_requests=100, window_seconds=60)  # Très permissif pour check
@validate_json_schema(required_fields=['password'])
def check_strength():
    """Vérifie la force d'un mot de passe"""
    data = getattr(request, 'sanitized_data', None) or request.get_json()
    return jsonify(check_password_strength_func(data))


@security_bp.route("/validate-email", methods=["POST"])
@rate_limit(max_requests=50, window_seconds=60)
@validate_json_schema(required_fields=['email'])
@sanitize_input(fields=['email'], max_length=254)  # RFC 5321 max length
def validate_email():
    """Valide le format d'une adresse email"""
    data = getattr(request, 'sanitized_data', None) or request.get_json()
    return jsonify(validate_email_func(data))
