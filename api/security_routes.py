"""
Routes de sécurité : Hash, génération de mots de passe, validation email
"""
from flask import Blueprint, request, jsonify
from modules.security.hashing import hash_password_func
from modules.security.password_manager import generate_password_func, check_password_strength_func
from modules.security.email_validator import validate_email_func

security_bp = Blueprint("security", __name__)


@security_bp.route('/hash', methods=['POST'])
def hash_password():
    data = request.get_json()
    password = data.get('password', '')
    algo = data.get('algo', 'sha256')
    
    if not password:
        return jsonify({'error': 'Password requis'}), 400
    
    result = hash_password_func(password, algo)
    return jsonify({'hash': result, 'algo': algo})



@security_bp.route("/generate-password", methods=["POST"])
def generate_password():
    """Génère un mot de passe aléatoire sécurisé"""
    data = request.get_json()
    return jsonify(generate_password_func(data))


@security_bp.route("/check-strength", methods=["POST"])
def check_strength():
    """Vérifie la force d'un mot de passe"""
    data = request.get_json()
    return jsonify(check_password_strength_func(data))


@security_bp.route("/validate-email", methods=["POST"])
def validate_email():
    """Valide le format d'une adresse email"""
    data = request.get_json()
    return jsonify(validate_email_func(data))