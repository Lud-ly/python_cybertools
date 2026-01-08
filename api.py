from flask import Blueprint, request, jsonify

# Modules existants
from modules.security import (
    hash_password_func,
    generate_password_func,
    check_password_strength_func,
    validate_email_func,
)
from modules.virus_total import (
    virus_total_scan,
    submit_url_to_virustotal,
    get_url_report_from_virustotal,
)
from modules.nmap_scanner import NmapScanner

# Nouveaux modules
from modules.gitstats import analyze_git_repo
from modules.password_manager import save_password_func, load_passwords_func, delete_password_func
from modules.web_enumerator import find_forms_func
from modules.http_brutforce import brute_force_func
from modules.osint_recon import osint_search_func

api_blueprint = Blueprint("api", __name__)


# ========== Sécurité & Cryptographie ==========

@api_blueprint.route("/api/hash", methods=["POST"])
def hash_password():
    """Hash un mot de passe avec l'algorithme choisi"""
    data = request.get_json()
    return jsonify(hash_password_func(data))


@api_blueprint.route("/api/generate-password", methods=["POST"])
def generate_password():
    """Génère un mot de passe aléatoire sécurisé"""
    data = request.get_json()
    return jsonify(generate_password_func(data))


@api_blueprint.route("/api/check-strength", methods=["POST"])
def check_strength():
    """Vérifie la force d'un mot de passe"""
    data = request.get_json()
    return jsonify(check_password_strength_func(data))


@api_blueprint.route("/api/validate-email", methods=["POST"])
def validate_email():
    """Valide le format d'une adresse email"""
    data = request.get_json()
    return jsonify(validate_email_func(data))


# ========== VirusTotal ==========

@api_blueprint.route("/api/virus-total", methods=["POST"])
def virus_total():
    """Scan complet VirusTotal"""
    data = request.get_json()
    return jsonify(virus_total_scan(data))


@api_blueprint.route("/api/virus-total/submit", methods=["POST"])
def virus_total_submit():
    """Soumet une URL à VirusTotal"""
    data = request.get_json()
    return jsonify(submit_url_to_virustotal(data))


@api_blueprint.route("/api/virus-total/report", methods=["POST"])
def virus_total_report():
    """Récupère un rapport VirusTotal"""
    data = request.get_json()
    return jsonify(get_url_report_from_virustotal(data))


# ========== Nmap Scanner ==========

@api_blueprint.route('/api/nmap', methods=['POST'])
def nmap_scan():
    """Scan de ports avec Nmap"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        scan_type = data.get('scan_type', 'quick')
        ports = data.get('ports', '1-1000')

        if not target:
            return jsonify({'error': 'Target manquant'}), 400

        scanner = NmapScanner()
        
        if scan_type == 'quick':
            results = scanner.quick_scan(target)
        else:
            results = scanner.port_scan(target, ports)

        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ========== Git Statistics ==========

@api_blueprint.route('/api/gitstats', methods=['POST'])
def git_statistics():
    """Analyse les statistiques d'un dépôt Git"""
    try:
        data = request.get_json()
        results = analyze_git_repo(data)
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ========== Password Manager ==========

@api_blueprint.route('/api/password-manager/save', methods=['POST'])
def save_password_endpoint():
    """Sauvegarde un mot de passe de manière sécurisée"""
    try:
        data = request.get_json()
        results = save_password_func(data)
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_blueprint.route('/api/password-manager/load', methods=['POST'])
def load_passwords_endpoint():
    """Charge tous les mots de passe sauvegardés"""
    try:
        data = request.get_json()
        results = load_passwords_func(data)
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_blueprint.route('/api/password-manager/delete', methods=['POST'])
def delete_password_endpoint():
    """Supprime un mot de passe"""
    try:
        data = request.get_json()
        results = delete_password_func(data)
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ========== Web Enumerator ==========

@api_blueprint.route('/api/web-enum', methods=['POST'])
def web_enumeration():
    """Énumère les formulaires d'un site web"""
    try:
        data = request.get_json()
        results = find_forms_func(data)
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ========== HTTP Brute Force ==========

@api_blueprint.route('/api/http-bruteforce', methods=['POST'])
def http_brute_force():
    """Brute force HTTP/Login"""
    try:
        data = request.get_json()
        results = brute_force_func(data)
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ========== OSINT Reconnaissance ==========

@api_blueprint.route('/api/osint', methods=['POST'])
def osint_reconnaissance():
    """Recherche OSINT sur une cible"""
    try:
        data = request.get_json()
        results = osint_search_func(data)
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ========== Health Check ==========

@api_blueprint.route('/api/health', methods=['GET'])
def health_check():
    """Vérifie l'état de l'API"""
    return jsonify({
        'status': 'online',
        'modules': [
            'security',
            'virus_total',
            'nmap_scanner',
            'gitstats',
            'password_manager',
            'web_enumerator',
            'http_brutforce',
            'osint_recon'
        ]
    })