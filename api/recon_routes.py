"""
Routes de reconnaissance : OSINT, GitStats, Web Enumerator, HTTP Brute Force
"""
from flask import Blueprint, request, jsonify
from modules.recon.gitstats import analyze_git_repo
from modules.recon.web_enumerator import find_forms_func
from modules.recon.http_bruteforce import brute_force_func
from modules.recon.osint import osint_search_func

recon_bp = Blueprint("recon", __name__)


@recon_bp.route('/gitstats', methods=['POST'])
def git_statistics():
    """Analyse les statistiques d'un dépôt Git"""
    try:
        data = request.get_json()
        results = analyze_git_repo(data)
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@recon_bp.route('/web-enum', methods=['POST'])
def web_enumeration():
    """Énumère les formulaires d'un site web"""
    try:
        data = request.get_json()
        results = find_forms_func(data)
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@recon_bp.route('/http-bruteforce', methods=['POST'])
def http_brute_force():
    """Brute force HTTP/Login"""
    try:
        data = request.get_json()
        results = brute_force_func(data)
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@recon_bp.route('/osint', methods=['POST'])
def osint_reconnaissance():
    """Recherche OSINT sur une cible"""
    try:
        data = request.get_json()
        results = osint_search_func(data)
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500