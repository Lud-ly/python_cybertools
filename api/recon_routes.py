#!/usr/bin/env python3
"""
Routes de reconnaissance : OSINT, GitStats, Web Enumerator, HTTP Brute Force
"""
from flask import Blueprint, request, jsonify

# ========== IMPORTER LES MIDDLEWARES ==========
from middleware.rate_limiter import rate_limit
from middleware.input_sanitizer import sanitize_input, validate_json_schema

from modules.recon.gitstats import analyze_git_repo
from modules.recon.web_enumerator import find_forms_func
from modules.recon.http_bruteforce import brute_force_func
from modules.recon.osint import osint_search_func


recon_bp = Blueprint("recon", __name__)


@recon_bp.route('/gitstats', methods=['POST'])
@rate_limit(max_requests=20, window_seconds=60)  # 20 analyses/min
@validate_json_schema(required_fields=['repo_url'])
@sanitize_input(fields=['repo_url'])
def git_statistics():
    """Analyse les statistiques d'un dépôt Git"""
    try:
        data = getattr(request, 'sanitized_data', None) or request.get_json()
        
        # Validation URL GitHub/GitLab
        repo_url = data.get('repo_url', '').strip()
        if not repo_url.startswith(('https://github.com/', 'https://gitlab.com/', 'http://github.com/', 'http://gitlab.com/')):
            return jsonify({'error': 'URL doit être un dépôt GitHub ou GitLab'}), 400
        
        results = analyze_git_repo(data)
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@recon_bp.route('/web-enum', methods=['POST'])
@rate_limit(max_requests=15, window_seconds=60)  # 15 énumérations/min
@validate_json_schema(required_fields=['url'])
@sanitize_input(fields=['url'])
def web_enumeration():
    """Énumère les formulaires d'un site web"""
    try:
        data = getattr(request, 'sanitized_data', None) or request.get_json()
        
        # Validation URL
        url = data.get('url', '').strip()
        if not url.startswith(('http://', 'https://')):
            return jsonify({'error': 'URL doit commencer par http:// ou https://'}), 400
        
        results = find_forms_func(data)
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@recon_bp.route('/http-bruteforce', methods=['POST'])
@rate_limit(max_requests=5, window_seconds=300)  # TRÈS limité : 5 brute force/5min (sensible!)
@validate_json_schema(required_fields=['url', 'username', 'wordlist'])
@sanitize_input(fields=['url', 'username'])  # NE PAS nettoyer wordlist (contient passwords)
def http_brute_force():
    """Brute force HTTP/Login"""
    try:
        data = getattr(request, 'sanitized_data', None) or request.get_json()
        
        # Validation URL
        url = data.get('url', '').strip()
        if not url.startswith(('http://', 'https://')):
            return jsonify({'error': 'URL doit commencer par http:// ou https://'}), 400
        
        # Validation wordlist
        wordlist = data.get('wordlist', [])
        if not isinstance(wordlist, list):
            return jsonify({'error': 'Wordlist doit être une liste'}), 400
        
        if len(wordlist) > 1000:
            return jsonify({'error': 'Wordlist limitée à 1000 mots de passe'}), 400
        
        if len(wordlist) == 0:
            return jsonify({'error': 'Wordlist ne peut pas être vide'}), 400
        
        results = brute_force_func(data)
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@recon_bp.route('/osint', methods=['POST'])
@rate_limit(max_requests=30, window_seconds=60)  # 30 recherches/min
@validate_json_schema(required_fields=['target'])
@sanitize_input(fields=['target'])
def osint_reconnaissance():
    """Recherche OSINT sur une cible"""
    try:
        data = getattr(request, 'sanitized_data', None) or request.get_json()
        
        # Validation target (domaine ou IP)
        target = data.get('target', '').strip()
        if not target or len(target) < 3:
            return jsonify({'error': 'Target invalide (min 3 caractères)'}), 400
        
        results = osint_search_func(data)
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
