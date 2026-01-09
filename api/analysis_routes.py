#!/usr/bin/env python3
"""
Routes d'analyse : Log Analyzer
"""
from flask import Blueprint, request, jsonify
from modules.analysis.log_analyzer import analyze_log_file


analysis_bp = Blueprint("analysis", __name__)


@analysis_bp.route('/log-analyzer', methods=['POST'])
def log_analyzer():
    """Analyser des logs Apache/Nginx"""
    try:
        data = request.get_json()
        log_content = data.get('log_content', '').strip()
        
        if not log_content:
            return jsonify({'error': 'Contenu de log requis'}), 400
        
        result = analyze_log_file({'log_content': log_content})
        
        if 'error' in result:
            return jsonify(result), 400
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
