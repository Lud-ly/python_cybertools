#!/usr/bin/env python3
"""
Routes Threat Intelligence : VirusTotal, IOC Enrichment
"""
from flask import Blueprint, request, jsonify

# ========== IMPORTER LES MIDDLEWARES ==========
from middleware.rate_limiter import rate_limit
from middleware.input_sanitizer import sanitize_input, validate_json_schema

from modules.analysis.virus_total import (
    virus_total_scan,
    submit_url_to_virustotal,
    get_url_report_from_virustotal
)
from modules.analysis.ioc_enrichment import enrich_ioc_api


threat_intel_bp = Blueprint("threat_intel", __name__)


# ========== VirusTotal ==========

@threat_intel_bp.route("/virus-total", methods=["POST"])
@rate_limit(max_requests=4, window_seconds=60)  # API VirusTotal gratuite : 4 req/min
@validate_json_schema(required_fields=['url'])
@sanitize_input(fields=['url'])
def virus_total():
    """Scan complet VirusTotal"""
    data = getattr(request, 'sanitized_data', None) or request.get_json()
    
    # Validation URL
    url = data.get('url', '').strip()
    if not url.startswith(('http://', 'https://')):
        return jsonify({'error': 'URL doit commencer par http:// ou https://'}), 400
    
    result = virus_total_scan(data)
    
    if 'error' in result:
        return jsonify(result), 400
    
    return jsonify(result)


@threat_intel_bp.route("/virus-total/submit", methods=["POST"])
@rate_limit(max_requests=4, window_seconds=60)  # Limite API VT
@validate_json_schema(required_fields=['url'])
@sanitize_input(fields=['url'])
def virus_total_submit():
    """Soumet une URL à VirusTotal"""
    data = getattr(request, 'sanitized_data', None) or request.get_json()
    
    # Validation URL
    url = data.get('url', '').strip()
    if not url.startswith(('http://', 'https://')):
        return jsonify({'error': 'URL doit commencer par http:// ou https://'}), 400
    
    result = submit_url_to_virustotal(data)
    
    if 'error' in result:
        return jsonify(result), 400
    
    return jsonify(result)


@threat_intel_bp.route("/virus-total/report", methods=["POST"])
@rate_limit(max_requests=4, window_seconds=60)  # Limite API VT
@validate_json_schema(required_fields=['url'])
@sanitize_input(fields=['url'])
def virus_total_report():
    """Récupère un rapport VirusTotal"""
    data = getattr(request, 'sanitized_data', None) or request.get_json()
    
    result = get_url_report_from_virustotal(data)
    
    if 'error' in result:
        return jsonify(result), 400
    
    return jsonify(result)


# ========== IOC Enrichment ==========

@threat_intel_bp.route('/ioc-enrich', methods=['POST'])
@rate_limit(max_requests=10, window_seconds=60)  # 10 enrichissements/min
@validate_json_schema(required_fields=['ioc'], optional_fields=['ioc_type', 'vt_api_key', 'shodan_api_key'])
@sanitize_input(fields=['ioc', 'ioc_type'])  # NE PAS nettoyer les API keys
def ioc_enrichment():
    """Enrichir un IOC avec VirusTotal et Shodan"""
    try:
        data = getattr(request, 'sanitized_data', None) or request.get_json()
        ioc = data.get('ioc', '').strip()
        ioc_type = data.get('ioc_type', 'ip')
        vt_api_key = data.get('vt_api_key', '')
        shodan_api_key = data.get('shodan_api_key', '')
        
        if not ioc:
            return jsonify({'error': 'IOC requis'}), 400
        
        # Validation IOC type
        if ioc_type not in ['ip', 'domain']:
            return jsonify({'error': 'ioc_type doit être "ip" ou "domain"'}), 400
        
        result = enrich_ioc_api(
            ioc=ioc,
            ioc_type=ioc_type,
            vt_api=vt_api_key,
            shodan_api=shodan_api_key
        )
        
        if 'error' in result:
            return jsonify(result), 400
        
        return jsonify({
            'success': True,
            'ioc': ioc,
            'type': ioc_type,
            'enrichment': result
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@threat_intel_bp.route('/ioc-enrich-batch', methods=['POST'])
@rate_limit(max_requests=3, window_seconds=60)  # Limité car batch intensif
@validate_json_schema(required_fields=['iocs'], optional_fields=['ioc_type', 'vt_api_key', 'shodan_api_key'])
def ioc_enrichment_batch():
    """Enrichir plusieurs IOCs en batch"""
    try:
        data = getattr(request, 'sanitized_data', None) or request.get_json()
        iocs_list = data.get('iocs', [])
        ioc_type = data.get('ioc_type', 'ip')
        vt_api_key = data.get('vt_api_key', '')
        shodan_api_key = data.get('shodan_api_key', '')
        
        if not iocs_list:
            return jsonify({'error': 'Liste d\'IOCs vide'}), 400
        
        if not isinstance(iocs_list, list):
            return jsonify({'error': 'iocs doit être une liste'}), 400
        
        # Limiter le nombre d'IOCs par batch
        if len(iocs_list) > 50:
            return jsonify({'error': 'Maximum 50 IOCs par batch'}), 400
        
        # Validation IOC type
        if ioc_type not in ['ip', 'domain']:
            return jsonify({'error': 'ioc_type doit être "ip" ou "domain"'}), 400
        
        results = []
        for ioc in iocs_list:
            try:
                result = enrich_ioc_api(
                    ioc=ioc.strip(),
                    ioc_type=ioc_type,
                    vt_api=vt_api_key,
                    shodan_api=shodan_api_key
                )
                results.append({
                    'ioc': ioc,
                    'status': 'success' if 'error' not in result else 'error',
                    'data': result
                })
            except Exception as e:
                results.append({
                    'ioc': ioc,
                    'status': 'error',
                    'error': str(e)
                })
        
        return jsonify({
            'success': True,
            'total': len(iocs_list),
            'results': results
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
