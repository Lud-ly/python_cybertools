#!/usr/bin/env python3
"""
Routes Threat Intelligence : VirusTotal, IOC Enrichment
"""
from flask import Blueprint, request, jsonify
from modules.analysis.virus_total import (
    virus_total_scan,
    submit_url_to_virustotal,
    get_url_report_from_virustotal
)
from modules.analysis.ioc_enrichment import enrich_ioc_api


threat_intel_bp = Blueprint("threat_intel", __name__)


# ========== VirusTotal ==========

@threat_intel_bp.route("/virus-total", methods=["POST"])
def virus_total():
    """Scan complet VirusTotal"""
    data = request.get_json()
    return jsonify(virus_total_scan(data))


@threat_intel_bp.route("/virus-total/submit", methods=["POST"])
def virus_total_submit():
    """Soumet une URL à VirusTotal"""
    data = request.get_json()
    return jsonify(submit_url_to_virustotal(data))


@threat_intel_bp.route("/virus-total/report", methods=["POST"])
def virus_total_report():
    """Récupère un rapport VirusTotal"""
    data = request.get_json()
    return jsonify(get_url_report_from_virustotal(data))


# ========== IOC Enrichment ==========

@threat_intel_bp.route('/ioc-enrich', methods=['POST'])
def ioc_enrichment():
    """Enrichir un IOC avec VirusTotal et Shodan"""
    try:
        data = request.get_json()
        ioc = data.get('ioc', '').strip()
        ioc_type = data.get('ioc_type', 'ip')
        vt_api_key = data.get('vt_api_key', '')
        shodan_api_key = data.get('shodan_api_key', '')
        
        if not ioc:
            return jsonify({'error': 'IOC requis'}), 400
        
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
def ioc_enrichment_batch():
    """Enrichir plusieurs IOCs en batch"""
    try:
        data = request.get_json()
        iocs_list = data.get('iocs', [])
        ioc_type = data.get('ioc_type', 'ip')
        vt_api_key = data.get('vt_api_key', '')
        shodan_api_key = data.get('shodan_api_key', '')
        
        if not iocs_list:
            return jsonify({'error': 'Liste d\'IOCs vide'}), 400
        
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
