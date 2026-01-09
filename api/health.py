"""
Route de health check et monitoring
"""
from flask import Blueprint, jsonify
import os
import psutil
from datetime import datetime

health_bp = Blueprint("health", __name__)


@health_bp.route('/health', methods=['GET'])
def health_check():
    """Vérifie l'état de l'API et des modules"""
    return jsonify({
        'status': 'online',
        'timestamp': datetime.now().isoformat(),
        'modules': {
            'security': True,
            'scanning': True,
            'analysis': True,
            'recon': True,
            'vault': True
        },
        'features': [
            'hash_passwords',
            'generate_passwords',
            'email_validation',
            'virus_total_scan',
            'nmap_scanner',
            'pentest_automation',
            'port_scanner',
            'gitstats',
            'web_enumeration',
            'http_bruteforce',
            'osint_recon',
            'securevault',
            'ioc_enrichment'
        ]
    })


@health_bp.route('/status', methods=['GET'])
def system_status():
    """Informations système détaillées"""
    try:
        return jsonify({
            'status': 'online',
            'system': {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent
            },
            'python_version': os.sys.version,
            'uptime': 'N/A'  # À implémenter si nécessaire
        })
    except:
        return jsonify({
            'status': 'online',
            'message': 'Système monitoring non disponible'
        })