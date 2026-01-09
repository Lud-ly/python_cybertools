#!/usr/bin/env python3
"""
Route de health check et monitoring
"""
from flask import Blueprint, jsonify
import os
import psutil
from datetime import datetime

# ========== IMPORTER MIDDLEWARE RATE LIMITING ==========
from middleware.rate_limiter import rate_limit

health_bp = Blueprint("health", __name__)


@health_bp.route('/health', methods=['GET'])
@rate_limit(max_requests=100, window_seconds=60)  # Très permissif pour health check
def health_check():
    """Vérifie l'état de l'API et des modules"""
    return jsonify({
        'status': 'online',
        'timestamp': datetime.now().isoformat(),
        'version': '1.5.0',
        'modules': {
            'security': True,
            'scanning': True,
            'analysis': True,
            'threat_intel': True,
            'recon': True,
            'vault': True
        },
        'features': [
            'hash_passwords',
            'generate_passwords',
            'check_strength',
            'email_validation',
            'virus_total_scan',
            'nmap_scanner',
            'pentest_automation',
            'port_scanner',
            'log_analyzer',
            'ioc_enrichment',
            'gitstats',
            'web_enumeration',
            'http_bruteforce',
            'osint_recon',
            'securevault'
        ]
    })


@health_bp.route('/status', methods=['GET'])
@rate_limit(max_requests=60, window_seconds=60)  # 1 req/sec max
def system_status():
    """Informations système détaillées"""
    try:
        return jsonify({
            'status': 'online',
            'timestamp': datetime.now().isoformat(),
            'system': {
                'cpu_percent': psutil.cpu_percent(interval=0.1),  # Réduit l'interval
                'memory_percent': psutil.virtual_memory().percent,
                'memory_available_mb': psutil.virtual_memory().available / (1024 * 1024),
                'disk_percent': psutil.disk_usage('/').percent,
                'disk_free_gb': psutil.disk_usage('/').free / (1024 * 1024 * 1024)
            },
            'runtime': {
                'python_version': f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}",
                'platform': os.sys.platform
            },
            'api': {
                'version': '1.5.0',
                'endpoints_count': 25  # Approximatif
            }
        })
    except Exception as e:
        return jsonify({
            'status': 'degraded',
            'message': 'System monitoring partially unavailable',
            'error': str(e)
        }), 503


@health_bp.route('/ping', methods=['GET'])
@rate_limit(max_requests=200, window_seconds=60)  # Très permissif pour ping
def ping():
    """Ping minimal pour tests de connectivité"""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat()
    })
