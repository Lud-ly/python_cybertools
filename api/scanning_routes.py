"""
Routes de scanning : Nmap, Port Scanner, Pentest, Threat Scanner
"""
from flask import Blueprint, request, jsonify
from modules.scanning.nmap_scanner import NmapScanner
from modules.scanning.pentest_nmap import PentestNmap
from modules.scanning.ports_scanner import scan_target_api
from modules.scanning.threat_scanner import ThreatScanner

scanning_bp = Blueprint("scanning", __name__)


@scanning_bp.route('/nmap', methods=['POST'])
def nmap_scan():
    """Scan de ports avec Nmap basique"""
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


@scanning_bp.route('/pentest-nmap', methods=['POST'])
def pentest_nmap_automation():
    """Automatisation de pentest avec Nmap (scan rapide, complet, vulns, OS)"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        scan_mode = data.get('scan_mode', 'quick')  # quick, full, vuln, os, all
        ports = data.get('ports', '1-1000')
        
        if not target:
            return jsonify({'error': 'Target manquant'}), 400
        
        pentest = PentestNmap(target)
        
        if not pentest.check_nmap_installed():
            return jsonify({
                'error': 'Nmap non installé sur le système',
                'install_instructions': {
                    'macOS': 'brew install nmap',
                    'Linux': 'sudo apt-get install nmap',
                    'Windows': 'https://nmap.org/download.html'
                }
            }), 500
        
        results = {
            'target': target,
            'scan_mode': scan_mode,
            'scans_executed': []
        }
        
        if scan_mode == 'quick' or scan_mode == 'all':
            pentest.quick_scan()
            results['scans_executed'].append('quick_scan')
        
        if scan_mode == 'full' or scan_mode == 'all':
            pentest.full_scan(ports)
            results['scans_executed'].append('full_scan')
        
        if scan_mode == 'vuln' or scan_mode == 'all':
            pentest.vuln_scan()
            results['scans_executed'].append('vuln_scan')
        
        if scan_mode == 'os':
            pentest.os_detection()
            results['scans_executed'].append('os_detection')
        
        results['data'] = pentest.results
        
        if data.get('generate_report', False):
            output_dir = data.get('output_dir', 'data/reports')
            report_file = pentest.generate_report(output_dir)
            results['report_file'] = report_file
        
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@scanning_bp.route('/port-scanner', methods=['POST'])
def port_scanner_advanced():
    """Scanner de ports avancé avec récupération de bannières"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        ports_range = data.get('ports', '1-1000')
        threads = data.get('threads', 100)
        timeout = data.get('timeout', 1.0)
        
        if not target:
            return jsonify({'error': 'Target manquant'}), 400
        
        try:
            start, end = map(int, ports_range.split('-'))
            if start < 1 or end > 65535 or start > end:
                return jsonify({'error': 'Range de ports invalide (1-65535)'}), 400
        except ValueError:
            return jsonify({'error': 'Format de ports invalide (ex: 1-1000)'}), 400
        
        results = scan_target_api(target, range(start, end + 1), threads, timeout)
        
        return jsonify({
            'target': target,
            'ports_scanned': f'{start}-{end}',
            'total_scanned': end - start + 1,
            'open_ports_count': len(results),
            'open_ports': results,
            'scan_completed': True
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500