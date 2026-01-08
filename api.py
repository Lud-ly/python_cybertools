from flask import Blueprint, request, jsonify
import os
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
            'pentest_nmap',
            'port_scanner',
            'securevault',
            'ioc_enrichment', 
            'gitstats',
            'password_manager',
            'web_enumerator',
            'http_brutforce',
            'osint_recon'
        ]
    })

# ========== Pentest Nmap Automation ==========

@api_blueprint.route('/api/pentest-nmap', methods=['POST'])
def pentest_nmap_automation():
    """Automatisation de pentest avec Nmap (scan rapide, complet, vulns, OS)"""
    try:
        data = request.get_json()
        target = data.get('target', '').strip()
        scan_mode = data.get('scan_mode', 'quick')  # quick, full, vuln, os, all
        ports = data.get('ports', '1-1000')
        
        if not target:
            return jsonify({'error': 'Target manquant'}), 400
        
        # Import du module pentest
        from modules.pentest_nmap import PentestNmap
        
        # Initialisation du scanner
        pentest = PentestNmap(target)
        
        # Vérification que Nmap est installé
        if not pentest.check_nmap_installed():
            return jsonify({
                'error': 'Nmap non installé sur le système',
                'install_instructions': {
                    'macOS': 'brew install nmap',
                    'Linux': 'sudo apt-get install nmap',
                    'Windows': 'https://nmap.org/download.html'
                }
            }), 500
        
        # Exécution des scans selon le mode
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
        
        # Récupération des résultats
        results['data'] = pentest.results
        
        # Génération du rapport (optionnel)
        if data.get('generate_report', False):
            output_dir = data.get('output_dir', 'reports')
            report_file = pentest.generate_report(output_dir)
            results['report_file'] = report_file
        
        return jsonify(results)
    
    except ImportError as e:
        return jsonify({
            'error': 'Module python-nmap non installé',
            'install_command': 'pip install python-nmap',
            'details': str(e)
        }), 500
    
    except Exception as e:
        return jsonify({
            'error': f'Erreur lors du scan: {str(e)}',
            'type': type(e).__name__
        }), 500

# ========== Port Scanner with Banner Grabbing ==========

@api_blueprint.route('/api/port-scanner', methods=['POST'])
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
        
        # Validation du range de ports
        try:
            start, end = map(int, ports_range.split('-'))
            if start < 1 or end > 65535 or start > end:
                return jsonify({'error': 'Range de ports invalide (1-65535)'}), 400
        except ValueError:
            return jsonify({'error': 'Format de ports invalide (ex: 1-1000)'}), 400
        
        # Import du module scanner
        from modules.port_scanner import scan_target_api
        
        # Lancement du scan
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
        return jsonify({
            'error': f'Erreur lors du scan: {str(e)}',
            'type': type(e).__name__
        }), 500


# ========== SecureVault - Password Manager ==========

@api_blueprint.route('/api/securevault/init', methods=['POST'])
def securevault_init():
    """Initialiser un nouveau vault chiffré"""
    try:
        data = request.get_json()
        print(f"[DEBUG] Data reçue: {data}")  # DEBUG
        
        master_password = data.get('master_password', '')
        vault_name = data.get('vault_name', 'default')
        
        print(f"[DEBUG] Master password length: {len(master_password)}")  # DEBUG
        print(f"[DEBUG] Vault name: {vault_name}")  # DEBUG
        
        if not master_password:
            print("[DEBUG] Master password vide!")  # DEBUG
            return jsonify({'error': 'Master password requis'}), 400
        
        from modules.securevault import SecureVault, PasswordGenerator
        
        # Vérifier la force du master password
        strength = PasswordGenerator.check_strength(master_password)
        print(f"[DEBUG] Strength score: {strength['score']}")  # DEBUG
        
        if strength['score'] < 60:
            print(f"[DEBUG] Password trop faible: {strength}")  # DEBUG
            return jsonify({
                'error': 'Master password trop faible',
                'strength': strength,
                'recommendation': 'Utilisez au moins 12 caractères avec majuscules, minuscules, chiffres et symboles'
            }), 400
        
        # Créer le dossier vaults s'il n'existe pas
        os.makedirs('vaults', exist_ok=True)
        
        vault_path = f'vaults/{vault_name}.db'
        print(f"[DEBUG] Vault path: {vault_path}")  # DEBUG
        
        vault = SecureVault(vault_path)
        
        if vault.initialize(master_password):
            print("[DEBUG] Vault créé avec succès!")  # DEBUG
            return jsonify({
                'success': True,
                'message': 'Vault créé avec succès',
                'vault_name': vault_name,
                'strength': strength
            })
        else:
            print("[DEBUG] Le vault existe déjà")  # DEBUG
            return jsonify({'error': 'Le vault existe déjà'}), 400
    
    except Exception as e:
        print(f"[ERROR] Exception: {e}")  # DEBUG
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@api_blueprint.route('/api/securevault/unlock', methods=['POST'])
def securevault_unlock():
    """Déverrouiller un vault existant"""
    try:
        data = request.get_json()
        print(f"[DEBUG UNLOCK] Data reçue: {data}")  # DEBUG
        
        master_password = data.get('master_password', '')
        vault_name = data.get('vault_name', 'default')
        
        print(f"[DEBUG UNLOCK] Master password length: {len(master_password)}")  # DEBUG
        print(f"[DEBUG UNLOCK] Vault name: {vault_name}")  # DEBUG
        
        if not master_password:
            return jsonify({'error': 'Master password requis'}), 400
        
        from modules.securevault import SecureVault
        
        vault_path = f'vaults/{vault_name}.db'
        print(f"[DEBUG UNLOCK] Vault path: {vault_path}")  # DEBUG
        print(f"[DEBUG UNLOCK] Vault existe: {os.path.exists(vault_path)}")  # DEBUG
        
        vault = SecureVault(vault_path)
        
        if vault.unlock(master_password):
            print("[DEBUG UNLOCK] Vault déverrouillé avec succès!")  # DEBUG
            return jsonify({
                'success': True,
                'message': 'Vault déverrouillé',
                'vault_name': vault_name,
                'entries_count': len(vault.vault_data['entries'])
            })
        else:
            print("[DEBUG UNLOCK] Échec du déverrouillage")  # DEBUG
            return jsonify({'error': 'Master password incorrect ou vault introuvable'}), 401
    
    except Exception as e:
        print(f"[ERROR UNLOCK] Exception: {e}")  # DEBUG
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# ========== IOC Enrichment (VirusTotal + Shodan) ==========

@api_blueprint.route('/api/ioc-enrich', methods=['POST'])
def ioc_enrichment():
    """Enrichir un IOC avec VirusTotal et Shodan"""
    try:
        data = request.get_json()
        ioc = data.get('ioc', '').strip()
        ioc_type = data.get('ioc_type', 'ip')  # ip ou domain
        vt_api_key = data.get('vt_api_key', '')
        shodan_api_key = data.get('shodan_api_key', '')
        
        if not ioc:
            return jsonify({'error': 'IOC requis'}), 400
        
        from modules.ioc_enrichment import enrich_ioc_api
        
        # Enrichissement
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


@api_blueprint.route('/api/ioc-enrich-batch', methods=['POST'])
def ioc_enrichment_batch():
    """Enrichir plusieurs IOCs en batch"""
    try:
        data = request.get_json()
        iocs_list = data.get('iocs', [])  # Liste d'IOCs
        ioc_type = data.get('ioc_type', 'ip')
        vt_api_key = data.get('vt_api_key', '')
        shodan_api_key = data.get('shodan_api_key', '')
        
        if not iocs_list:
            return jsonify({'error': 'Liste d\'IOCs vide'}), 400
        
        from modules.ioc_enrichment import enrich_ioc_api
        
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
