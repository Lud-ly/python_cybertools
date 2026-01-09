#!/usr/bin/env python3
"""
Routes SecureVault : Gestionnaire de mots de passe chiffré
"""
from flask import Blueprint, request, jsonify
import os

# ========== IMPORTER LES MIDDLEWARES ==========
from middleware.rate_limiter import rate_limit
from middleware.input_sanitizer import sanitize_input, validate_json_schema

vault_bp = Blueprint("vault", __name__)


@vault_bp.route('/securevault/init', methods=['POST'])
@rate_limit(max_requests=5, window_seconds=300)  # 5 créations de vault/5min (sensible)
@validate_json_schema(required_fields=['master_password'], optional_fields=['vault_name'])
@sanitize_input(fields=['vault_name'])  # NE PAS nettoyer master_password
def securevault_init():
    """Initialiser un nouveau vault chiffré"""
    try:
        data = getattr(request, 'sanitized_data', None) or request.get_json()
        master_password = data.get('master_password', '')
        vault_name = data.get('vault_name', 'default')
        
        if not master_password:
            return jsonify({'error': 'Master password requis'}), 400
        
        from modules.vault.securevault import SecureVault, PasswordGenerator
        
        # Vérifier la force du master password
        strength = PasswordGenerator.check_strength(master_password)
        
        if strength['score'] < 40:
            return jsonify({
                'error': 'Master password trop faible',
                'strength': strength,
                'recommendation': 'Utilisez au moins 8 caractères avec majuscules, minuscules, chiffres et symboles'
            }), 400
        
        # Créer le dossier vaults
        os.makedirs('data/vaults', exist_ok=True)
        
        vault_path = f'data/vaults/{vault_name}.db'
        vault = SecureVault(vault_path)
        
        if vault.initialize(master_password):
            return jsonify({
                'success': True,
                'message': 'Vault créé avec succès',
                'vault_name': vault_name,
                'strength': strength
            })
        else:
            return jsonify({'error': 'Le vault existe déjà'}), 400
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@vault_bp.route('/securevault/unlock', methods=['POST'])
@rate_limit(max_requests=10, window_seconds=60)  # 10 tentatives/min
@validate_json_schema(required_fields=['master_password'], optional_fields=['vault_name'])
@sanitize_input(fields=['vault_name'])  # NE PAS nettoyer master_password
def securevault_unlock():
    """Déverrouiller un vault existant"""
    try:
        data = getattr(request, 'sanitized_data', None) or request.get_json()
        master_password = data.get('master_password', '')
        vault_name = data.get('vault_name', 'default')
        
        if not master_password:
            return jsonify({'error': 'Master password requis'}), 400
        
        from modules.vault.securevault import SecureVault
        
        vault_path = f'data/vaults/{vault_name}.db'
        
        if not os.path.exists(vault_path):
            return jsonify({'error': 'Vault introuvable'}), 404
        
        vault = SecureVault(vault_path)
        
        if vault.unlock(master_password):
            return jsonify({
                'success': True,
                'message': 'Vault déverrouillé',
                'vault_name': vault_name,
                'entries_count': len(vault.vault_data.get('entries', []))
            })
        else:
            return jsonify({'error': 'Master password incorrect'}), 401
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@vault_bp.route('/securevault/add', methods=['POST'])
@rate_limit(max_requests=20, window_seconds=60)  # 20 ajouts/min
@validate_json_schema(
    required_fields=['master_password', 'name', 'username', 'password'],
    optional_fields=['vault_name', 'category', 'notes']
)
@sanitize_input(fields=['vault_name', 'name', 'category', 'notes'])  # NE PAS nettoyer passwords
def securevault_add_entry():
    """Ajouter une entrée dans le vault"""
    try:
        data = getattr(request, 'sanitized_data', None) or request.get_json()
        master_password = data.get('master_password', '')
        vault_name = data.get('vault_name', 'default')
        name = data.get('name', '')
        username = data.get('username', '')
        password = data.get('password', '')
        category = data.get('category', 'General')
        notes = data.get('notes', '')
        
        if not all([master_password, name, username, password]):
            return jsonify({'error': 'Tous les champs sont requis'}), 400
        
        from modules.vault.securevault import SecureVault
        
        vault_path = f'data/vaults/{vault_name}.db'
        vault = SecureVault(vault_path)
        
        if not vault.unlock(master_password):
            return jsonify({'error': 'Master password incorrect'}), 401
        
        vault.add_entry(name, username, password, category, notes)
        
        return jsonify({
            'success': True,
            'message': f'Entrée ajoutée pour {name}'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@vault_bp.route('/securevault/list', methods=['POST'])
@rate_limit(max_requests=30, window_seconds=60)  # 30 listings/min
@validate_json_schema(required_fields=['master_password'], optional_fields=['vault_name'])
@sanitize_input(fields=['vault_name'])
def securevault_list_entries():
    """Lister toutes les entrées du vault"""
    try:
        data = getattr(request, 'sanitized_data', None) or request.get_json()
        master_password = data.get('master_password', '')
        vault_name = data.get('vault_name', 'default')
        
        if not master_password:
            return jsonify({'error': 'Master password requis'}), 400
        
        from modules.vault.securevault import SecureVault
        
        vault_path = f'data/vaults/{vault_name}.db'
        vault = SecureVault(vault_path)
        
        if not vault.unlock(master_password):
            return jsonify({'error': 'Master password incorrect'}), 401
        
        entries = vault.list_entries()
        
        return jsonify({
            'success': True,
            'total': len(entries),
            'entries': entries
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@vault_bp.route('/securevault/get', methods=['POST'])
@rate_limit(max_requests=30, window_seconds=60)  # 30 récupérations/min
@validate_json_schema(required_fields=['master_password', 'name'], optional_fields=['vault_name'])
@sanitize_input(fields=['vault_name', 'name'])
def securevault_get_entry():
    """Récupérer une entrée spécifique du vault"""
    try:
        data = getattr(request, 'sanitized_data', None) or request.get_json()
        master_password = data.get('master_password', '')
        vault_name = data.get('vault_name', 'default')
        name = data.get('name', '')
        
        if not all([master_password, name]):
            return jsonify({'error': 'Master password et nom requis'}), 400
        
        from modules.vault.securevault import SecureVault
        
        vault_path = f'data/vaults/{vault_name}.db'
        vault = SecureVault(vault_path)
        
        if not vault.unlock(master_password):
            return jsonify({'error': 'Master password incorrect'}), 401
        
        entry = vault.get_entry(name)
        
        if not entry:
            return jsonify({'error': f'Entrée "{name}" introuvable'}), 404
        
        return jsonify({
            'success': True,
            'entry': entry
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@vault_bp.route('/securevault/delete', methods=['POST'])
@rate_limit(max_requests=20, window_seconds=60)  # 20 suppressions/min
@validate_json_schema(required_fields=['master_password', 'name'], optional_fields=['vault_name'])
@sanitize_input(fields=['vault_name', 'name'])
def securevault_delete_entry():
    """Supprimer une entrée du vault"""
    try:
        data = getattr(request, 'sanitized_data', None) or request.get_json()
        master_password = data.get('master_password', '')
        vault_name = data.get('vault_name', 'default')
        name = data.get('name', '')
        
        if not all([master_password, name]):
            return jsonify({'error': 'Master password et nom requis'}), 400
        
        from modules.vault.securevault import SecureVault
        
        vault_path = f'data/vaults/{vault_name}.db'
        vault = SecureVault(vault_path)
        
        if not vault.unlock(master_password):
            return jsonify({'error': 'Master password incorrect'}), 401
        
        if vault.delete_entry(name):
            return jsonify({
                'success': True,
                'message': f'Entrée "{name}" supprimée'
            })
        else:
            return jsonify({'error': f'Entrée "{name}" introuvable'}), 404
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@vault_bp.route('/securevault/delete-vault', methods=['POST'])
@rate_limit(max_requests=3, window_seconds=300)  # TRÈS limité : 3 suppressions/5min
@validate_json_schema(required_fields=['vault_name'])
@sanitize_input(fields=['vault_name'])
def securevault_delete_vault():
    """Supprimer complètement un vault (DANGEREUX)"""
    try:
        data = getattr(request, 'sanitized_data', None) or request.get_json()
        vault_name = data.get('vault_name', 'default')
        
        vault_path = f'data/vaults/{vault_name}.db'
        backup_path = f'{vault_path}.backup'
        
        if not os.path.exists(vault_path):
            return jsonify({'error': 'Vault introuvable'}), 404
        
        # Supprimer le vault et son backup
        os.remove(vault_path)
        if os.path.exists(backup_path):
            os.remove(backup_path)
        
        return jsonify({
            'success': True,
            'message': f'Vault {vault_name} supprimé avec succès'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
