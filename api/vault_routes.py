"""
Routes SecureVault : Gestionnaire de mots de passe chiffré
"""
from flask import Blueprint, request, jsonify
import os

vault_bp = Blueprint("vault", __name__)


@vault_bp.route('/securevault/init', methods=['POST'])
def securevault_init():
    """Initialiser un nouveau vault chiffré"""
    try:
        data = request.get_json()
        print(f"DEBUG - Data reçue: {data}")
        
        master_password = data.get('master_password', '')
        vault_name = data.get('vault_name', 'default')
        
        print(f"DEBUG - master_password: '{master_password}'")
        print(f"DEBUG - vault_name: '{vault_name}'")
        
        if not master_password:
            print("DEBUG - Master password vide!")
            return jsonify({'error': 'Master password requis'}), 400
        
        from modules.vault.securevault import SecureVault, PasswordGenerator
        
        # Vérifier la force du master password
        strength = PasswordGenerator.check_strength(master_password)
        print(f"DEBUG - Strength: {strength}")
        
        if strength['score'] < 40:
            print(f"DEBUG - Score trop faible: {strength['score']}")
            return jsonify({
                'error': 'Master password trop faible',
                'strength': strength,
                'recommendation': 'Utilisez au moins 8 caractères avec majuscules, minuscules, chiffres et symboles'
            }), 400
        
        # Créer le dossier vaults
        os.makedirs('data/vaults', exist_ok=True)
        
        vault_path = f'data/vaults/{vault_name}.db'
        print(f"DEBUG - vault_path: {vault_path}")
        
        vault = SecureVault(vault_path)
        
        if vault.initialize(master_password):
            print("DEBUG - Vault créé avec succès!")
            return jsonify({
                'success': True,
                'message': 'Vault créé avec succès',
                'vault_name': vault_name,
                'strength': strength
            })
        else:
            print("DEBUG - Le vault existe déjà")
            return jsonify({'error': 'Le vault existe déjà'}), 400
    
    except Exception as e:
        print(f"DEBUG - Exception: {e}")  # ← AJOUTE
        import traceback
        traceback.print_exc()  # ← AJOUTE
        return jsonify({'error': str(e)}), 500




@vault_bp.route('/securevault/unlock', methods=['POST'])
def securevault_unlock():
    """Déverrouiller un vault existant"""
    try:
        data = request.get_json()
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
def securevault_add_entry():
    """Ajouter une entrée dans le vault"""
    try:
        data = request.get_json()
        master_password = data.get('master_password', '')
        vault_name = data.get('vault_name', 'default')
        name = data.get('name', '')  # ← CHANGE service en name
        username = data.get('username', '')
        password = data.get('password', '')
        category = data.get('category', 'General')  # ← AJOUTE
        notes = data.get('notes', '')  # ← AJOUTE
        
        if not all([master_password, name, username, password]):  # ← CHANGE service en name
            return jsonify({'error': 'Tous les champs sont requis'}), 400
        
        from modules.vault.securevault import SecureVault
        
        vault_path = f'data/vaults/{vault_name}.db'
        vault = SecureVault(vault_path)
        
        if not vault.unlock(master_password):
            return jsonify({'error': 'Master password incorrect'}), 401
        
        vault.add_entry(name, username, password, category, notes)  # ← AJOUTE category et notes
        
        return jsonify({
            'success': True,
            'message': f'Entrée ajoutée pour {name}'  # ← CHANGE service en name
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@vault_bp.route('/securevault/list', methods=['POST'])
def securevault_list_entries():
    """Lister toutes les entrées du vault"""
    try:
        data = request.get_json()
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
            'total': len(entries),  # ← AJOUTE
            'entries': entries
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@vault_bp.route('/securevault/delete-vault', methods=['POST'])
def securevault_delete_vault():
    """Supprimer complètement un vault"""
    try:
        data = request.get_json()
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
