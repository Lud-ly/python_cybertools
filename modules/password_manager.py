#!/usr/bin/env python3
"""
Password Manager - Gestionnaire de mots de passe chiffré
"""
import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


STORAGE_FILE = 'passwords.enc'


def derive_key(password: str, salt: bytes) -> bytes:
    """Dérive une clé AES depuis un mot de passe"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def save_password_func(data):
    """Sauvegarde un mot de passe de manière sécurisée"""
    try:
        service = data.get('service')
        username = data.get('username')
        password = data.get('password')
        master_password = data.get('master_password')
        
        if not all([service, username, password, master_password]):
            return {'error': 'Tous les champs sont requis'}
        
        # Charger les mots de passe existants
        passwords = load_passwords_func({'master_password': master_password})
        
        if 'error' in passwords and 'Fichier de mots de passe introuvable' not in passwords['error']:
            return passwords
        
        # Si nouveau fichier ou erreur de fichier introuvable
        if 'error' in passwords:
            passwords = {'passwords': {}}
        
        # Ajouter le nouveau mot de passe
        passwords['passwords'][service] = {
            'username': username,
            'password': password
        }
        
        # Sauvegarder
        salt = os.urandom(16)
        key = derive_key(master_password, salt)
        f = Fernet(key)
        encrypted = f.encrypt(json.dumps(passwords['passwords']).encode())
        
        data_to_save = {
            'salt': base64.b64encode(salt).decode(),
            'encrypted': base64.b64encode(encrypted).decode()
        }
        
        with open(STORAGE_FILE, 'w') as file:
            json.dump(data_to_save, file)
        
        return {
            'success': True,
            'message': f'Mot de passe pour {service} sauvegardé avec succès'
        }
    
    except Exception as e:
        return {'error': f'Erreur lors de la sauvegarde: {str(e)}'}


def load_passwords_func(data):
    """Charge tous les mots de passe déchiffrés"""
    try:
        master_password = data.get('master_password')
        
        if not master_password:
            return {'error': 'Master password requis'}
        
        if not os.path.exists(STORAGE_FILE):
            return {'error': 'Fichier de mots de passe introuvable'}
        
        with open(STORAGE_FILE) as file:
            stored_data = json.load(file)
        
        salt = base64.b64decode(stored_data['salt'])
        key = derive_key(master_password, salt)
        f = Fernet(key)
        
        decrypted = f.decrypt(base64.b64decode(stored_data['encrypted']))
        passwords = json.loads(decrypted.decode())
        
        return {'passwords': passwords}
    
    except Exception as e:
        return {'error': f'Erreur lors du déchiffrement: {str(e)}'}


def delete_password_func(data):
    """Supprime un mot de passe"""
    try:
        service = data.get('service')
        master_password = data.get('master_password')
        
        if not all([service, master_password]):
            return {'error': 'Service et master password requis'}
        
        passwords = load_passwords_func({'master_password': master_password})
        
        if 'error' in passwords:
            return passwords
        
        if service not in passwords['passwords']:
            return {'error': f'Service {service} introuvable'}
        
        del passwords['passwords'][service]
        
        # Resauvegarder
        salt = os.urandom(16)
        key = derive_key(master_password, salt)
        f = Fernet(key)
        encrypted = f.encrypt(json.dumps(passwords['passwords']).encode())
        
        data_to_save = {
            'salt': base64.b64encode(salt).decode(),
            'encrypted': base64.b64encode(encrypted).decode()
        }
        
        with open(STORAGE_FILE, 'w') as file:
            json.dump(data_to_save, file)
        
        return {
            'success': True,
            'message': f'Mot de passe pour {service} supprimé'
        }
    
    except Exception as e:
        return {'error': f'Erreur lors de la suppression: {str(e)}'}