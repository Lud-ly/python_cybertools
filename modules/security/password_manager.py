#!/usr/bin/env python3
"""
Password Manager - Gestionnaire de mots de passe chiffré
"""
import os
import json
import base64
import string
import secrets
import re
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


def generate_password_func(data):
    length = data.get("length", 16)
    characters = string.ascii_letters + string.digits + string.punctuation
    password = "".join(secrets.choice(characters) for _ in range(length))
    strength = check_password_strength_func({"password": password})
    return {
        "password": password,
        "length": length,
        "strength": strength["level"],
    }

def check_password_strength_func(data):
    password = data.get("password", "")
    score = 0
    suggestions = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        suggestions.append("Utilisez au moins 12 caractères")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        suggestions.append("Ajoutez des lettres majuscules")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        suggestions.append("Ajoutez des lettres minuscules")

    if re.search(r"\d", password):
        score += 1
    else:
        suggestions.append("Ajoutez des chiffres")

    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        suggestions.append("Ajoutez des caractères spéciaux")

    if score <= 2:
        level = "Faible"
    elif score <= 3:
        level = "Moyen"
    elif score <= 4:
        level = "Fort"
    else:
        level = "Très Fort"

    if not suggestions:
        suggestions.append("Excellent mot de passe!")

    return {"score": score, "level": level, "suggestions": suggestions}