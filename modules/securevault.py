#!/usr/bin/env python3
"""
SecureVault - Gestionnaire de mots de passe chiffré
Chiffrement AES-256-GCM avec PBKDF2
Pour API Flask
"""

import os
import json
import secrets
import string
import math
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class CryptoEngine:
    """Moteur de chiffrement AES-256-GCM"""
    
    def __init__(self, master_password: str, salt: bytes = None):
        self.salt = salt or os.urandom(32)
        self.key = self._derive_key(master_password)
        self.aesgcm = AESGCM(self.key)
    
    def _derive_key(self, password: str) -> bytes:
        """Dériver une clé de 256 bits depuis le master password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def encrypt(self, data: str) -> bytes:
        """Chiffrer des données avec AES-256-GCM"""
        nonce = os.urandom(12)  # 96 bits pour GCM
        plaintext = data.encode()
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)
        return nonce + ciphertext
    
    def decrypt(self, encrypted_data: bytes) -> str:
        """Déchiffrer des données"""
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()


class PasswordGenerator:
    """Générateur de mots de passe sécurisés"""
    
    @staticmethod
    def generate(length: int = 16, use_symbols: bool = True, 
                use_numbers: bool = True) -> str:
        """Générer un mot de passe aléatoire fort"""
        chars = string.ascii_letters
        if use_numbers:
            chars += string.digits
        if use_symbols:
            chars += string.punctuation
        
        password = ''.join(secrets.choice(chars) for _ in range(length))
        return password
    
    @staticmethod
    def check_strength(password: str) -> Dict[str, any]:
        """Vérifier la force d'un mot de passe"""
        strength = {
            'length': len(password),
            'has_upper': any(c.isupper() for c in password),
            'has_lower': any(c.islower() for c in password),
            'has_digit': any(c.isdigit() for c in password),
            'has_symbol': any(c in string.punctuation for c in password),
            'entropy': 0,
            'score': 0,
            'rating': ''
        }
        
        # Calcul de l'entropie
        charset_size = 0
        if strength['has_lower']: charset_size += 26
        if strength['has_upper']: charset_size += 26
        if strength['has_digit']: charset_size += 10
        if strength['has_symbol']: charset_size += 32
        
        if charset_size > 0:
            strength['entropy'] = len(password) * math.log2(charset_size)
        
        # Score sur 100
        score = 0
        if strength['length'] >= 12: score += 25
        elif strength['length'] >= 8: score += 15
        if strength['has_upper']: score += 15
        if strength['has_lower']: score += 15
        if strength['has_digit']: score += 15
        if strength['has_symbol']: score += 15
        if strength['entropy'] >= 60: score += 15
        
        strength['score'] = min(score, 100)
        
        # Rating
        if strength['score'] >= 80:
            strength['rating'] = 'Excellent'
        elif strength['score'] >= 60:
            strength['rating'] = 'Fort'
        elif strength['score'] >= 40:
            strength['rating'] = 'Moyen'
        else:
            strength['rating'] = 'Faible'
        
        return strength


class SecureVault:
    """Vault principal pour gérer les credentials"""
    
    def __init__(self, vault_path: str = "vault.db"):
        self.vault_path = Path(vault_path)
        self.vault_path.parent.mkdir(parents=True, exist_ok=True)
        self.crypto = None
        self.vault_data = {
            'metadata': {
                'created': datetime.now().isoformat(),
                'modified': datetime.now().isoformat(),
                'version': '1.0'
            },
            'entries': []
        }
    
    def initialize(self, master_password: str) -> bool:
        """Initialiser un nouveau vault"""
        if self.vault_path.exists():
            return False
        
        salt = os.urandom(32)
        self.crypto = CryptoEngine(master_password, salt)
        
        # Sauvegarder le vault
        self._save_vault(salt)
        return True
    
    def unlock(self, master_password: str) -> bool:
        """Déverrouiller un vault existant"""
        if not self.vault_path.exists():
            return False
        
        try:
            with open(self.vault_path, 'rb') as f:
                salt = f.read(32)
                encrypted_data = f.read()
            
            self.crypto = CryptoEngine(master_password, salt)
            decrypted_json = self.crypto.decrypt(encrypted_data)
            self.vault_data = json.loads(decrypted_json)
            
            return True
            
        except Exception:
            return False
    
    def add_entry(self, name: str, username: str, password: str, 
                category: str = "General", notes: str = ""):
        """Ajouter une nouvelle entrée"""
        entry = {
            'id': secrets.token_hex(8),
            'name': name,
            'username': username,
            'password': password,
            'category': category,
            'notes': notes,
            'created': datetime.now().isoformat(),
            'modified': datetime.now().isoformat(),
            'accessed': None
        }
        
        self.vault_data['entries'].append(entry)
        self._save_vault(self.crypto.salt)
    
    def get_entry(self, name: str) -> Optional[Dict]:
        """Récupérer une entrée par nom"""
        for entry in self.vault_data['entries']:
            if entry['name'].lower() == name.lower():
                entry['accessed'] = datetime.now().isoformat()
                self._save_vault(self.crypto.salt)
                return entry
        return None
    
    def delete_entry(self, name: str) -> bool:
        """Supprimer une entrée"""
        for i, entry in enumerate(self.vault_data['entries']):
            if entry['name'].lower() == name.lower():
                del self.vault_data['entries'][i]
                self._save_vault(self.crypto.salt)
                return True
        return False
    
    def _save_vault(self, salt: bytes):
        """Sauvegarder le vault chiffré"""
        # Backup avant sauvegarde
        if self.vault_path.exists():
            backup_path = Path(str(self.vault_path) + '.backup')
            import shutil
            shutil.copy(self.vault_path, backup_path)
        
        self.vault_data['metadata']['modified'] = datetime.now().isoformat()
        json_data = json.dumps(self.vault_data, indent=2)
        encrypted = self.crypto.encrypt(json_data)
        
        with open(self.vault_path, 'wb') as f:
            f.write(salt)
            f.write(encrypted)
