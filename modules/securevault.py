#!/usr/bin/env python3
"""
SecureVault - Gestionnaire de mots de passe chiffré CLI
Chiffrement AES-256-GCM avec PBKDF2
Author: Ludovic Mouly
GitHub: https://github.com/Lud-ly/python_cybertools
"""

import os
import json
import secrets
import string
import hashlib
import getpass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import argparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich import print as rprint

try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False

console = Console()

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
            'score': 0
        }
        
        # Calcul de l'entropie
        charset_size = 0
        if strength['has_lower']: charset_size += 26
        if strength['has_upper']: charset_size += 26
        if strength['has_digit']: charset_size += 10
        if strength['has_symbol']: charset_size += 32
        
        import math
        if charset_size > 0:
            strength['entropy'] = len(password) * math.log2(charset_size)
        
        # Score sur 100
        score = 0
        if strength['length'] >= 12: score += 25
        if strength['has_upper']: score += 15
        if strength['has_lower']: score += 15
        if strength['has_digit']: score += 15
        if strength['has_symbol']: score += 15
        if strength['entropy'] >= 60: score += 15
        
        strength['score'] = min(score, 100)
        
        return strength

class SecureVault:
    """Vault principal pour gérer les credentials"""
    
    def __init__(self, vault_path: str = "vault.db"):
        self.vault_path = Path(vault_path)
        self.crypto = None
        self.vault_data = {
            'metadata': {
                'created': datetime.now().isoformat(),
                'modified': datetime.now().isoformat(),
                'version': '1.0'
            },
            'entries': []
        }
    
    def initialize(self, master_password: str):
        """Initialiser un nouveau vault"""
        if self.vault_path.exists():
            console.print("[red]❌ Vault déjà existant![/red]")
            return False
        
        # Vérifier la force du master password
        strength = PasswordGenerator.check_strength(master_password)
        if strength['score'] < 60:
            console.print(f"[yellow]⚠️  Master password faible (score: {strength['score']}/100)[/yellow]")
            if not Confirm.ask("Continuer quand même?"):
                return False
        
        salt = os.urandom(32)
        self.crypto = CryptoEngine(master_password, salt)
        
        # Sauvegarder le vault
        self._save_vault(salt)
        console.print("[green]✅ Vault créé avec succès![/green]")
        return True
    
    def unlock(self, master_password: str) -> bool:
        """Déverrouiller un vault existant"""
        if not self.vault_path.exists():
            console.print("[red]❌ Vault introuvable![/red]")
            return False
        
        try:
            with open(self.vault_path, 'rb') as f:
                salt = f.read(32)
                encrypted_data = f.read()
            
            self.crypto = CryptoEngine(master_password, salt)
            decrypted_json = self.crypto.decrypt(encrypted_data)
            self.vault_data = json.loads(decrypted_json)
            
            console.print("[green]🔓 Vault déverrouillé![/green]")
            return True
            
        except Exception as e:
            console.print(f"[red]❌ Échec du déverrouillage: {str(e)}[/red]")
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
        console.print(f"[green]✅ '{name}' ajouté au vault[/green]")
    
    def get_entry(self, name: str) -> Optional[Dict]:
        """Récupérer une entrée par nom"""
        for entry in self.vault_data['entries']:
            if entry['name'].lower() == name.lower():
                entry['accessed'] = datetime.now().isoformat()
                return entry
        return None
    
    def list_entries(self, category: str = None):
        """Lister toutes les entrées"""
        table = Table(title="🔐 SecureVault Entries")
        table.add_column("Nom", style="cyan")
        table.add_column("Username", style="magenta")
        table.add_column("Catégorie", style="green")
        table.add_column("Modifié", style="yellow")
        
        entries = self.vault_data['entries']
        if category:
            entries = [e for e in entries if e['category'] == category]
        
        for entry in entries:
            table.add_row(
                entry['name'],
                entry['username'],
                entry['category'],
                entry['modified'][:10]
            )
        
        console.print(table)
    
    def delete_entry(self, name: str) -> bool:
        """Supprimer une entrée"""
        for i, entry in enumerate(self.vault_data['entries']):
            if entry['name'].lower() == name.lower():
                del self.vault_data['entries'][i]
                self._save_vault(self.crypto.salt)
                console.print(f"[red]🗑️  '{name}' supprimé[/red]")
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

def main():
    parser = argparse.ArgumentParser(description='SecureVault - Password Manager')
    parser.add_argument('--vault', default='vault.db', help='Vault file path')
    parser.add_argument('--init', action='store_true', help='Initialize new vault')
    
    args = parser.parse_args()
    
    vault = SecureVault(args.vault)
    
    if args.init:
        console.print(Panel.fit("🔐 Initialisation du SecureVault", style="bold blue"))
        master_pw = getpass.getpass("Master Password: ")
        confirm_pw = getpass.getpass("Confirm Password: ")
        
        if master_pw != confirm_pw:
            console.print("[red]❌ Les mots de passe ne correspondent pas![/red]")
            return
        
        vault.initialize(master_pw)
        return
    
    # Déverrouiller le vault
    master_pw = getpass.getpass("🔑 Master Password: ")
    if not vault.unlock(master_pw):
        return
    
    # Menu interactif
    while True:
        console.print("\n" + "="*50)
        console.print("[bold cyan]1.[/] Ajouter une entrée")
        console.print("[bold cyan]2.[/] Lister les entrées")
        console.print("[bold cyan]3.[/] Récupérer un mot de passe")
        console.print("[bold cyan]4.[/] Générer un mot de passe")
        console.print("[bold cyan]5.[/] Supprimer une entrée")
        console.print("[bold cyan]6.[/] Quitter")
        console.print("="*50)
        
        choice = Prompt.ask("Choix", choices=["1", "2", "3", "4", "5", "6"])
        
        if choice == "1":
            name = Prompt.ask("Nom")
            username = Prompt.ask("Username")
            
            if Confirm.ask("Générer un mot de passe?"):
                length = int(Prompt.ask("Longueur", default="16"))
                password = PasswordGenerator.generate(length)
                console.print(f"[green]Mot de passe généré: {password}[/green]")
            else:
                password = getpass.getpass("Password: ")
            
            category = Prompt.ask("Catégorie", default="General")
            notes = Prompt.ask("Notes (optionnel)", default="")
            
            vault.add_entry(name, username, password, category, notes)
        
        elif choice == "2":
            vault.list_entries()
        
        elif choice == "3":
            name = Prompt.ask("Nom de l'entrée")
            entry = vault.get_entry(name)
            
            if entry:
                console.print(f"[cyan]Username:[/] {entry['username']}")
                console.print(f"[cyan]Password:[/] {entry['password']}")
                
                if CLIPBOARD_AVAILABLE:
                    if Confirm.ask("Copier le mot de passe?"):
                        pyperclip.copy(entry['password'])
                        console.print("[green]✅ Copié dans le presse-papier![/green]")
            else:
                console.print("[red]❌ Entrée introuvable[/red]")
        
        elif choice == "4":
            length = int(Prompt.ask("Longueur", default="16"))
            password = PasswordGenerator.generate(length)
            strength = PasswordGenerator.check_strength(password)
            
            console.print(f"[green]Password: {password}[/green]")
            console.print(f"Score: {strength['score']}/100")
            console.print(f"Entropy: {strength['entropy']:.1f} bits")
        
        elif choice == "5":
            name = Prompt.ask("Nom de l'entrée")
            vault.delete_entry(name)
        
        elif choice == "6":
            console.print("[yellow]👋 Au revoir![/yellow]")
            break

if __name__ == "__main__":
    main()