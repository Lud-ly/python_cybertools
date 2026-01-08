#!/usr/bin/env python3
import hashlib
import argparse
import csv
from pathlib import Path

def hash_password(password: str, algo: str = "sha256") -> str:
    """Hash un password"""
    if algo == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif algo == "md5":
        return hashlib.md5(password.encode()).hexdigest()

def check_password_strength(pwd: str) -> dict:
    """Vérifie force password"""
    score = 0
    issues = []
    
    if len(pwd) >= 12: score += 2
    elif len(pwd) >= 8: score += 1
    else: issues.append("trop court")
    
    if any(c.isupper() for c in pwd): score += 1
    else: issues.append("pas majuscule")
    
    if any(c.isdigit() for c in pwd): score += 1
    else: issues.append("pas chiffre")
    
    if any(c in "!@#$%^&*" for c in pwd): score += 1
    else: issues.append("pas symbole")
    
    return {"score": score, "strength": "forte" if score >= 4 else "faible", "issues": issues}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hash", help="Vérifier hash")
    parser.add_argument("--generate", help="Générer hash")
    parser.add_argument("--strength", action="store_true")
    args = parser.parse_args()
    
    if args.hash:
        print(f"SHA256: {hash_password(args.hash)}")
        print(f"MD5: {hash_password(args.hash, 'md5')}")
    
    elif args.generate:
        print(hash_password(args.generate))
    
    elif args.strength:
        while True:
            pwd = input("Password (quit pour arrêter): ")
            if pwd == "quit": break
            result = check_password_strength(pwd)
            print(f"Score: {result['score']}/5 - {result['strength']}")
            if result['issues']:
                print("Problèmes:", ", ".join(result['issues']))

if __name__ == "__main__":
    main()
