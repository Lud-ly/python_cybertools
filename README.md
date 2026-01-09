# LMCyberSec Tools 🛡️

Suite complète d'outils de cybersécurité professionnels développée avec Flask et architecture Blueprint. Application web moderne offrant cryptographie, analyse de menaces, reconnaissance OSINT, scanning réseau et gestion sécurisée de mots de passe.

## 🚀 Fonctionnalités

### 🔐 Cryptographie & Mots de passe
- **Générateur de mots de passe** : Génération sécurisée (8-128 caractères)
- **Analyse de force** : Score et recommandations sur 100 points
- **Hachage** : SHA-256, SHA-512, bcrypt, MD5
- **Validation email** : Vérification syntaxique et domaine
- **SecureVault** : Gestionnaire de mots de passe chiffré AES-256-GCM avec PBKDF2

### 🛡️ Analyse & Détection
- **VirusTotal** : Scan d'URLs et fichiers
- **Scanner Nmap** : Reconnaissance réseau (rapide/personnalisé)
- **Pentest Nmap Auto** : Modes quick/full/vuln/os/all avec rapports JSON
- **Port Scanner Pro** : Scan multi-threadé avec bannière grabbing
- **Analyseur de logs** : Détection brute force, chemins suspects, user-agents malveillants
- **Enrichissement IOC** : Threat intelligence (VirusTotal + Shodan)

### 🔍 Reconnaissance & OSINT
- **Git Statistics** : Analyse de dépôts GitHub
- **Énumération Web** : Découverte de technologies et headers
- **OSINT** : Collecte d'informations publiques
- **Brute Force HTTP** : Test de wordlists sur formulaires de login

## 📋 Prérequis

- Python 3.11+
- Nmap installé (`brew install nmap` sur macOS, `apt install nmap` sur Linux)
- Clés API (optionnelles) :
  - [VirusTotal](https://www.virustotal.com/gui/join-us) (gratuit, 4 requêtes/min)
  - [Shodan](https://account.shodan.io/register) (gratuit, 100 crédits)

## ⚙️ Installation locale

### 1. Cloner le repository
```bash
git clone https://github.com/Lud-ly/cybersec-tools.git
cd cybersec-tools

2. Créer un environnement virtuel

bash
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows

3. Installer les dépendances

bash
pip install -r requirements.txt

4. Configuration des variables d'environnement

Créez un fichier .env à la racine :

text
# Obligatoire
FLASK_ENV=development

# Optionnel - APIs externes
VIRUSTOTAL_API_KEY=votre_cle_virustotal
SHODAN_API_KEY=votre_cle_shodan

# Optionnel - Configuration serveur
FLASK_HOST=0.0.0.0
FLASK_PORT=5050

5. Lancer l'application

bash
python app.py

Application accessible sur http://localhost:5050
📡 API Endpoints
Cryptographie
POST /api/hash

# Hache un mot de passe avec l'algorithme spécifié.

Request :

json
{
  "password": "MonMotDePasse123!",
  "algo": "sha256"
}

Response :

json
{
  "hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
  "algorithm": "sha256"
}

POST /api/generate-password

json
{
  "length": 16
}

POST /api/check-strength

json
{
  "password": "TestPassword123!"
}

Analyse & Détection
POST /api/virus-total

json
{
  "url": "https://example.com"
}

POST /api/log-analyzer

json
{
  "log_content": "192.168.1.1 - - [09/Jan/2026:12:00:00] \"GET /admin HTTP/1.1\" 404 512"
}

POST /api/port-scanner

json
{
  "target": "example.com",
  "ports": "1-1000",
  "threads": 100,
  "timeout": 1
}

POST /api/pentest-nmap

json
{
  "target": "example.com",
  "scan_mode": "full",
  "ports": "1-1000",
  "generate_report": true
}

POST /api/ioc-enrich

json
{
  "ioc": "8.8.8.8",
  "ioc_type": "ip",
  "vt_api_key": "optionnel",
 } 