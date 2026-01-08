# CyberSec Tools

Suite d'outils de cybersécurité professionnels développée avec Flask et architecture Blueprint. Application web moderne permettant le hachage de mots de passe, l'analyse d'URLs via VirusTotal et la validation d'adresses email.

## Fonctionnalités

### Outils disponibles

- **Hachage de mot de passe** : Support de SHA-256, SHA-512, bcrypt et MD5
- **Analyse VirusTotal** : Scan d'URLs pour détecter les menaces potentielles
- **Validation d'email** : Vérification de la syntaxe et du format des adresses email

### Architecture technique

- Backend Flask avec API Blueprint pour une architecture modulaire
- Interface web moderne et responsive (HTML5/CSS3/JavaScript)
- Intégration API VirusTotal v3
- Gestion sécurisée des variables d'environnement
- Déploiement production-ready sur Render

## Prérequis

- Python 3.11 ou supérieur
- Compte VirusTotal pour obtenir une clé API gratuite
- Git pour le versionnement

## Installation locale

### 1. Cloner le repository
```bash
git clone https://github.com/votre-username/cybersec-tools.git
cd cybersec-tools

```

### 2. Créer un environnement virtuel
```python
python3 -m venv venv
source venv/bin/activate # macOS/Linux
venv\Scripts\activate # Windows

```

### 3. Installer les dépendances
```bash
pip install -r requirements.txt
```

### 4. Configuration des variables d'environnement

Créez un fichier `.env` à la racine du projet :
```bash
VIRUSTOTAL_API_KEY=ta_cle_api_virustotal
```

Pour obtenir une clé API VirusTotal gratuite :
1. Créez un compte sur https://www.virustotal.com
2. Accédez à votre profil > API Key
3. Copiez la clé dans le fichier `.env`

### 5. Lancer l'application
```bash
python3 app.py
```

L'application sera accessible sur `http://localhost:5050`


## API Endpoints

### POST /api/hash

Hash un mot de passe avec l'algorithme spécifié.

**Request body :**
```json
{
"password": "mon_mot_de_passe",
"algorithm": "sha256"
}
```

**Algorithmes supportés :** `sha256`, `sha512`, `bcrypt`, `md5`

**Response :**
```json
{
"hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
}
```

### POST /api/virustotal

Analyse une URL via l'API VirusTotal.

**Request body :**
```json
{
"url": "https://example.com"
}
```

**Response :**
```json
{
"url": "https://example.com",
"positives": 0,
"total": 89,
"last_analysis_date": "2025-12-19 18:00:00",
"vt_id": "base64_encoded_url_id"
}
```

### POST /api/email

Valide une adresse email.

**Request body :**
```json
{
"email": "exemple@domaine.com"
}
```

**Response :**
```json
{
"valid": true,
"email": "exemple@domaine.com"
}
```

## Déploiement sur Render

### 1. Préparer le repository

Assurez-vous que ces fichiers sont présents :

**Procfile**
```json
web: gunicorn app:app
```

**requirements.txt**
```json
Flask==3.0.0
gunicorn==21.2.0
requests==2.31.0
bcrypt==4.1.2
python-dotenv==1.0.0
```

### 2. Push sur GitHub
```bash
git add .
git commit -m "Prepare for Render deployment"
git push origin main
```

### 3. Créer un service sur Render

1. Allez sur https://render.com et connectez-vous
2. Cliquez sur **New +** > **Web Service**
3. Connectez votre repository GitHub
4. Configuration :
   - **Name** : `cybersec-tools`
   - **Environment** : `Python 3`
   - **Build Command** : `pip install -r requirements.txt`
   - **Start Command** : `gunicorn app:app`
   - **Plan** : Free

### 4. Configurer les variables d'environnement

Dans le dashboard Render :
1. Allez dans **Environment**
2. Ajoutez : `VIRUSTOTAL_API_KEY` = `votre_cle_api`
3. Sauvegardez

Le déploiement démarre automatiquement. Votre app sera accessible sur :
```bash
https://cybersec-tools.onrender.com
```

### 5. Domaine personnalisé (optionnel)

Dans Render :
1. **Settings** > **Custom Domains**
2. Ajoutez votre domaine : `security.devlm.fr`
3. Configurez le DNS avec un CNAME vers `cybersec-tools.onrender.com`

## Sécurité

### Bonnes pratiques implémentées

- Variables d'environnement pour les secrets (clés API)
- Fichier `.env` exclu du versionnement Git
- Validation des entrées utilisateur côté serveur
- Timeouts sur les requêtes externes
- Headers de sécurité HTTP
- Pas de logs sensibles en production

### Recommandations

- Ne jamais commit la clé API VirusTotal
- Utiliser HTTPS en production (fourni par Render)
- Limiter le rate limiting sur les endpoints publics
- Maintenir les dépendances à jour

## Développement

### Installer en mode développement
```json
pip install -e .
```

### Lancer les tests
```json
python -m pytest tests/
```

### Linter le code

flake8 *.py
black *.py

text

## Technologies utilisées

- **Backend** : Flask 3.0, Python 3.13
- **API** : Flask Blueprint architecture
- **Sécurité** : bcrypt, hashlib
- **Intégrations** : VirusTotal API v3
- **Déploiement** : Gunicorn, Render
- **Frontend** : HTML5, CSS3 (variables CSS), Vanilla JavaScript

## Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## Auteur

**Ludovic Mouly**  
Portfolio : https://lmcv.vercel.app  
GitHub : https://github.com/Lud-ly

## Support

Pour signaler un bug ou demander une fonctionnalité, ouvrez une issue sur GitHub.

## Changelog

### Version 1.0.0 (2025-12-19)

- Version initiale
- Hachage de mots de passe (SHA-256, SHA-512, bcrypt, MD5)
- Intégration VirusTotal pour analyse d'URLs
- Validation d'adresses email
- Interface web moderne et responsive
- Déploiement sur Render

---
# Script de Pentest avec VRAI Nmap

## Scan rapide (top 100 ports)
python pentest_auto.py --target example.com --quick

## Scan complet avec détection de services
python pentest_auto.py --target example.com --full

## Scan de vulnérabilités
python pentest_auto.py --target example.com --vuln

## Scan complet (quick + full + vuln)
python pentest_auto.py --target example.com --all

## Scan personnalisé
python pentest_auto.py --target 192.168.1.1 --full --ports 1-65535

## Détection OS (nécessite sudo)
sudo python pentest_auto.py --target example.com --os


Développé avec Flask par Ludovic Mouly - 2025
