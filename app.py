from flask import Flask, render_template
from flask_cors import CORS
import os

# Import de la configuration
from config import get_config

# Import de la fonction d'enregistrement des routes
from api import register_routes

# Créer l'application Flask
app = Flask(__name__)

# Charger la configuration selon l'environnement
env = os.getenv('FLASK_ENV', 'development')
config = get_config(env)
app.config.from_object(config)

# Initialiser la configuration (créer les dossiers, etc.)
config.init_app(app)

# Activer CORS
CORS(app, origins=app.config['CORS_ORIGINS'])

# Enregistrer toutes les routes API
register_routes(app)


@app.route("/")
def index():
    """Page d'accueil"""
    return render_template("index.html")


@app.route("/docs")
def api_docs():
    """Documentation API simple"""
    routes = []
    for rule in app.url_map.iter_rules():
        if rule.endpoint != 'static':
            routes.append({
                'endpoint': rule.endpoint,
                'methods': list(rule.methods - {'HEAD', 'OPTIONS'}),
                'path': str(rule)
            })
    
    return {
        'api_version': '1.0',
        'environment': env,
        'total_routes': len(routes),
        'routes': sorted(routes, key=lambda x: x['path'])
    }


@app.errorhandler(404)
def not_found(error):
    """Gestion des erreurs 404"""
    return {"error": "Route non trouvée"}, 404


@app.errorhandler(500)
def internal_error(error):
    """Gestion des erreurs 500"""
    return {"error": "Erreur interne du serveur"}, 500


@app.errorhandler(413)
def request_entity_too_large(error):
    """Gestion des fichiers trop volumineux"""
    return {"error": "Fichier trop volumineux (max 16MB)"}, 413


if __name__ == "__main__":
    print("=" * 60)
    print("🚀 LMCyberSec Tools")
    print("=" * 60)
    print(f"📍 Environnement : {env.upper()}")
    print(f"🔗 URL          : http://{app.config['HOST']}:{app.config['PORT']}")
    print(f"🐛 Debug        : {app.config['DEBUG']}")
    print(f"📚 API Docs     : http://localhost:{app.config['PORT']}/docs")
    print(f"🔑 VirusTotal   : {'✅' if app.config['VIRUSTOTAL_API_KEY'] else '❌'}")
    print(f"🔍 Shodan       : {'✅' if app.config['SHODAN_API_KEY'] else '❌'}")
    print("=" * 60)
    
    app.run(
        debug=app.config['DEBUG'],
        host=app.config['HOST'],
        port=app.config['PORT']
    )