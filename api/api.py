"""
API Blueprint Principal
Regroupe toutes les routes des différents modules
"""
from flask import Blueprint

# Import des sous-routes
from api.security_routes import security_bp
from api.scanning_routes import scanning_bp
from api.analysis_routes import analysis_bp
from api.threat_intel_routes import threat_intel_bp 
from api.recon_routes import recon_bp
from api.vault_routes import vault_bp
from api.health import health_bp

# Création du blueprint principal
api_blueprint = Blueprint("api", __name__)

# Enregistrement des sous-blueprints
def register_routes(app):
    """Enregistre tous les blueprints dans l'application Flask"""
    app.register_blueprint(security_bp, url_prefix='/api')
    app.register_blueprint(scanning_bp, url_prefix='/api')
    app.register_blueprint(analysis_bp, url_prefix='/api')
    app.register_blueprint(threat_intel_bp, url_prefix='/api') 
    app.register_blueprint(recon_bp, url_prefix='/api')
    app.register_blueprint(vault_bp, url_prefix='/api')
    app.register_blueprint(health_bp, url_prefix='/api')