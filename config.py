"""
Configuration centralisée pour LMCyberSec Tools
"""
import os
from datetime import timedelta
from dotenv import load_dotenv

# Charger les variables d'environnement depuis .env
load_dotenv()


class Config:
    """Configuration de base"""
    
    # ========== Application Flask ==========
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('FLASK_ENV', 'development') == 'development'
    TESTING = False
    
    # ========== Server ==========
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', 5050))
    
    # ========== JSON ==========
    JSON_SORT_KEYS = False
    JSON_AS_ASCII = False
    JSONIFY_PRETTYPRINT_REGULAR = True
    
    # ========== Upload & Files ==========
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload
    UPLOAD_FOLDER = 'data/uploads'
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'pcap', 'log'}
    
    # ========== Dossiers de données ==========
    DATA_DIR = 'data'
    VAULTS_DIR = os.path.join(DATA_DIR, 'vaults')
    REPORTS_DIR = os.path.join(DATA_DIR, 'reports')
    LOGS_DIR = os.path.join(DATA_DIR, 'logs')
    
    # ========== API Keys ==========
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
    
    # ========== Rate Limiting ==========
    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = "100 per hour"
    RATELIMIT_STORAGE_URL = "memory://"
    
    # Limites spécifiques par endpoint
    RATELIMIT_NMAP = "10 per hour"
    RATELIMIT_BRUTEFORCE = "5 per hour"
    RATELIMIT_VIRUSTOTAL = "4 per minute"  # Limite API gratuite VT
    
    # ========== Security ==========
    SESSION_COOKIE_SECURE = True  # HTTPS uniquement en production
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # CORS
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', '*').split(',')
    
    # ========== JWT Authentication ==========
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # ========== Scanning Configuration ==========
    NMAP_TIMEOUT = 300  # 5 minutes max par scan
    PORT_SCAN_TIMEOUT = 1.0  # 1 seconde par port
    PORT_SCAN_MAX_THREADS = 100
    
    # ========== Logging ==========
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.path.join(LOGS_DIR, 'app.log')
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
    LOG_BACKUP_COUNT = 5
    
    # ========== Database (si vous ajoutez SQLite plus tard) ==========
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'DATABASE_URL',
        f'sqlite:///{os.path.join(DATA_DIR, "cybersec.db")}'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # ========== Cache ==========
    CACHE_TYPE = "simple"
    CACHE_DEFAULT_TIMEOUT = 300  # 5 minutes
    
    # ========== Features Flags ==========
    FEATURE_BRUTEFORCE_ENABLED = os.getenv('FEATURE_BRUTEFORCE', 'true').lower() == 'true'
    FEATURE_PENTEST_ENABLED = os.getenv('FEATURE_PENTEST', 'true').lower() == 'true'
    FEATURE_VAULT_ENABLED = os.getenv('FEATURE_VAULT', 'true').lower() == 'true'
    
    @staticmethod
    def init_app(app):
        """Initialisation de l'application avec la configuration"""
        # Créer les dossiers nécessaires
        for directory in [
            Config.DATA_DIR,
            Config.VAULTS_DIR,
            Config.REPORTS_DIR,
            Config.LOGS_DIR,
            Config.UPLOAD_FOLDER
        ]:
            os.makedirs(directory, exist_ok=True)
        
        print(f"✅ Configuration chargée : {os.getenv('FLASK_ENV', 'development')}")


class DevelopmentConfig(Config):
    """Configuration de développement"""
    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False  # Pas de HTTPS requis en dev


class ProductionConfig(Config):
    """Configuration de production"""
    DEBUG = False
    TESTING = False
    
    # Sécurité renforcée
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    # Rate limiting plus strict
    RATELIMIT_DEFAULT = "50 per hour"
    RATELIMIT_NMAP = "5 per hour"
    RATELIMIT_BRUTEFORCE = "3 per hour"
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)
        
        # Log des erreurs en production
        import logging
        from logging.handlers import RotatingFileHandler
        
        if not os.path.exists(cls.LOGS_DIR):
            os.makedirs(cls.LOGS_DIR)
        
        file_handler = RotatingFileHandler(
            cls.LOG_FILE,
            maxBytes=cls.LOG_MAX_BYTES,
            backupCount=cls.LOG_BACKUP_COUNT
        )
        file_handler.setFormatter(logging.Formatter(cls.LOG_FORMAT))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)


class TestingConfig(Config):
    """Configuration de test"""
    TESTING = True
    DEBUG = True
    
    # Utiliser une base de données en mémoire pour les tests
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    
    # Désactiver les limites pour les tests
    RATELIMIT_ENABLED = False
    
    # Dossiers de test
    DATA_DIR = 'tests/data'
    VAULTS_DIR = os.path.join(DATA_DIR, 'vaults')
    REPORTS_DIR = os.path.join(DATA_DIR, 'reports')


# Dictionnaire de configuration
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}


def get_config(env=None):
    """Récupère la configuration selon l'environnement"""
    if env is None:
        env = os.getenv('FLASK_ENV', 'development')
    return config.get(env, config['default'])