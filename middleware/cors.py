#!/usr/bin/env python3
"""
CORS Middleware - Configuration Cross-Origin Resource Sharing
"""

from flask_cors import CORS


def setup_cors(app):
    """Configure CORS pour l'application Flask"""
    
    allowed_origins = app.config.get('CORS_ORIGINS', ['http://localhost:3000', 'http://localhost:5050'])
    
    cors_config = {
        'origins': allowed_origins,
        'methods': ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
        'allow_headers': [
            'Content-Type',
            'Authorization',
            'X-API-Key',
            'X-Requested-With'
        ],
        'expose_headers': [
            'Content-Range',
            'X-Content-Range'
        ],
        'supports_credentials': True,
        'max_age': 3600
    }
    
    CORS(app, resources={r'/api/*': cors_config})
    
    return app
