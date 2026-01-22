# Fichier: app/__init__.py
from flask import Flask
from app.routes import bp

def creer_application():
    # Instanciation du conteneur principal de l'application Flask
    app = Flask(__name__)
    
    # injection des routes de 'bp' dans l'instance 'app'
    app.register_blueprint(bp)

    return app
