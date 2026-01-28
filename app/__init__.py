from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config

db = SQLAlchemy()


def creer_application():
    # Instanciation du conteneur principal de l'application Flask
    app = Flask(__name__)

    app.config.from_object(Config)
    # Initialise la DB avec l'instance de l'app
    db.init_app(app)
    from app.routes import bp

    # injection des routes de 'bp' dans l'instance 'app'
    app.register_blueprint(bp)

    return app
