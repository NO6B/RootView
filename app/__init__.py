from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_apscheduler import APScheduler

db = SQLAlchemy()
schedule = APScheduler()


def creer_application():
    # Instanciation du conteneur principal de l'application Flask
    app = Flask(__name__)

    app.config.from_object(Config)
    # Initialise la DB avec l'instance de l'app
    db.init_app(app)
    from app.routes import bp

    # schedule config
    # Charge la configuration (liste JOBS)
    schedule.init_app(app)
    # Lancement d'un thread parallèle en arrière-plan 
    # pour surveiller l'heure sans bloquer le site web.
    schedule.start()

    # injection des routes de 'bp' dans l'instance 'app'
    app.register_blueprint(bp)

    return app
