import os
from dotenv import load_dotenv


# Récupération du chemin absolu du dossier courant pour localiser le fichier de BDD
basedir = os.path.abspath(os.path.dirname(__file__))
# Chargement des variables du fichier .env
load_dotenv(os.path.join(basedir, ".env"))


class Config:
    # Recuperation de la clé du fichier .env
    SECRET_KEY = os.environ.get("SECRET_KEY")

    if not SECRET_KEY:
        raise ValueError("ERREUR : La variable 'SECRET_KEY' est manquante.")

    # Définitions de l'emplacement où sera stocké le fichier de la base de données.
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(basedir, "rootview.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = False
    # activation la route '/scheduler/jobs' pour visualiser les tâches actives (JSON)
    SCHEDULER_API_ENABLED = True

    # CONFIGURATION DES TÂCHES AUTOMATISÉES A EXECUTER
    JOBS = [
        {
            'id': 'scan_routine',
            'func': 'app.services.task:scan_global',
            'trigger': 'interval',
            'minutes': 5
        }
    ]
