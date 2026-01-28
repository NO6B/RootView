import os
from dotenv import load_dotenv


# Récupère le chemin absolu du dossier courant pour localiser le fichier de BDD
basedir = os.path.abspath(os.path.dirname(__file__))
# Charge les variables du fichier .env s'il existe
load_dotenv(os.path.join(basedir, ".env"))


class Config:
    # Recuperation de la clé du fichier .env
    SECRET_KEY = os.environ.get("SECRET_KEY")

    if not SECRET_KEY:
        raise ValueError("ERREUR : La variable 'SECRET_KEY' est manquante.")

    # Définit l'emplacement où sera stocké le fichier de la base de données.
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(basedir, "rootview.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    DEBUG = False
