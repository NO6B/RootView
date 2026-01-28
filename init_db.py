from app.models import Utilisateur, Alerte, Serveur
from app import db, creer_application

# On stocke l'instance de l'application (fabriquée par fonction) dans la variable 'app'
app = creer_application()

# On active le contexte pour que SQLAlchemy puisse lire la config (notamment SQLALCHEMY_DATABASE_URI)
with app.app_context():
    try:
        # Génération du schéma : SQLAlchemy scanne les modèles importés et crée les tables correspondantes dans le fichier .db.
        db.create_all()
        print("base de donnée cree")
    except Exception as ex:
        print(f"echec de la creation de la db: {ex}")
