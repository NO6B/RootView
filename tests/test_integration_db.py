import pytest
from sqlalchemy.exc import IntegrityError
from app import creer_application, db
from app.models import Utilisateur, Serveur, Alerte

@pytest.fixture(scope='module')
def app_test():
    """Configure l'application pour pointer sur PostgreSQL."""
    app = creer_application()
    app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://rootview_user:rootview_pass@localhost/rootview"
    app.config["TESTING"] = True

    with app.app_context():
        db.create_all()
        yield app
        
        # Nettoyage des données de test
        alerte = Alerte.query.filter_by(type="Test_Alert").first()
        if alerte:
            db.session.delete(alerte)
            
        serveur = Serveur.query.filter_by(nom="Serveur_Test").first()
        if serveur:
            db.session.delete(serveur)
            
        user = Utilisateur.query.filter_by(nom_utilisateur="test_pg_user").first()
        if user:
            db.session.delete(user)
            
        db.session.commit()

def test_crud_et_unicite_utilisateur(app_test):
    """Vérifie l'insertion et la restriction de doublons (PostgreSQL strict)."""
    with app_test.app_context():
        # Test de création
        nouvel_utilisateur = Utilisateur(
            nom_utilisateur="test_pg_user",
            mot_de_passe_hash="hash_123"
        )
        db.session.add(nouvel_utilisateur)
        db.session.commit()

        # Test de lecture
        utilisateur_verif = Utilisateur.query.filter_by(nom_utilisateur="test_pg_user").first()
        assert utilisateur_verif is not None
        assert utilisateur_verif.mot_de_passe_hash == "hash_123"

        # Test de la contrainte UNIQUE (PostgreSQL doit rejeter cette insertion)
        utilisateur_doublon = Utilisateur(
            nom_utilisateur="test_pg_user",
            mot_de_passe_hash="hash_456"
        )
        db.session.add(utilisateur_doublon)
        
        with pytest.raises(IntegrityError):
            db.session.commit()
            
        # Annulation de la transaction échouée pour libérer la session
        db.session.rollback()

def test_relations_cles_etrangeres(app_test):
    """Vérifie l'insertion en cascade et le respect des Foreign Keys."""
    with app_test.app_context():
        # Récupération de l'utilisateur créé dans le test précédent
        user = Utilisateur.query.filter_by(nom_utilisateur="test_pg_user").first()
        
        # Création d'un serveur lié
        nouveau_serveur = Serveur(
            id_utilisateur=user.id,
            nom="Serveur_Test",
            adresse_ip="127.0.0.1",
            utilisateur_ssh="root",
            endpoint_web="/admin"
        )
        db.session.add(nouveau_serveur)
        db.session.commit()

        # Création d'une alerte liée
        nouvelle_alerte = Alerte(
            id_serveur=nouveau_serveur.id,
            type="Test_Alert",
            date_heure="2026-03-02 12:00:00"
        )
        db.session.add(nouvelle_alerte)
        db.session.commit()

        # Vérification des relations
        assert len(user.serveurs) == 1
        assert user.serveurs[0].nom == "Serveur_Test"
        assert len(nouveau_serveur.alertes) == 1
        assert nouveau_serveur.alertes[0].type == "Test_Alert"
