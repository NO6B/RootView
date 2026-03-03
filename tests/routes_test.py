import pytest
from unittest.mock import patch
from werkzeug.security import generate_password_hash
from app import creer_application, db
from app.models import Utilisateur, Serveur, Alerte


# ==============================================================
# FIXTURE
# ==============================================================

@pytest.fixture
def app_test():
    """Instance Flask de test avec SQLite mémoire et scheduler désactivé."""
    with patch('app.schedule.init_app'), patch('app.schedule.start'):
        app = creer_application()

    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False
    })

    with app.app_context():
        db.create_all()

        # Utilisateur de test pré-inséré
        utilisateur = Utilisateur(
            nom_utilisateur="test_user",
            mot_de_passe_hash=generate_password_hash("motdepasse123", method="pbkdf2:sha256")
        )
        db.session.add(utilisateur)
        db.session.commit()

        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app_test):
    """Client HTTP de test Flask."""
    return app_test.test_client()


@pytest.fixture
def client_connecte(client):
    """Client HTTP avec session authentifiée."""
    client.post("/login", data={
        "identifiant": "test_user",
        "motdepass": "motdepasse123"
    })
    return client


# ==============================================================
# TESTS ROUTES PUBLIQUES
# ==============================================================

def test_page_login_accessible(client):
    """Vérifie que la page de login retourne 200."""
    response = client.get("/login")
    assert response.status_code == 200


def test_page_register_accessible(client):
    """Vérifie que la page d'inscription retourne 200."""
    response = client.get("/register")
    assert response.status_code == 200


def test_connexion_valide(client):
    """Vérifie qu'un login correct redirige vers le dashboard."""
    response = client.post("/login", data={
        "identifiant": "test_user",
        "motdepass": "motdepasse123"
    })
    assert response.status_code == 302
    assert "/dashboard" in response.headers["Location"]


def test_connexion_invalide(client):
    """Vérifie qu'un mauvais mot de passe ne connecte pas."""
    response = client.post("/login", data={
        "identifiant": "test_user",
        "motdepass": "mauvais_mdp"
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Identifiant ou mot de passe incorrect" in response.data


def test_inscription_nouvel_utilisateur(client):
    """Vérifie qu'un nouvel utilisateur peut s'inscrire."""
    response = client.post("/register", data={
        "identifiant": "nouvel_user",
        "motdepass": "Secure123!"
    })
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_inscription_doublon(client):
    """Vérifie qu'on ne peut pas créer deux comptes avec le même identifiant."""
    response = client.post("/register", data={
        "identifiant": "test_user",
        "motdepass": "Secure123!"
    }, follow_redirects=True)
    assert b"d\xc3\xa9j\xc3\xa0 utilis\xc3\xa9" in response.data


# ==============================================================
# TESTS ROUTES PROTEGEES (login_required)
# ==============================================================

def test_dashboard_sans_connexion(client):
    """Vérifie qu'un utilisateur non connecté est redirigé vers le login."""
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "login" in response.headers["Location"]


def test_dashboard_connecte(client_connecte):
    """Vérifie que le dashboard est accessible une fois connecté."""
    response = client_connecte.get("/dashboard")
    assert response.status_code == 200


def test_servers_sans_connexion(client):
    """Vérifie que /servers est protégé."""
    response = client.get("/servers")
    assert response.status_code == 302
    assert "login" in response.headers["Location"]


def test_ajout_serveur(client_connecte, app_test):
    """Vérifie qu'un serveur peut être ajouté via le formulaire."""
    response = client_connecte.post("/servers", data={
        "nom": "Serveur Test",
        "ip": "192.168.1.1",
        "user_ssh": "root",
        "key_ssh": "clef_fictive",
        "endpoint": "/login"
    })
    assert response.status_code == 302

    with app_test.app_context():
        serveur = Serveur.query.filter_by(nom="Serveur Test").first()
        assert serveur is not None
        assert serveur.adresse_ip == "192.168.1.1"


def test_suppression_serveur(client_connecte, app_test):
    """Vérifie qu'un utilisateur peut supprimer son propre serveur."""
    with app_test.app_context():
        user = Utilisateur.query.filter_by(nom_utilisateur="test_user").first()
        serveur = Serveur(
            nom="A Supprimer",
            adresse_ip="10.0.0.1",
            utilisateur_ssh="root",
            clef_ssh="clef",
            endpoint_web="/login",
            id_utilisateur=user.id
        )
        db.session.add(serveur)
        db.session.commit()
        serveur_id = serveur.id

    response = client_connecte.post(f"/servers/delete/{serveur_id}")
    assert response.status_code == 302

    with app_test.app_context():
        assert Serveur.query.get(serveur_id) is None


def test_deconnexion(client_connecte):
    """Vérifie que la déconnexion redirige vers le login."""
    response = client_connecte.get("/logout")
    assert response.status_code == 302
    assert "login" in response.headers["Location"]


def test_recommendations_connecte(client_connecte):
    """Vérifie que la page recommendations est accessible."""
    response = client_connecte.get("/recommendations")
    assert response.status_code == 200


def test_details_ip_connecte(client_connecte):
    """Vérifie que la page détails d'une IP est accessible."""
    response = client_connecte.get("/details/192.168.1.1")
    assert response.status_code == 200
