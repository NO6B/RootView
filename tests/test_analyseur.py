import pytest
from unittest.mock import patch
from datetime import datetime
from app import creer_application, db
from app.models import Serveur, Alerte, Utilisateur
from app.services.parser import parser_ligne_log
from app.services.analyzer import AnalyseurSecurite


# ==============================================================
# TESTS UNITAIRES - PARSER
# ==============================================================

def test_parser_extrait_ip_et_message():
    """Vérifie l'extraction correcte de l'IP et du message sur une ligne SSH valide."""
    ligne_ssh = "Feb 16 22:30:15 ip-172-31-10-10 sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2"
    resultat = parser_ligne_log(ligne_ssh)

    assert resultat is not None
    assert resultat['adresse_ip'] == "192.168.1.50"
    assert "Failed password" in resultat['message']


def test_parser_ligne_invalide():
    """Vérifie que le parser retourne None sur une ligne sans format reconnu."""
    ligne_corrompue = "Ceci est une ligne de log sans adresse IP valide"
    resultat = parser_ligne_log(ligne_corrompue)

    assert resultat is None


def test_parser_extrait_ip_web():
    """Vérifie l'extraction correcte sur une ligne de log web (Common Log Format)."""
    ligne_web = '192.168.1.10 - - [16/Feb/2026:22:30:15 +0000] "GET /login HTTP/1.1" 200 512'
    resultat = parser_ligne_log(ligne_web)

    assert resultat is not None
    assert resultat['adresse_ip'] == "192.168.1.10"
    assert resultat['status_code'] == "200"


# ==============================================================
# TESTS UNITAIRES - MOTEUR DE DETECTION (REGEX)
# ==============================================================

def test_detection_ssh_brute_force():
    """Vérifie la détection d'un échec d'authentification SSH."""
    message = "Failed password for invalid user admin from 10.0.0.5 port 22 ssh2"
    assert AnalyseurSecurite.echec_de_mot_de_passe(message) is True


def test_detection_ssh_utilisateur_invalide():
    """Vérifie la détection d'une tentative avec un utilisateur inexistant."""
    message = "Invalid user fantome from 10.0.0.5 port 22"
    assert AnalyseurSecurite.utilisateur_inconnu(message) is True


def test_detection_sql_injection():
    """Vérifie la détection d'un payload SQLi classique OR 1=1."""
    message = "GET /login?id=1'%20OR%201=1 HTTP/1.1"
    assert AnalyseurSecurite.injection_sql(message) is True


def test_detection_sql_injection_union():
    """Vérifie la détection d'un payload SQLi de type UNION SELECT."""
    message = "GET /search?q=1%20UNION%20SELECT%20*%20FROM%20users HTTP/1.1"
    assert AnalyseurSecurite.injection_sql(message) is True


def test_detection_path_traversal():
    """Vérifie la détection d'une tentative d'accès à /etc/passwd."""
    message = "GET /../../etc/passwd HTTP/1.1"
    assert AnalyseurSecurite.remontee_de_dossier(message) is True


def test_detection_brute_force_endpoint():
    """Vérifie la détection d'une tentative de brute force sur /login."""
    assert AnalyseurSecurite.brute_force_endpoint("POST", "/login", "/login", "401") is True


def test_faux_positif_requete_legitime():
    """Vérifie qu'une requête normale ne déclenche aucune alerte."""
    message = "GET /index.html HTTP/1.1"
    assert AnalyseurSecurite.injection_sql(message) is False
    assert AnalyseurSecurite.remontee_de_dossier(message) is False


def test_faux_positif_post_legitime():
    """Vérifie qu'un POST avec code 200 ne déclenche pas d'alerte brute force."""
    assert AnalyseurSecurite.brute_force_endpoint("POST", "/login", "/login", "200") is False


# ==============================================================
# TEST D'INTEGRATION - FLUX COMPLET BDD (SQLite mémoire)
# ==============================================================

@pytest.fixture
def app_test():
    """
    Crée une instance Flask de test avec SQLite en mémoire.
    Le scheduler est désactivé via TESTING=True pour éviter
    les conflits entre les instances lors des tests.
    """
    # Interception stricte du scheduler pour éviter le SchedulerAlreadyRunningError
    with patch('app.schedule.init_app'), patch('app.schedule.start'):
        app = creer_application()

    app.config.update({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False
    })

    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_flux_complet_utilisateur_serveur_alerte(app_test):
    """
    Test d'intégration : vérifie le flux complet
    Utilisateur -> Serveur -> Alerte -> lecture BDD.
    """
    # Création utilisateur
    nouvel_utilisateur = Utilisateur(
        nom_utilisateur="admin_test",
        mot_de_passe_hash="hash_bidon_123"
    )
    db.session.add(nouvel_utilisateur)
    db.session.commit()

    # Création serveur lié à l'utilisateur
    nouveau_serveur = Serveur(
        id_utilisateur=nouvel_utilisateur.id,
        nom="Serveur Test QA",
        adresse_ip="10.0.0.99",
        utilisateur_ssh="root",
        clef_ssh="clef_fictive",
        endpoint_web="/login"
    )
    db.session.add(nouveau_serveur)
    db.session.commit()

    # Création alerte liée au serveur
    nouvelle_alerte = Alerte(
        id_serveur=nouveau_serveur.id,
        type="SSH Brute Force",
        ip_source="192.168.1.100",
        ip_liste=True,
        score_fiabilite=100,
        log_brut="Failed password for root from 192.168.1.100",
        date_heure=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    db.session.add(nouvelle_alerte)
    db.session.commit()

    # Vérification lecture BDD
    alerte_recuperee = Alerte.query.filter_by(ip_source="192.168.1.100").first()

    assert alerte_recuperee is not None
    assert alerte_recuperee.type == "SSH Brute Force"
    assert alerte_recuperee.id_serveur == nouveau_serveur.id
    assert alerte_recuperee.ip_liste is True
    assert alerte_recuperee.score_fiabilite == 100