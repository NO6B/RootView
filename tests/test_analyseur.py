import pytest
from datetime import datetime
from app import creer_application, db
from app.models import Serveur, Alerte, Utilisateur
from app.services.parser import parser_ligne_log
from app.services.analyzer import AnalyseurSecurite


# TESTS DU PARSER

def test_parser_extrait_ip_et_message():
    ligne_ssh = "Feb 16 22:30:15 ip-172-31-10-10 sshd[1234]: Failed password for root from 192.168.1.50 port 22 ssh2"
    resultat = parser_ligne_log(ligne_ssh)
    
    assert resultat is not None
    assert resultat['adresse_ip'] == "192.168.1.50"
    assert "Failed password" in resultat['message']

def test_parser_ligne_invalide():
    ligne_corrompue = "Ceci est une ligne de log sans adresse IP valide"
    resultat = parser_ligne_log(ligne_corrompue)
    
    # Doit retourner None si aucune IP n'est détectée
    assert resultat is None

# TESTS DES REGEX

def test_detection_ssh_brute_force():
    message_ssh = "Failed password for invalid user admin from 10.0.0.5 port 22 ssh2"
    assert AnalyseurSecurite.echec_de_mot_de_passe(message_ssh) is True

def test_detection_ssh_utilisateur_invalide():
    message_ssh = "Invalid user fantome from 10.0.0.5 port 22"
    assert AnalyseurSecurite.utilisateur_inconnu(message_ssh) is True

def test_detection_sql_injection():
    # Simulation de l'attaque envoyée par ton script bash : "?id=1'%20OR%201=1"
    message_web = 'GET /login?id=1\'%20OR%201=1 HTTP/1.1'
    assert AnalyseurSecurite.injection_sql(message_web) is True

def test_detection_path_traversal():
    # Simulation de l'attaque envoyée par ton script bash : "../../etc/passwd"
    message_web = 'GET /../../etc/passwd HTTP/1.1'
    assert AnalyseurSecurite.remontee_de_dossier(message_web) is True

def test_faux_positif_requete_legitime():
    message_legitime = 'GET /index.html HTTP/1.1'
    assert AnalyseurSecurite.injection_sql(message_legitime) is False
    assert AnalyseurSecurite.remontee_de_dossier(message_legitime) is False

# TESTS D'INTÉGRATION

@pytest.fixture
def app_test():
    """Configuration d'une application Flask de test avec une base de données en mémoire."""
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

def test_sauvegarde_et_lecture_alerte(app_test):
    # Créer un utilisateur fictif
    nouvel_utilisateur = Utilisateur(
        nom_utilisateur="admin_test",
        mot_de_passe_hash="hash_bidon_123"
    )
    db.session.add(nouvel_utilisateur)
    db.session.commit()

    # Créer un serveur virtuel en base, lié à l'utilisateur
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

    # Sauvegarder une alerte générée liée à ce serveur
    nouvelle_alerte = Alerte(
        id_serveur=nouveau_serveur.id,
        type="Brute Force SSH",
        ip_source="192.168.1.100",
        ip_liste=True,
        score_fiabilite=100,
        log_brut="Failed password for root from 192.168.1.100",
        date_heure=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    db.session.add(nouvelle_alerte)
    db.session.commit()

    # Vérifier sa bonne lecture depuis SQLite
    alerte_recuperee = Alerte.query.filter_by(ip_source="192.168.1.100").first()
    
    assert alerte_recuperee is not None
    assert alerte_recuperee.type == "Brute Force SSH"
    assert alerte_recuperee.id_serveur == nouveau_serveur.id