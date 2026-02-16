from collections import defaultdict
from app import db
from app.models import Serveur, Alerte
from app.ssh_client import GestionnaireSSH
from app.parser import parser_ligne_log
from app.analyzer import AnalyseurSecurite
from app.client_abuseipdb import verification_ip


# Configuration
SEUIL_BRUTE_FORCE = 10
SEUIL_DOS = 100


def scan(serveur_id):
    # recuperation d'info serveur de la bdd
    serveur = Serveur.query.get(serveur_id)
    if not serveur:
        print(f"ERREUR: Serveur ID {serveur_id} introuvable.")
        return

    # connection serveur ssh
    session_ssh = GestionnaireSSH()
    connecte = session_ssh.etablir_connexion(
        serveur.adresse_ip, serveur.utilisateur_ssh, serveur.clef_ssh
    )

    if not connecte:
        print(f"ECHEC: Connexion impossible sur {serveur.nom}")
        return

    print(f"Démarrage sur {serveur.nom}")

    # Extraction des logs via SSH
    logs_ssh = session_ssh.recuperation_log_systeme()
    logs_web = session_ssh.recuperation_log_web()

    # Traitement analytique du type de log
    if logs_ssh:
        traiter_logs(serveur.id, logs_ssh, "SSH")
    if logs_web:
        traiter_logs(serveur.id, logs_web, "WEB")

    session_ssh.fermer()
    print(f"Audit terminé pour {serveur.nom}.")


def traiter_logs(serveur_id, logs, protocole):

    lignes = logs.split("\n")

    # Création de dictionnaire pour comptabiliser les occurrences par IP
    registre_echecs_ip = defaultdict(int)
    registre_volume = defaultdict(int)

    # Zone accumuler les alertes avant l'envoi en BDD
    lot_alertes = []

    for ligne in lignes:

        # Structuration de la ligne brute en dictionnaire
        donnees = parser_ligne_log(ligne)

        if donnees is None:
            continue

        # Récupération des clés ,adresse_ip / message
        ip_source = donnees["adresse_ip"]
        contenu_log = donnees["message"]
        date_log = donnees["date"]

        # Incrémentation Volume (DoS)
        registre_volume[ip_source] += 1
        
        # Détection DoS :alerte uniquement au moment précis où le seuil est franchit
        if registre_volume[ip_source] == SEUIL_DOS + 1:
            score, pays = verification_ip(ip_source)
            lot_alertes.append(
                creation_alerte(serveur_id, "DoS", ip_source, ligne, date_log, score, pays)
            )

        # Détection par Protocole
        if protocole == "SSH":
            if AnalyseurSecurite.echec_de_mot_de_passe(contenu_log):
                registre_echecs_ip[ip_source] += 1
                
                # Détection Brute Force
                if registre_echecs_ip[ip_source] == SEUIL_BRUTE_FORCE + 1:
                     score, pays =verification_ip(ip_source)
                     lot_alertes.append(
                        creation_alerte(serveur_id, "SSH Brute Force", ip_source, ligne, date_log, score, pays)
                    )

            elif AnalyseurSecurite.utilisateur_inconnu(contenu_log):
                score, pays = verification_ip(ip_source)
                lot_alertes.append(
                    creation_alerte(serveur_id, "Invalid User", ip_source, ligne, date_log, score, pays)
                )

        elif protocole == "WEB":
            if AnalyseurSecurite.injection_sql(contenu_log):
                score, pays = verification_ip(ip_source)
                lot_alertes.append(
                    creation_alerte(serveur_id, "SQL Injection", ip_source, ligne, date_log, score, pays)
                )

            elif AnalyseurSecurite.remontee_de_dossier(contenu_log):
                score, pays = verification_ip(ip_source)
                lot_alertes.append(
                    creation_alerte(serveur_id, "Path Traversal", ip_source, ligne, date_log, score, pays)
                )

    persister_alertes(lot_alertes)


def creation_alerte(srv_id, type, ip, lignes, date_log,score=None, pays=None):
    """Créeation d'un objet Alerte prêt à être sauvegardé."""

    est_liste = False
    if score is not None and score > 50:
        est_liste = True

    return Alerte(
        id_serveur=srv_id,
        type=type,
        ip_source=ip,
        ip_liste=est_liste,
        log_brut=lignes,
        date_heure=str(date_log),
        score_fiabilite=score,
        code_pays=pays    
    )


def persister_alertes(lot_alertes):
    """Sauvegarde groupée en BDD."""
    if not lot_alertes:
        return
    try:
        db.session.add_all(lot_alertes)
        db.session.commit()
        print(f"DB: {len(lot_alertes)} alertes enregistrées")
    except Exception as e:
        db.session.rollback()
        print(f"ERREUR BDD: {e}")
