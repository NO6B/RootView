from collections import defaultdict
from datetime import datetime
from app import db
from app.models import Serveur, Alerte
from app.ssh_client import GestionnaireSSH
from app.parser import parser_ligne_log
from app.analyzer import AnalyseurSecurite


# Configuration
SEUIL_BRUTE_FORCE = 15
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

    # Découpe le bloc de texte brut en une liste de lignes
    lignes = logs.split("\n")

    # Création de dictionnaire pour comptabiliser les occurrences par IP
    registre_echecs_ip = defaultdict(int)
    registre_volume = defaultdict(int)

    # Zone accumuler les alertes avant l'envoi en BDD
    queue_alertes = []

    for ligne in lignes:
        # Structuration de la ligne brute en dictionnaire
        donnees = parser_ligne_log(ligne)

        if donnees is None:
            continue

        # Récupération des clés ,adresse_ip / message
        ip_source = donnees["adresse_ip"]
        contenu_log = donnees["message"]

        # Incrémentation Volume (DoS)
        registre_volume[ip_source] += 1

        # Détection et stockage en format liste des instances d'alertes
        if protocole == "SSH":
            if AnalyseurSecurite.echec_de_mot_de_passe(contenu_log):
                registre_echecs_ip[ip_source] += 1

            elif AnalyseurSecurite.utilisateur_inconnu(contenu_log):
                queue_alertes.append(
                    instancier_alerte(serveur_id, "Invalid User", ip_source, ligne)
                )

        elif protocole == "WEB":
            if AnalyseurSecurite.injection_sql(contenu_log):
                queue_alertes.append(
                    instancier_alerte(serveur_id, "SQL Injection", ip_source, ligne)
                )

            elif AnalyseurSecurite.remontee_de_dossier(contenu_log):
                queue_alertes.append(
                    instancier_alerte(serveur_id, "Path Traversal", ip_source, ligne)
                )

    # Validation des Seuils et creation des alerte
    # Brute Force SSH
    for ip, nb_echecs in registre_echecs_ip.items():
        if AnalyseurSecurite.depasse_le_seuil(nb_echecs, SEUIL_BRUTE_FORCE):
            motif = f"Détection de {nb_echecs} échecs d'authentification cumulés."
            queue_alertes.append(
                instancier_alerte(serveur_id, "SSH Brute Force", ip, motif)
            )

    # DoS
    for ip, volume in registre_volume.items():
        if AnalyseurSecurite.depasse_le_seuil(volume, SEUIL_DOS):
            motif = f"Anomalie volumétrique : {volume} requêtes ({protocole})."
            queue_alertes.append(
                instancier_alerte(serveur_id, "DoS", ip, motif)
            )


    persister_alertes(queue_alertes)


def instancier_alerte(srv_id, classification, ip, preuve_technique):
    """Créeation d'un objet Alerte prêt à être sauvegardé."""
    return Alerte(
        id_serveur=srv_id,
        type=classification,
        ip_source=ip,
        ip_liste=False,
        log_brut=preuve_technique,
        date_heure=datetime.now(),
    )


def persister_alertes(lot_alertes):
    """Sauvegarde groupée en BDD."""
    if not lot_alertes:
        return
    try:
        db.session.add_all(lot_alertes)
        db.session.commit()
        print(f"[DB] {len(lot_alertes)} alertes enregistrées")
    except Exception as e:
        db.session.rollback()
        print(f"[ERREUR BDD] : {e}")
