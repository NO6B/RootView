import os
from dotenv import load_dotenv
from collections import defaultdict
from app import db
from app.models import Serveur, Alerte
from app.services.ssh_client import GestionnaireSSH
from app.services.parser import parser_ligne_log
from app.services.analyzer import AnalyseurSecurite
from app.services.client_abuseipdb import verification_ip


load_dotenv()

SEUIL_BRUTE_FORCE_SSH = int(os.getenv("SEUIL_BRUTE_FORCE_SSH"))
SEUIL_DOS = int(os.getenv("SEUIL_DOS"))
SEUIL_BRUTE_FORCE_WEB = int(os.getenv("SEUIL_BRUTE_FORCE_WEB"))


def scan(serveur_id):
    """
    Orchestre le processus d'audit complet d'un serveur spécifique.

    Récupère les informations du serveur en base de données, établit une connexion SSH,
    extrait les logs système et web, puis lance l'analyse.

    Args:
        serveur_id (int): L'identifiant unique du serveur à scanner.

    Returns:
        None: La fonction effectue des opérations en base de données et n'a pas de retour.
    """

    serveur = Serveur.query.get(serveur_id)
    if not serveur:
        return

    # connection serveur ssh
    session_ssh = GestionnaireSSH()
    succes, message = session_ssh.etablir_connexion(
        serveur.adresse_ip, serveur.utilisateur_ssh, serveur.clef_ssh
    )

    if not succes:
        return

    # Extraction des logs
    logs_ssh = session_ssh.recuperation_log_systeme()
    logs_web = session_ssh.recuperation_log_web()

    # Traitement analytique du type de log
    if logs_ssh:
        traiter_logs(serveur.id, logs_ssh, "SSH")
    if logs_web:
        traiter_logs(serveur.id, logs_web, "WEB", serveur.endpoint_web)

    session_ssh.fermer()


def traiter_logs(serveur_id, logs, protocole, endpoint_web=None):
    """
    Analyse un bloc de texte brut pour détecter et enregistrer des anomalies de sécurité.

    Cette fonction découpe les logs par ligne et identifie les menaces (DoS, Brute Force SSH/Web,
    Injection SQL, Path Traversal) selon le protocole spécifié.
    Elle gère les seuils de détection, évite la création de doublons en vérifiant l'historique
    en base de données et enrichit chaque alerte via une API de Threat Intelligence.

    Args:
        serveur_id (int): L'identifiant unique du serveur associé aux logs dans la base de données.
        logs (str): Chaîne de caractères contenant l'intégralité des lignes de logs extraites du serveur.
        protocole (str): Type de log à traiter, acceptant les valeurs 'SSH' ou 'WEB'.
        endpoint_web (str, optional): L'URL spécifique (ex: /login) à surveiller pour les tentatives de Brute Force HTTP.

    Returns:
        None: La fonction effectue des persistances directes en base de données via persister_alertes().
    """
    lignes = logs.split("\n")

    registre_echecs_ip = defaultdict(int)
    registre_volume = defaultdict(int)
    registre_brute_force_web = defaultdict(int)
    lot_alertes = []

    for ligne in lignes:
        donnees = parser_ligne_log(ligne)
        if donnees is None:
            continue

        ip_source = donnees["adresse_ip"]
        contenu_log = donnees["message"]
        date_log = donnees["date"]

        registre_volume[ip_source] += 1
        # DOS
        if registre_volume[ip_source] >= SEUIL_DOS:
            if not Alerte.query.filter_by(
                id_serveur=serveur_id, log_brut=ligne
            ).first():
                score, pays = verification_ip(ip_source)
                lot_alertes.append(
                    creation_alerte(
                        serveur_id, "DoS", ip_source, ligne, date_log, score, pays
                    )
                )
            registre_volume[ip_source] = 0

        # PROTOCOLE SSH
        if protocole == "SSH":
            if AnalyseurSecurite.echec_de_mot_de_passe(contenu_log):
                registre_echecs_ip[ip_source] += 1

            if registre_echecs_ip[ip_source] >= SEUIL_BRUTE_FORCE_SSH:
                if not Alerte.query.filter_by(
                    id_serveur=serveur_id, log_brut=ligne
                ).first():
                    score, pays = verification_ip(ip_source)
                    lot_alertes.append(
                        creation_alerte(
                            serveur_id,
                            "SSH Brute Force",
                            ip_source,
                            ligne,
                            date_log,
                            score,
                            pays,
                        )
                    )
                registre_echecs_ip[ip_source] = 0

            elif AnalyseurSecurite.utilisateur_inconnu(contenu_log):
                if not Alerte.query.filter_by(
                    id_serveur=serveur_id, log_brut=ligne
                ).first():
                    score, pays = verification_ip(ip_source)
                    lot_alertes.append(
                        creation_alerte(
                            serveur_id,
                            "Invalid User",
                            ip_source,
                            ligne,
                            date_log,
                            score,
                            pays,
                        )
                    )

        # PROTOCOLE WEB
        elif protocole == "WEB":
            methode = donnees.get("methode")
            url = donnees.get("url")
            status_code = donnees.get("status_code")

            if AnalyseurSecurite.brute_force_endpoint(
                methode, url, endpoint_web, status_code
            ):
                registre_brute_force_web[ip_source] += 1

                if registre_brute_force_web[ip_source] >= SEUIL_BRUTE_FORCE_WEB:
                    if not Alerte.query.filter_by(
                        id_serveur=serveur_id, log_brut=ligne
                    ).first():
                        score, pays = verification_ip(ip_source)
                        lot_alertes.append(
                            creation_alerte(
                                serveur_id,
                                "WEB Brute Force",
                                ip_source,
                                ligne,
                                date_log,
                                score,
                                pays,
                            )
                        )
                    registre_brute_force_web[ip_source] = 0

            if AnalyseurSecurite.injection_sql(contenu_log):
                if not Alerte.query.filter_by(
                    id_serveur=serveur_id, log_brut=ligne
                ).first():
                    score, pays = verification_ip(ip_source)
                    lot_alertes.append(
                        creation_alerte(
                            serveur_id,
                            "SQL Injection",
                            ip_source,
                            ligne,
                            date_log,
                            score,
                            pays,
                        )
                    )

            elif AnalyseurSecurite.remontee_de_dossier(contenu_log):
                if not Alerte.query.filter_by(
                    id_serveur=serveur_id, log_brut=ligne
                ).first():
                    score, pays = verification_ip(ip_source)
                    lot_alertes.append(
                        creation_alerte(
                            serveur_id,
                            "Path Traversal",
                            ip_source,
                            ligne,
                            date_log,
                            score,
                            pays,
                        )
                    )

    persister_alertes(lot_alertes)


def creation_alerte(srv_id, type_attaque, ip, lignes, date_log, score=None, pays=None):
    """
    Instancie un nouvel objet Alerte.

    Détermine si l'IP doit être listée (blacklist) selon son score de fiabilité.

    Args:
        srv_id (int): Identifiant du serveur cible.
        type_attaque (str): Libellé de l'attaque détectée.
        ip (str): Adresse IP source de l'attaque.
        lignes (str): Contenu brut de la ligne de log incriminée.
        date_log (datetime/str): Horodatage de l'événement.
        score (int, optional): Score de réputation AbuseIPDB (0-100).
        pays (str, optional): Code pays de l'IP.

    Returns:
        Alerte: Une instance du modèle SQLAlchemy Alerte prête pour l'insertion.
    """
    est_liste = False
    if score is not None and score > 50:
        est_liste = True

    return Alerte(
        id_serveur=srv_id,
        type=type_attaque,
        ip_source=ip,
        ip_liste=est_liste,
        log_brut=lignes,
        date_heure=str(date_log),
        score_fiabilite=score,
        code_pays=pays,
    )


def persister_alertes(lot_alertes):
    """
    Réalise la sauvegarde physique des alertes dans la base de données.

    Utilise add_all pour ajouter tous les objets dans lot_alertes.
    En cas d'échec, un rollback est effectué.

    Args:
        lot_alertes (list): Liste d'objets Alerte à enregistrer.

    Returns:
        None
    """
    if not lot_alertes:
        return
    try:
        db.session.add_all(lot_alertes)
        db.session.commit()
    except Exception:
        db.session.rollback()
