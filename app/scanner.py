import os
from dotenv import load_dotenv
from collections import defaultdict
from app import db
from app.models import Serveur, Alerte
from app.ssh_client import GestionnaireSSH
from app.parser import parser_ligne_log
from app.analyzer import AnalyseurSecurite
from app.client_abuseipdb import verification_ip


load_dotenv()

SEUIL_BRUTE_FORCE = int(os.getenv("SEUIL_BRUTE_FORCE"))
SEUIL_DOS = int(os.getenv("SEUIL_DOS"))

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

    # Extraction des logs
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
    """
    Analyse un bloc de texte brut pour détecter des anomalies de sécurité.
    
    Découpe les logs par ligne, identifie les types d'attaques (DoS, Brute Force, 
    SQLi, Path Traversal) selon le protocole, gère les seuils de détection 
    et évite les doublons par rapport à l'historique en base de données.
    
    Args:
        serveur_id (int): ID du serveur lié aux logs.
        logs (str): Chaîne de caractères contenant l'ensemble des logs extraits.
        protocole (str): Type de log à traiter ('SSH' ou 'WEB').
        
    Returns:
        None: Appelle persister_alertes() pour sauvegarder les résultats.
    """

    lignes = logs.split("\n")

    registre_echecs_ip = defaultdict(int)
    registre_volume = defaultdict(int)
    lot_alertes = []

    alertes_existantes = Alerte.query.filter_by(id_serveur=serveur_id).all()
    logs_deja_traites = set()

    for alerte in alertes_existantes:
        contenu_du_log = alerte.log_brut
        
        logs_deja_traites.add(contenu_du_log)

    for ligne in lignes:
        donnees = parser_ligne_log(ligne)
        if donnees is None:
            continue

        ip_source = donnees["adresse_ip"]
        contenu_log = donnees["message"]
        date_log = donnees["date"]

        # Incrémentation Volume (DoS)
        registre_volume[ip_source] += 1
        
        if registre_volume[ip_source] == SEUIL_DOS + 1:
            if ligne not in logs_deja_traites:
                score, pays = verification_ip(ip_source)
                lot_alertes.append(creation_alerte(serveur_id, "DoS", ip_source, ligne, date_log, score, pays))
                logs_deja_traites.add(ligne)

        if protocole == "SSH":
            if AnalyseurSecurite.echec_de_mot_de_passe(contenu_log):
                registre_echecs_ip[ip_source] += 1
        
            if registre_echecs_ip[ip_source] == SEUIL_BRUTE_FORCE + 1:
                if ligne not in logs_deja_traites:
                    score, pays = verification_ip(ip_source)
                    lot_alertes.append(creation_alerte(serveur_id, "SSH Brute Force", ip_source, ligne, date_log, score, pays))
                    logs_deja_traites.add(ligne)

            
            elif AnalyseurSecurite.utilisateur_inconnu(contenu_log):
                if ligne not in logs_deja_traites:
                    score, pays = verification_ip(ip_source)
                    lot_alertes.append(creation_alerte(serveur_id, "Invalid User", ip_source, ligne, date_log, score, pays))
                    logs_deja_traites.add(ligne)

        elif protocole == "WEB":
            if AnalyseurSecurite.injection_sql(contenu_log):
                if ligne not in logs_deja_traites:
                    score, pays = verification_ip(ip_source)
                    lot_alertes.append(creation_alerte(serveur_id, "SQL Injection", ip_source, ligne, date_log, score, pays))
                    logs_deja_traites.add(ligne)

            elif AnalyseurSecurite.remontee_de_dossier(contenu_log):
                if ligne not in logs_deja_traites:
                    score, pays = verification_ip(ip_source)
                    lot_alertes.append(creation_alerte(serveur_id, "Path Traversal", ip_source, ligne, date_log, score, pays))
                    logs_deja_traites.add(ligne)

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
        code_pays=pays    
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
        print(f"DB: {len(lot_alertes)} alertes enregistrées")
    except Exception as e:
        db.session.rollback()
        print(f"ERREUR BDD: {e}")
