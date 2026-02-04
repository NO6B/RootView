from datetime import datetime
from app import db
from app.models import Serveur, Alerte
from app.ssh_client import GestionnaireSSH

def scan(serveur_id):
    # Récupération des infos du serveur dans le db
    serveur = Serveur.query.get(serveur_id)
    if not serveur:
        print(f"Erreur : Serveur {serveur_id} introuvable.")
        return

    # Connexion SSH
    connection = GestionnaireSSH()
    
    succes, message = connection.etablir_connexion(
        serveur.adresse_ip, 
        serveur.utilisateur_ssh,
        serveur.clef_ssh
    )

    if not succes:
        print(f"Erreur de connexion : {message}")
        return

    # Récupération des logs
    logs_bruts = connection.recuperation_log_systeme()
    connection.fermer() 

    if not logs_bruts:
        print("Aucun log récupéré.")
        return

    # --Stockage-- transformation du bloc de texte en liste de lignes
    lignes = logs_bruts.split('\n')
    
    compteur = 0
    
    # boucle sur toutes les lignes
    for ligne in lignes:
        
        # On saute les lignes vides
        if not ligne.strip(): 
            continue

        # On stocke la ligne brute
        alerte = Alerte(
            id_serveur=serveur.id,
            type="LOG_BRUT",
            ip_source="0.0.0.0",
            ip_liste=False,
            log_brut=ligne,
            date_heure=datetime.now()
        )
        db.session.add(alerte)
        compteur += 1

    # Sauvegarde finale
    try:
        db.session.commit()
        print(f"Succès : {compteur} lignes sauvegardées (Tout le fichier).")
    except Exception as e:
        db.session.rollback()
        print(f"Erreur BDD : {e}")
