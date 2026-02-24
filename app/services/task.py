from app import schedule
from app.models import Serveur
from app.services.scanner import scan

def scan_global():
    # activation l'accès à la BDD et à la config (car dans un thread different).
    with schedule.app.app_context():
        try:
            # Récupération de tous les serveurs
            serveurs = Serveur.query.all()
            
            if not serveurs:
                print("Aucun serveur à scanner.")
                return

            print(f"Serveurs trouvés : {len(serveurs)}")

            # Boucle sur chaque serveur
            for i in serveurs:
                print(f"Traitement du serveur : {i.nom} ({i.adresse_ip})")
                scan(i.id)
                
        except Exception as e:
            print(f"ERREUR DANS LE SCHEDULER : {e}")
