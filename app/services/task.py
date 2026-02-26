from app import schedule
from app.models import Serveur
from app.services.scanner import scan


def scan_global():
    """
    Lance une analyse de sécurité automatisée sur l'intégralité du parc de serveurs.

    Cette fonction récupère tous les serveurs enregistrés en base de données et
    déclenche séquentiellement le moteur de scan pour chacun d'entre eux.
    Elle est conçue pour être pilotée par le planificateur de tâches (APScheduler).

    Note technique :
        L'utilisation de 'app_context()' est indispensable ici car cette fonction
        s'exécute dans un thread de fond, indépendant de la requête Flask principale,
        nécessitant un accès explicite à la session SQLAlchemy.

    Returns:
        None
    """
    with schedule.app.app_context():
        try:
            # Récupération de tous les serveurs
            serveurs = Serveur.query.all()

            if not serveurs:
                return

            for i in serveurs:
                scan(i.id)

        except Exception:
            pass
