import requests
import os
from dotenv import load_dotenv
from app.models import CacheIP
from app import db


load_dotenv()


def verification_ip(ip):
    """
    Consulte le score de réputation d'une adresse IP via l'API AbuseIPDB.

    Vérifie d'abord si l'IP est présente dans le cache local (Base de données)
    pour limiter les appels API. Si absente, interroge l'API externe,
    sauvegarde le résultat en cache et retourne les informations.

    Args:
        ip (str): L'adresse IP à analyser.

    Returns:
        tuple: (score d'abus, code pays) ou (None, None) en cas d'échec.
    """

    url = "https://api.abuseipdb.com/api/v2/check"

    cache = CacheIP.query.get(ip)
    if cache:
        return cache.score, cache.code_pays
    else:

        clef_api = os.environ.get("api_key")

        # Paramètres de la requête GET
        querystring = {"ipAddress": ip, "maxAgeInDays": "90"}

        headers = {"Accept": "application/json", "Key": clef_api}

        try:
            reponse = requests.get(url, params=querystring, headers=headers)

            if reponse.status_code == 200:
                json_response = reponse.json()
                data = json_response["data"]
                score = data.get("abuseConfidenceScore")
                pays = data.get("countryCode")

                try:
                    nouveau = CacheIP(ip=ip, score=score, code_pays=pays)
                    db.session.add(nouveau)
                    db.session.commit()
                except Exception:
                    db.session.rollback()

                return score, pays
            else:
                return None, None

        except Exception:
            return None, None
