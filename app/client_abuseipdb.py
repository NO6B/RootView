import requests
import os
from dotenv import load_dotenv
from app.models import CacheIP
from app import db


load_dotenv()
def verification_ip(ip):


    url = 'https://api.abuseipdb.com/api/v2/check'

    cache = CacheIP.query.get(ip)
    if cache:
        return cache.score, cache.code_pays
    else:

        clef_api =os.environ.get("api_key")

        # Paramètres de la requête GET
        querystring = {
            'ipAddress': ip,
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': clef_api
        }
        
        try:
            reponse = requests.get(url, params=querystring, headers=headers)

            if reponse.status_code == 200:
                json_response = reponse.json()
                data = json_response['data']
                score = data.get('abuseConfidenceScore')
                pays = data.get('countryCode')

                try:
                    # SAUVEGARDE
                    nouveau = CacheIP(ip=ip, score=score, code_pays=pays)
                    db.session.add(nouveau)
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    print(f"erreur: {e}")
                
                return score, pays
            else:
                print(f"Erreur: {reponse.status_code}")
                return None, None
            

        except Exception as e:
            print(f"erreur:{e}")
            return None, None
