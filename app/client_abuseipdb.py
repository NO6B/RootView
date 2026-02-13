import requests
import os
from dotenv import load_dotenv

load_dotenv()
def verification_ip(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'

    clef_api =os.environ.get("api_key")

    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': clef_api
    }

    reponse = requests.get(url,headers=headers, params=querystring)

    if reponse.status_code==200:

        data = reponse.json()
        return data['data']['abuseConfidenceScore']

