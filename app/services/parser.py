import re

def parser_ligne_log(ligne_brute):
    if not ligne_brute or not ligne_brute.strip():
        return None

    #  SSH: Linux System Logs
    regex_ssh = r"^(.+?)\s+.*?sshd\[\d+\]:\s+(.*?)(?:\s+from)?\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    match_ssh = re.search(regex_ssh, ligne_brute)

    if match_ssh:
        return {
            "source": "SSH",
            "date": match_ssh.group(1).strip(),
            "message": match_ssh.group(2).strip(),
            "adresse_ip": match_ssh.group(3),
            "ligne_complete": ligne_brute,
        }

    # WEB: Apache
    regex_web = r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s-\s-\s\[(.*?)\]\s\"(.*?)\""
    match_web = re.search(regex_web, ligne_brute)

    if match_web:
        return {
            "source": "WEB",
            "date": match_web.group(2),
            "message": match_web.group(3),
            "adresse_ip": match_web.group(1),
            "ligne_complete": ligne_brute,
        }

    return None
