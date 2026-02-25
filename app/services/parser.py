import re

def parser_ligne_log(ligne_brute):
    if not ligne_brute or not ligne_brute.strip():
        return None

    #  SSH
    regex_ssh = r"^(.+?)\s+.*?sshd\[\d+\]:\s+(.*?)(?:\s+from)?\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    match_ssh = re.search(regex_ssh, ligne_brute)

    if match_ssh:
        return {
            "date": match_ssh.group(1).strip(),
            "message": match_ssh.group(2).strip(),
            "adresse_ip": match_ssh.group(3),
        }

    # WEB
    regex_web = r"^(\d{1,3}(?:\.\d{1,3}){3})\s-\s-\s\[(.*?)\]\s\"((\S+)\s(.*?)\s.*?)\"\s(\d{3})"
    match_web = re.search(regex_web, ligne_brute)

    if match_web:
        return {
            "adresse_ip": match_web.group(1),
            "date": match_web.group(2),
            "message": match_web.group(3),
            "methode": match_web.group(4),
            "url": match_web.group(5),
            "status_code": match_web.group(6),
        }

    return None
