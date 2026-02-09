import re

def convertir_ligne_en_info(ligne_brute):
    if not ligne_brute or not ligne_brute.strip():
        return None

    # --- FORMAT 1 : SSH (Linux System Logs) ---
    
    regex_ssh = r"^(.{15}).*?:\s+(.*?)\s+from\s+(\d+\.\d+\.\d+\.\d+)"
    match_ssh = re.search(regex_ssh, ligne_brute)
    
    if match_ssh:
        return {
            "source":      "SSH",
            "date":        match_ssh.group(1),
            "message":     match_ssh.group(2),
            "adresse_ip":  match_ssh.group(3),
            "ligne_complete": ligne_brute
        }

    # --- FORMAT 2 : WEB (Apache / Nginx) ---
    
    regex_web = r"^(\d+\.\d+\.\d+\.\d+)\s-\s-\s\[(.*?)\]\s\"(.*?)\""
    match_web = re.search(regex_web, ligne_brute)

    if match_web:
        return {
            "source":      "WEB",
            "date":        match_web.group(2),
            "message":     match_web.group(3),
            "adresse_ip":  match_web.group(1),
            "ligne_complete": ligne_brute
        }

    return None