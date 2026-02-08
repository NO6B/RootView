import re

def parse_log_ligne(ligne):
    if not ligne:
        return None

    # Motif complet : Date | Message | User | IP
    motif = r"^(.{15}).*?:\s+(.*?)\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)"

    # Exécution de la recherche du motif dans la ligne
    match = re.search(motif, ligne)

    if match:
        return {
            "date_heure":     match.group(1),
            "ip_source":      match.group(4),
            "log_brut":       ligne,
            "user":           match.group(3),
            "message_erreur": match.group(2)
        }
    
    return None
