import re

class AnalyseurSecurite:
    # --- RÈGLES SSH ---

    @staticmethod
    def echec_de_mot_de_passe(contenu_log):
        patterns = [
            "Failed password", 
            "Connection closed by authenticating user",
            "Connection reset by authenticating user"
        ]
        return any(motif in contenu_log for motif in patterns)

    @staticmethod
    def utilisateur_inconnu(contenu_log):
        return bool(re.search(r"(invalid|illegal)\s+user", contenu_log, re.IGNORECASE))

    # --- RÈGLES WEB ---

    @staticmethod
    def injection_sql(contenu_log):
        patterns = [
            r"UNION(\s+|%20| \+ )+SELECT",
            r"SELECT(\s+|%20| \+ )+.*FROM",
            r"OR(\s+|%20| \+ )*1(\s+|%20| \+ )*=(\s+|%20| \+ )*1",
            r"DROP(\s+|%20| \+ )+TABLE",
            r"%27",
            r"--"
        ]
        return bool(re.search("|".join(patterns), contenu_log, re.IGNORECASE))

    @staticmethod
    def remontee_de_dossier(contenu_log):
        patterns = [r"\.\./", r"/etc/passwd", r"/bin/bash"]
        return bool(re.search("|".join(patterns), contenu_log, re.IGNORECASE))


    @staticmethod
    def brute_force_endpoint(methode_log, endpoint, endpoint_configure, status_code):
        """
        Vérifie si une requête correspond à une tentative de connexion échouée
        sur l'endpoint spécifique paramétré pour ce serveur.
        """
        cible_atteinte = (methode_log == "POST" and endpoint == endpoint_configure)
        
        codes_echec = ["401", "403", "404"]
        echec_confirme = status_code in codes_echec
        
        return cible_atteinte and echec_confirme
    