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

    # --- RÈGLE VOLUME (DOS) ---

    @staticmethod
    def depasse_le_seuil(compteur, limite):
        return compteur > limite
