import re

class AnalyseurSecurite:
    # --- RÈGLES SSH ---

    @staticmethod
    def echec_de_mot_de_passe(contenu_log):
        # Cherche la phrase exacte générée par Linux
        return "Failed password" in contenu_log

    @staticmethod
    def utilisateur_inconnu(contenu_log):
        # Cherche "Invalid user" ou "Illegal user" (Majuscules ignorées)
        return bool(re.search(r"(invalid|illegal)\s+user", contenu_log, re.IGNORECASE))

    # --- RÈGLES WEB ---

    @staticmethod
    def injection_sql(contenu_log):
        # Cherche des commandes SQL dangereuses
        patterns = [
            r"UNION\s+SELECT",
            r"SELECT\s+.*FROM",
            r"OR\s+1=1",
            r"DROP\s+TABLE"
        ]
        # Vérifie si l'un des patterns est présent
        return bool(re.search("|".join(patterns), contenu_log, re.IGNORECASE))

    @staticmethod
    def remontee_de_dossier(contenu_log):
        # Cherche des tentatives d'accès aux fichiers système (Path Traversal)
        patterns = [r"\.\./", r"/etc/passwd", r"/bin/bash"]
        return bool(re.search("|".join(patterns), contenu_log, re.IGNORECASE))

    # --- RÈGLE VOLUME (DOS) ---

    @staticmethod
    def depasse_le_seuil(compteur, limite):
        # comparaison mathématique
        return compteur > limite
