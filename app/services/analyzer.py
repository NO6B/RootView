import re


class AnalyseurSecurite:
    """
    Moteur de détection regroupant les règles logiques pour identifier
    les tentatives d'intrusion à partir des logs système et web.
    """

    @staticmethod
    def echec_de_mot_de_passe(contenu_log):
        """
        Identifie une tentative de connexion SSH ayant échoué à l'étape
        de l'authentification par mot de passe.
        """
        patterns = [
            "Failed password",
            "Connection closed by authenticating user",
            "Connection reset by authenticating user",
        ]
        return any(motif in contenu_log for motif in patterns)

    @staticmethod
    def utilisateur_inconnu(contenu_log):
        """
        Détecte l'utilisation d'un nom d'utilisateur qui n'existe pas
        sur le système distant (invalid/illegal user).
        """
        return bool(re.search(r"(invalid|illegal)\s+user", contenu_log, re.IGNORECASE))

    # --- RÈGLES WEB ---

    @staticmethod
    def injection_sql(contenu_log):
        """
        Repère les signatures d'attaques par injection SQL (Union Select,
        Or 1=1, Drop Table, etc.) dans les requêtes HTTP.
        """
        patterns = [
            r"UNION(\s+|%20| \+ )+SELECT",
            r"SELECT(\s+|%20| \+ )+.*FROM",
            r"OR(\s+|%20| \+ )*1(\s+|%20| \+ )*=(\s+|%20| \+ )*1",
            r"DROP(\s+|%20| \+ )+TABLE",
            r"%27",
            r"--",
        ]
        return bool(re.search("|".join(patterns), contenu_log, re.IGNORECASE))

    @staticmethod
    def remontee_de_dossier(contenu_log):
        """
        Détecte les tentatives d'accès à des fichiers sensibles du système
        via des patterns de type Path Traversal (../ ou /etc/passwd).
        """
        patterns = [r"\.\./", r"/etc/passwd", r"/bin/bash"]
        return bool(re.search("|".join(patterns), contenu_log, re.IGNORECASE))

    @staticmethod
    def brute_force_endpoint(methode_log, endpoint, endpoint_configure, status_code):
        """
        Vérifie si une requête correspond à une tentative de connexion échouée
        sur l'endpoint spécifique paramétré pour ce serveur.
        """
        cible_atteinte = methode_log == "POST" and endpoint == endpoint_configure

        codes_echec = ["401", "403", "404"]
        echec_confirme = status_code in codes_echec

        return cible_atteinte and echec_confirme
