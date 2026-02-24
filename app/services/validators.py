import re

def validation(nom, mdp):
    """
    Vérifie la conformité de l'identifiant et du mot de passe.
    Retourne (True, None) si valide, ou (False, "Message d'erreur") si invalide.
    """
    # Vérification de l'identifiant
    if not nom or len(nom) < 5:
        return False, "L'identifiant doit contenir au moins 5 caractères."

    # Vérification du mot de passe
    regex_special = r"[!@#$%^&*(),.?\":{}|<>]"
    if not mdp or len(mdp) < 8 or not re.search(r"[A-Z]", mdp) or not re.search(r"\d", mdp) or not re.search(regex_special, mdp):
        return False, "Le mot de passe doit contenir au minimum 8 caractères, dont une majuscule, un chiffre et un caractère spécial."

    return True, None
