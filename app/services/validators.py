import re


def validation(nom, mdp):
    """
    Valide la conformité et la robustesse des identifiants et des mots de passe.

    Cette fonction applique une politique de sécurité stricte pour prévenir
    la création de comptes avec des identifiants trop faibles (Weak Credentials),
    limitant ainsi l'efficacité des attaques par dictionnaire.

    Critères appliqués :
    - Identifiant : Minimum 5 caractères.
    - Mot de passe : Minimum 8 caractères, incluant au moins une majuscule,
      un chiffre et un caractère spécial.

    Args:
        nom (str): L'identifiant choisi par l'utilisateur.
        mdp (str): Le mot de passe en clair à soumettre au test de robustesse.

    Returns:
        tuple: (bool, str) Un booléen indiquant la validité et un message
               d'erreur explicatif en cas d'échec (None si succès).
    """
    # Vérification de l'identifiant
    if not nom or len(nom) < 5:
        return False, "L'identifiant doit contenir au moins 5 caractères."

    # Vérification du mot de passe
    regex_special = r"[!@#$%^&*(),.?\":{}|<>]"
    if (
        not mdp
        or len(mdp) < 8
        or not re.search(r"[A-Z]", mdp)
        or not re.search(r"\d", mdp)
        or not re.search(regex_special, mdp)
    ):
        return (
            False,
            "Le mot de passe doit contenir au minimum 8 caractères, dont une majuscule, un chiffre et un caractère spécial.",
        )

    return True, None
