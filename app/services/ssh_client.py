import paramiko
import io


class GestionnaireSSH:
    """
    Gère les connexions et l'exécution de commandes à distance via SSH.
    """

    def __init__(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def etablir_connexion(self, ip, utilisateur, cle_privee_texte):
        """
        Initialise une connexion SSH sécurisée vers un serveur distant.

        Args:
            ip (str): L'adresse IPv4 ou le nom de domaine.
            utilisateur (str): Le nom du compte utilisateur.
            cle_privee_texte (str): Le contenu brut de la clé (.pem).

        Returns:
            tuple: (bool, str) Succès et message de statut.
        """
        try:
            cle_virtuelle = io.StringIO(cle_privee_texte)
            pkey = None

            # DÉTECTION DU TYPE DE CLÉ
            try:
                pkey = paramiko.RSAKey.from_private_key(cle_virtuelle)
            except Exception:
                cle_virtuelle.seek(0)
                try:
                    pkey = paramiko.Ed25519Key.from_private_key(cle_virtuelle)
                except Exception:
                    return False, "Format de clé privé invalide ou corrompu."

            self.client.connect(
                hostname=ip, username=utilisateur, pkey=pkey, timeout=20
            )
            return True, "Connecté avec succès"

        except Exception as e:
            return False, f"Échec de connexion : {str(e)}"

    def recuperation_log_systeme(self):
        """
        Extrait les derniers événements d'authentification du serveur.

        Returns:
            str: Le contenu des logs ou None en cas d'erreur.
        """
        try:
            stdin, stdout, stderr = self.client.exec_command(
                "sudo tail -n 1000 /var/log/auth.log"
            )
            return stdout.read().decode("utf-8")
        except Exception:
            return None

    def recuperation_log_web(self):
        """
        Récupère les logs web en testant Nginx puis Apache.

        Returns:
            str: Le contenu des logs ou None.
        """
        commandes = [
            "sudo tail -n 1000 /var/log/nginx/access.log",
            "sudo tail -n 1000 /var/log/apache2/access.log",
        ]

        for commande in commandes:
            try:
                stdin, stdout, stderr = self.client.exec_command(commande)
                if stdout.channel.recv_exit_status() == 0:
                    return stdout.read().decode("utf-8")
            except Exception:
                continue

        return None

    def fermer(self):
        """Clôture la session SSH."""
        self.client.close()
