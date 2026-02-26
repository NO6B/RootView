import paramiko
import io

class GestionnaireSSH:
    def __init__(self):
        # Initialisation des attributs de l'instance de l'objet
        self.client = paramiko.SSHClient()
        # Accepte les clés inconnues pour éviter de bloquer sur la validation (yes/no)
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def etablir_connexion(self, ip, utilisateur, cle_privee_texte):
        """
        Initialise une connexion SSH sécurisée vers un serveur distant.

        Cette méthode traite la clé privée fournie sous forme de texte, identifie 
        automatiquement son format cryptographique (RSA ou Ed25519) et tente 
        d'établir le tunnel SSH avec un délai d'attente de 20 secondes.

        Args:
            ip (str): L'adresse IPv4 ou le nom de domaine du serveur distant.
            utilisateur (str): Le nom du compte utilisateur (ex: 'ubuntu').
            cle_privee_texte (str): Le contenu brut du fichier de clé (.pem).

        Returns:
            tuple: (bool, str) Un booléen de succès et un message de statut 
                ou d'erreur détaillé.
        """
        try:
            # instance du fichier mémoire de la clef en format txt
            cle_virtuelle = io.StringIO(cle_privee_texte)
            # variable qui permet de recuperer la clef_privee en format binaire 
            pkey = None
            # DÉTECTION DU TYPE DE CLÉ
            try:
                # test format RSA
                pkey = paramiko.RSAKey.from_private_key(cle_virtuelle)
            except:
                # En cas d'échec, on rembobine le fichier au début
                cle_virtuelle.seek(0)
                try:
                    # test Format Ed25519
                    pkey = paramiko.Ed25519Key.from_private_key(cle_virtuelle)
                except:
                    return False, "Format de clé inconnu (ni RSA, ni Ed25519)"

            # Connexion au serveur avec un timeout de 20s pour abandonner la tentative d'entrer.
            self.client.connect(
                hostname=ip, username=utilisateur, 
                pkey=pkey, timeout=20
            )
            return True, "Connecté avec succès"
            
        except Exception as e:
            return False, f"Impossible de joindre le serveur: {e}"
        
    def recuperation_log_systeme(self):
        """
        Extrait les derniers événements d'authentification du serveur.

        Exécute la commande 'sudo tail' pour récupérer les 1000 dernières lignes 
        du fichier /var/log/auth.log. Ce fichier contient les tentatives de 
        connexion SSH, les accès sudo et les erreurs d'authentification.

        Returns:
            str: Le contenu des logs décodé en UTF-8 ou un message d'erreur 
                préfixé par "Erreur:".
        """
        try:

            stdin, stdout, stderr = self.client.exec_command('sudo tail -n 1000 /var/log/auth.log')
            # récuperation du résultat binaire, et le traduit en texte
            return stdout.read().decode('utf-8')
        except Exception as e:
            return f"Erreur: {e}"
            
    def recuperation_log_web(self):
        """
        Récupère les logs web en testant les services par ordre de priorité.
        
        Tente d'abord de lire les logs Apache. Si le fichier n'existe pas ou 
        n'est pas accessible, bascule automatiquement sur les logs Nginx.
        
        Returns:
            str: Le contenu des logs du premier service trouvé, ou None si aucun n'est disponible.
        """
        commandes = [
            'sudo tail -n 1000 /var/log/nginx/access.log',
            'sudo tail -n 1000 /var/log/apache2/access.log'
        ]
        
        for commande in commandes:
            try:
                stdin, stdout, stderr = self.client.exec_command(commande)
                exit_code = stdout.channel.recv_exit_status()
                
                if exit_code == 0:
                    return stdout.read().decode('utf-8')
            except Exception as e:
                print(f"Échec de la commande {commande} : {e}")
                continue

        return None

    def fermer(self):
        self.client.close()
