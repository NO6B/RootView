import paramiko
import io

class GestionnaireSSH:
    def __init__(self):
        # Initialisation des attributs de l'instance de l'objet
        self.client = paramiko.SSHClient()
        # Accepte les clés inconnues pour éviter de bloquer sur la validation (yes/no)
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def etablir_connexion(self, ip, utilisateur, cle_privee_texte):
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
        try:
            # execution de la command
            stdin, stdout, stderr = self.client.exec_command('sudo tail -n 1000 /var/log/auth.log')
            # récuperation du résultat binaire, et le traduit en texte
            return stdout.read().decode('utf-8')
        except Exception as e:
            return f"Erreur: {e}"
            
    def recuperation_log_web(self):
            try:
                # execution de la command
                stdin, stdout, stderr = self.client.exec_command('sudo tail -n 1000 /var/log/apache2/access.log')
                # récuperation du résultat binaire, et le traduit en texte
                return stdout.read().decode('utf-8')
            except Exception as e:
                return f"Erreur: {e}"

    def fermer(self):
        self.client.close()
        