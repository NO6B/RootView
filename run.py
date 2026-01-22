# run.py
from app import creer_application 

# On appelle la fonction pour créer l'application
app = creer_application()

# Vérifie si ce script est le point d'entrée principal (et non un import)
if __name__ == '__main__':
    # Démarre le serveur WSGI de développement sur le port 5000
    app.run(debug=True, port=5000)