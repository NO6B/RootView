---

```markdown
# RootView - Plateforme de Surveillance de Sécurité Automatisée

RootView est un analyseur de logs serveur via SSH développé pour automatiser et simplifier la détection d'intrusions (Blue Team). Conçu pour lutter contre la "fatigue des logs", il permet de surveiller un parc de serveurs Linux sans nécessiter l'installation d'agents lourds sur les machines cibles.

## Table des matières
1. [Fonctionnalités Clés](#fonctionnalités-clés)
2. [Architecture et Technologies](#architecture-et-technologies)
3. [Prérequis et Compatibilité](#prérequis-et-compatibilité)
4. [Configuration SSH (Ajout de serveur)](#configuration-ssh-ajout-de-serveur)
5. [Installation et Déploiement](#installation-et-déploiement)
6. [Utilisation](#utilisation)
7. [Simulation d'Attaques](#simulation-dattaques)

---

## Fonctionnalités Clés

* **Surveillance "Agentless"** : Connexion distante sécurisée via SSH sans installation de logiciel sur le serveur cible.
* **Moteur de Détection Multi-Vecteurs** :
    * **Système** : Brute Force SSH, tentatives sur utilisateurs inexistants (*Invalid User*).
    * **Web** : Injections SQL (SQLi), Path Traversal (LFI), Déni de Service (HTTP Flood), Brute Force sur des endpoints spécifiques (ex: `/login`).
* **Threat Intelligence** : Évaluation dynamique de la réputation des adresses IP attaquantes via l'API **[AbuseIPDB](https://www.abuseipdb.com/)**.
* **Tableau de Bord Interactif** : Visualisation claire des menaces qualifiées avec accès aux logs bruts comme preuves techniques.
* **Playbook de Remédiation** : Recommandations techniques intégrées (Fail2ban, configuration SSH) pour contrer les vecteurs d'attaque détectés.

---

## Architecture et Technologies

L'application repose sur une architecture monolithique robuste :
* **Backend** : Python 3 avec le framework Flask.
* **Base de données** : SQLite gérée via Flask-SQLAlchemy.
* **Client Réseau** : Librairie Paramiko pour le protocole SSH et l'extraction des logs.
* **Automatisation** : Flask-APScheduler pour déclencher des analyses à intervalles réguliers.
* **Frontend** : HTML5, Tailwind CSS et Bootstrap Icons pour une interface moderne.

---

## Prérequis et Compatibilité

Pour une analyse correcte, le serveur cible doit respecter les conditions suivantes :
* **Système d'exploitation** : Distribution Linux (Debian / Ubuntu recommandés).
* **Service SSH** : Accessible et configuré.
* **Fichiers de logs requis** :
    * Système : `/var/log/auth.log` (droits de lecture requis via le groupe `adm` ou `sudo`).
    * Web : `/var/log/nginx/access.log` ou `/var/log/apache2/access.log`.

---

## Configuration SSH (Ajout de serveur)

RootView utilise l'authentification par clé publique/privée (RSA ou Ed25519).

### 1. Générer une paire de clés
Ouvrez un terminal et exécutez la commande suivante :
```bash
ssh-keygen -t ed25519 -f ~/.ssh/rootview_key -C "rootview_monitoring"

```

*Laissez la "passphrase" vide pour permettre à l'application de s'y connecter automatiquement.*

### 2. Autoriser la clé sur le serveur cible

```bash
ssh-copy-id -i ~/.ssh/rootview_key.pub utilisateur_cible@adresse_ip_du_serveur

```

### 3. Récupérer la clé privée pour RootView

Affichez la clé privée pour la copier :

```bash
cat ~/.ssh/rootview_key

```

Copiez l'intégralité du texte (incluant les lignes `-----BEGIN ...` et `-----END ...`) pour le coller dans l'interface RootView.

---

## Installation et Déploiement

### 1. Cloner le dépôt

```bash
git clone [https://github.com/NO6B/RootView](https://github.com/NO6B/RootView)
cd RootView

```

### 2. Configurer l'environnement virtuel

```bash
python3 -m venv .venv
source .venv/bin/activate  # Sur Windows: .venv\Scripts\activate
pip install -r requirements.txt

```

### 3. Configuration des variables d'environnement (.env)

Créez un fichier `.env` à la racine du projet :

```env
SECRET_KEY=votre_cle_secrete_aleatoire
api_key=votre_cle_api_abuseipdb

# Seuils de déclenchement des alertes
SEUIL_BRUTE_FORCE_SSH=5
SEUIL_DOS=50
SEUIL_BRUTE_FORCE_WEB=10

```

### 4. Initialiser la base de données et Lancer

```bash
python init_db.py
python run.py

```

L'interface sera accessible à l'adresse : `http://127.0.0.1:5000`

---

## Utilisation

1. **Inscription** : Accédez à `/register` pour créer votre compte administrateur.
2. **Ajouter un serveur** : Naviguez dans la section "Serveurs" et renseignez l'IP, l'utilisateur et la **clé privée**.
3. **Surveillance** : Le planificateur effectue des scans automatiques, mais vous pouvez lancer une analyse immédiate via le Dashboard.

---

## Simulation d'Attaques

Un script de simulation est fourni pour générer du trafic malveillant détectable :

1. Rendez le script exécutable : `chmod +x tests/test_intrusions.sh`.
2. Modifiez la variable `CIBLE` dans le script avec l'IP de votre serveur de test.
3. Exécutez : `./tests/test_intrusions.sh`.

---

*Projet développé dans le cadre d'un portfolio cybersécurité. Usage strictement défensif.*
