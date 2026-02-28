---

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
* **Système** : Brute Force SSH, Utilisation d'utilisateurs invalides (Invalid User).
* **Web** : Injections SQL (SQLi), Path Traversal (LFI), Déni de Service (HTTP Flood), Brute Force sur des endpoints spécifiques (ex: `/login`).


* **Threat Intelligence** : Évaluation dynamique de la réputation des adresses IP attaquantes via l'API **AbuseIPDB**.
* **Tableau de Bord Interactif** : Visualisation claire des menaces qualifiées, avec accès aux logs bruts (preuves) et mise en évidence des IP listées.
* **Playbook de Remédiation** : Recommandations techniques intégrées (Fail2ban, configuration SSH, requêtes préparées) pour contrer les vecteurs d'attaque détectés.

---

## Architecture et Technologies

L'application repose sur une architecture monolithique robuste :

* **Backend** : Python 3 avec le framework Web Flask.
* **Base de données** : SQLite (gérée via Flask-SQLAlchemy).
* **Client Réseau** : Paramiko pour la gestion du protocole SSH et l'extraction des logs.
* **Automatisation** : Flask-APScheduler pour déclencher des analyses globales à intervalles réguliers.
* **Frontend** : HTML5, Tailwind CSS, et Bootstrap Icons pour une interface moderne et responsive.

---

## Prérequis et Compatibilité

Pour que RootView puisse analyser correctement un serveur cible, ce dernier doit respecter les conditions suivantes :

* **Système d'exploitation** : Distribution Linux (Debian / Ubuntu recommandés).
* **Service SSH** : Accessible et configuré.
* **Fichiers de logs requis** :
* Pour les attaques système : `/var/log/auth.log`. Le compte utilisé doit avoir les droits de lecture sur ce fichier (idéalement via `sudo` sans mot de passe pour la commande `tail`).
* Pour les attaques Web : `/var/log/nginx/access.log` ou `/var/log/apache2/access.log`.



---

## Configuration SSH (Ajout de serveur)

RootView utilise l'authentification par clé publique/privée pour se connecter à vos serveurs de manière sécurisée. La librairie réseau (Paramiko) supporte les clés au format **RSA** ou **Ed25519**.

Voici la procédure complète pour préparer un serveur cible et récupérer la clé privée nécessaire à l'interface RootView :

### 1. Générer une paire de clés (sur votre machine locale ou le serveur hébergeant RootView)

Ouvrez un terminal et exécutez la commande suivante pour créer une clé hautement sécurisée (Ed25519) :

```bash
ssh-keygen -t ed25519 -f ~/.ssh/rootview_key -C "rootview_monitoring"

```

*Laissez la "passphrase" (mot de passe) vide pour permettre à l'application de s'y connecter automatiquement.*

### 2. Autoriser la clé sur le serveur cible

Copiez la clé **publique** vers le serveur que vous souhaitez surveiller :

```bash
ssh-copy-id -i ~/.ssh/rootview_key.pub utilisateur_cible@adresse_ip_du_serveur

```


### 3. Récupérer la clé privée pour RootView

RootView a besoin de la clé **privée** pour s'authentifier. Affichez-la avec cette commande :

```bash
cat ~/.ssh/rootview_key

```

Copiez l'intégralité du texte affiché, incluant les lignes `-----BEGIN OPENSSH PRIVATE KEY-----` et `-----END OPENSSH PRIVATE KEY-----`. C'est cette valeur qu'il faudra coller dans le champ "Clé privée" lors de l'ajout du serveur dans le tableau de bord.

---

## ⚙️ Installation et Déploiement

### 1. Cloner le dépôt

```bash
git clone <URL_DU_DEPOT>
cd rootview

```

### 2. Configurer l'environnement virtuel

Il est recommandé d'isoler les dépendances du projet :

```bash
python3 -m venv .venv
source .venv/bin/activate  # Sur Windows: .venv\Scripts\activate
pip install -r requirements.txt

```

### 3. Configuration des variables d'environnement

Créez un fichier `.env` à la racine du projet et ajoutez-y les paramètres suivants :

```env
SECRET_KEY=votre_cle_secrete_aleatoire_et_robuste
api_key=votre_cle_api_abuseipdb_ici

# Seuils de déclenchement des alertes
SEUIL_BRUTE_FORCE_SSH=5
SEUIL_DOS=50
SEUIL_BRUTE_FORCE_WEB=10

```

*(Note : Vous pouvez obtenir une clé API gratuite en créant un compte sur [AbuseIPDB](https://www.google.com/search?q=https://www.abuseipdb.com/).)*

### 4. Initialiser la base de données

Cette commande va créer le fichier `rootview.db` et les tables nécessaires (Utilisateur, Serveur, Alerte, CacheIP) :

```bash
python init_db.py

```

### 5. Lancer l'application

```bash
python run.py

```

L'interface sera accessible à l'adresse : `http://127.0.0.1:5000`

---

## Utilisation

1. **Inscription et Connexion** : Accédez à la plateforme et créez votre premier compte administrateur robuste (minimum 8 caractères, majuscule, chiffre, caractère spécial).
2. **Ajouter un serveur** : Naviguez dans la section "Serveurs" et cliquez sur "Nouveau serveur". Renseignez :
* Le nom d'usage (ex: *Serveur Prod*).
* L'adresse IP.
* L'utilisateur SSH (ex: *ubuntu* ou *root*).
* L'endpoint Web à surveiller (ex: `/login` ou `/wp-admin`).
* La **clé privée** générée lors de la configuration SSH.


3. **Surveillance** : Le planificateur tourne en tâche de fond (toutes les 5 minutes). Vous pouvez également déclencher une analyse manuelle en cliquant sur "Lancer l'analyse" depuis le Dashboard.

---

## Simulation d'Attaques

Pour vérifier le bon fonctionnement de RootView et faire une démonstration active de ses capacités, un script de simulation est fourni. Il génère un trafic malveillant détectable par le moteur d'analyse.

1. Rendez le script exécutable :

```bash
chmod +x tests/test_intrusions.sh

```

2. Éditez le fichier `test_intrusions.sh` pour y insérer l'adresse IP de votre serveur cible (variable `CIBLE`).
3. Exécutez le script depuis une machine distante :

```bash
./tests/test_intrusions.sh

```

4. Retournez sur le tableau de bord RootView et lancez une analyse pour visualiser l'apparition des nouvelles alertes (Brute Force, SQLi, Path Traversal, etc.).

---

*Projet développé dans le cadre d'un portfolio cybersécurité. Usage strictement défensif.*

---
