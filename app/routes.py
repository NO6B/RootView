from flask import Blueprint, render_template, redirect, url_for, request
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from app import db
from app.models import Utilisateur, Alerte, Serveur
from app.scanner import scan


bp = Blueprint("main", __name__)

# AUTHENTIFICATION

@bp.route("/register", methods=["GET", "POST"])
def inscription():
    """
    Crée un nouveau compte utilisateur.
    
    - Vérifie la validité et l'unicité de l'identifiant.
    - Sécurise le mot de passe via hachage.
    - Redirige vers la connexion si succès, sinon réaffiche le formulaire.
    """
    if current_user.is_authenticated:
        return redirect(url_for("main.tableau_de_bord"))

    if request.method == "POST":
        nom = request.form.get("username")
        mdp = request.form.get("password")

        if not nom or not mdp:
            return render_template("register.html")

        utilisateur_existant = Utilisateur.query.filter_by(nom_utilisateur=nom).first()
        if utilisateur_existant:
            return render_template("register.html")

        try:
            # Création avec la méthode pbkdf2:sha256
            nouveau_membre = Utilisateur(
                nom_utilisateur=nom,
                mot_de_passe_hash=generate_password_hash(mdp, method='pbkdf2:sha256')
            )
            db.session.add(nouveau_membre)
            db.session.commit()
            return redirect(url_for("main.connexion"))
        except Exception as e:
            db.session.rollback()
            print(f"DEBUG SQL: {e}")

    return render_template("register.html")

@bp.route("/")
@bp.route("/login", methods=["GET", "POST"])
def connexion():
    """
    Gère l'authentification des utilisateurs.

    Vérifie les identifiants soumis via le formulaire de connexion. En cas de succès,
    établit une session pour l'utilisateur.

    Arguments:
        Aucun (récupère les données via 'request.form').

    Retourne:
        Redirection vers le tableau de bord si succès, sinon réaffiche la page de login.
    """
    if current_user.is_authenticated:
        return redirect(url_for("main.tableau_de_bord"))

    if request.method == "POST":
        nom_utilisateur = request.form.get("username")
        mot_de_passe = request.form.get("password")
        
        utilisateur = Utilisateur.query.filter_by(nom_utilisateur=nom_utilisateur).first()

        if utilisateur and check_password_hash(utilisateur.mot_de_passe_hash, mot_de_passe):
            login_user(utilisateur)
            return redirect(url_for("main.tableau_de_bord"))

    return render_template("login.html")

@bp.route("/logout")
@login_required
def deconnexion():
    """
    Déconnecte l'utilisateur actuel.

    Termine la session Flask-Login et redirige vers la page de connexion.

    Retourne:
        Redirection vers la route de connexion.
    """
    logout_user()
    return redirect(url_for("main.connexion"))


# SECTION TABLEAU DE BORD ET STATISTIQUES

@bp.route("/dashboard")
@login_required
def tableau_de_bord():
    """
    Génère les statistiques consolidées des alertes pour l'utilisateur.

    Récupère les serveurs de l'utilisateur, extrait les alertes associées,
    et les regroupe par couple (IP source, Serveur) en utilisant une clé composite.

    Retourne:
        Le template HTML du tableau de bord avec les bilans d'attaques formatés.
    """
    mes_serveurs = Serveur.query.filter_by(id_utilisateur=current_user.id).all()
    
    ids_serveurs = []
    noms_serveurs = {}
    for s in mes_serveurs:
        ids_serveurs.append(s.id)
        noms_serveurs[s.id] = s.nom

    if not ids_serveurs:
        return render_template("dashboard.html", stats_attaques=[], noms_serveurs={})

    # Récupération des alertes
    alertes_brutes = Alerte.query.filter(Alerte.id_serveur.in_(ids_serveurs)).all()

    # Regrouper les statistiques par IP
    dict_stats = {}
    for alerte in alertes_brutes:
        # configuration de la cle d'acces a un dict
        cle_ip_serveur = (alerte.ip_source, alerte.id_serveur)
        
        if cle_ip_serveur not in dict_stats:
            dict_stats[cle_ip_serveur] = {
                'ip_source': alerte.ip_source,
                'id_serveur': alerte.id_serveur,
                'types_detectes': set(),
                'nb_essais': 0,
                'derniere_tentative': alerte.date_heure,
                'est_dangereuse': alerte.ip_liste

            }
        
        dict_stats[cle_ip_serveur]['types_detectes'].add(alerte.type)
        dict_stats[cle_ip_serveur]['nb_essais'] += 1

        if alerte.ip_liste:
            dict_stats[cle_ip_serveur]['est_dangereuse'] = True

        # Mise à jour des compteurs et des types d'attaques
        if alerte.date_heure > dict_stats[cle_ip_serveur]['derniere_tentative']:
            dict_stats[cle_ip_serveur]['derniere_tentative'] = alerte.date_heure

    stats_attaques = sorted(
        list(dict_stats.values()), 
        key=lambda x: x['derniere_tentative'], 
        reverse=True
    )

    for info in stats_attaques:
        info['type_alerte'] = ", ".join(info['types_detectes'])

    return render_template(
        "dashboard.html",
        stats_attaques=stats_attaques,
        noms_serveurs=noms_serveurs
    )

@bp.route("/servers", methods=["GET", "POST"])
@login_required
def gestion_serveurs():
    """
    Affiche la liste des serveurs et gère l'ajout de nouvelles machines.

    Méthode POST : Valide et enregistre un nouveau serveur en base de données.
    Méthode GET : Récupère la liste complète des serveurs de l'utilisateur.

    Retourne:
        Template 'servers.html' avec la liste mise à jour des serveurs.
    """
    if request.method == "POST":
        nom = request.form.get("nom")
        ip = request.form.get("ip")
        user_ssh = request.form.get("user_ssh")
        key_ssh = request.form.get("key_ssh")
        

        try:
                # Création de l'objet Serveur
                nouveau_serveur = Serveur(
                    nom=nom,
                    adresse_ip=ip,
                    utilisateur_ssh=user_ssh,
                    clef_ssh=key_ssh,
                    id_utilisateur=current_user.id
                )
                
                db.session.add(nouveau_serveur)
                db.session.commit()
        except Exception as e:
                db.session.rollback()
            
        return redirect(url_for("main.gestion_serveurs"))

    # affichage liste de serveurs
    liste_serveurs = Serveur.query.filter_by(id_utilisateur=current_user.id).all()
    return render_template("servers.html", serveurs=liste_serveurs)



@bp.route("/servers/delete/<int:id_serveur>", methods=["POST"])
@login_required
def supprimer_serveur(id_serveur):
    """
    Supprime un serveur et toutes les alertes qui lui sont rattachées.

    Vérifie la propriété du serveur avant toute action pour garantir la sécurité.

    Arguments:
        id_serveur (int): L'identifiant unique du serveur à supprimer.

    Retourne:
        Redirection vers la liste des serveurs.
    """
    serveur_a_supprimer = Serveur.query.get_or_404(id_serveur)
    
    # vérification que le serveur appartient à l'utilisateur connecté
    if serveur_a_supprimer.id_utilisateur != current_user.id:
        return redirect(url_for('main.gestion_serveurs'))

    try:
        Alerte.query.filter_by(id_serveur=id_serveur).delete()
        
        db.session.delete(serveur_a_supprimer)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Erreur technique : {e}")
    
    # redirection vers la liste des serveurs
    return redirect(url_for('main.gestion_serveurs'))


@bp.route("/scan/run", methods=["POST"])
@login_required
def lancer_scan():
    """
    Déclenche manuellement le processus de scan uniquement pour les serveurs
    appartenant à l'utilisateur connecté (Autorisation).
    """
    try:
        mes_serveurs = Serveur.query.filter_by(id_utilisateur=current_user.id).all()
        
        for serveur in mes_serveurs:
            scan(serveur.id)
            
    except Exception as e:
        print(f"Erreur lors du scan manuel : {e}")
        
    return redirect(url_for("main.tableau_de_bord"))


@bp.route("/details/<ip>")
@login_required
def details_attaques_ip(ip):
    """
    Affiche l'historique complet des alertes pour une adresse IP spécifique.

    Filtre les alertes pour qu'elles correspondent uniquement aux serveurs
    appartenant à l'utilisateur connecté.

    Arguments:
        ip (str): L'adresse IP source dont on souhaite voir les détails.

    Retourne:
        Le template 'details_ip.html' avec la liste chronologique des alertes.
    """
    mes_serveurs = Serveur.query.filter_by(id_utilisateur=current_user.id).all()
    ids = []
    for s in mes_serveurs:
        ids.append(s.id)
    
    # Recuperation des logs détaillés d'une ip
    alertes_details = Alerte.query.filter(
        Alerte.ip_source == ip,
        Alerte.id_serveur.in_(ids)
    ).order_by(Alerte.date_heure.desc()).all()

    return render_template("details_ip.html", ip=ip, alertes=alertes_details)

