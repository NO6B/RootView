from flask import Blueprint, render_template, redirect, url_for, request
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from app import db
from app.models import Utilisateur, Alerte, Serveur
from app.scanner import scan


bp = Blueprint("main", __name__)

@bp.route("/register", methods=["GET", "POST"])
def inscription():
    """
    Gère la création de nouveaux comptes utilisateurs.
    
    Vérifie l'absence de doublons dans la base de données et procède au hachage 
    du mot de passe via l'algorithme PBKDF2 avant l'insertion.
    
    Returns:
        Response: Redirection vers la page de connexion ou rendu du formulaire d'inscription.
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
            nouveau_membre = Utilisateur(
                nom_utilisateur=nom,
                mot_de_passe_hash=generate_password_hash(mdp, method='pbkdf2:sha256')
            )
            db.session.add(nouveau_membre)
            db.session.commit()
            return redirect(url_for("main.connexion"))
        except Exception as e:
            db.session.rollback()
            print(f"Error: {e}")

    return render_template("register.html")




@bp.route("/")
@bp.route("/login", methods=["GET", "POST"])
def connexion():
    """
    Authentifie un utilisateur et initialise la session de navigation.
    
    Vérifie la correspondance entre le pseudonyme et le hash du mot de passe.
    Utilise Flask-Login pour la gestion de l'état de connexion.
    
    Returns:
        Response: Redirection vers le tableau de bord ou rendu de la page de login.
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
    Clôture la session active de l'utilisateur courant.
    
    Returns:
        Response: Redirection vers la page de connexion.
    """
    logout_user()
    return redirect(url_for("main.connexion"))





@bp.route("/dashboard")
@login_required
def tableau_de_bord():
    """
    Récupère et affiche la synthèse des menaces détectées pour l'utilisateur.
    
    Requête la base de données pour obtenir les serveurs du propriétaire et
    les alertes associées, classées de la plus récente à la plus ancienne.
    
    Returns:
        render_template: Page HTML injectée avec la liste des alertes et serveurs.
    """
    mes_serveurs = Serveur.query.filter_by(id_utilisateur=current_user.id).all()
    ids_serveurs = [s.id for s in mes_serveurs]
    noms_serveurs = {s.id: s.nom for s in mes_serveurs}

    if not ids_serveurs:
        return render_template("dashboard.html", alertes=[], noms_serveurs={}, total_infractions=0)

    # Récupération de toutes les alertes
    alertes_brutes = Alerte.query.filter(
        Alerte.id_serveur.in_(ids_serveurs)
    ).order_by(Alerte.date_heure.desc()).all()

    total_infractions = len(alertes_brutes)

    return render_template(
        "dashboard.html",
        alertes=alertes_brutes,
        noms_serveurs=noms_serveurs,
        total_infractions=total_infractions
    )




@bp.route("/servers", methods=["GET", "POST"])
@login_required
def gestion_serveurs():
    """
    Permet l'enregistrement de nouveaux serveurs distants.
    
    Enregistre les paramètres de connexion (IP, Utilisateur SSH, Clé) nécessaires
    au fonctionnement futur du module de scan.
    
    Returns:
        render_template: Page de gestion des serveurs avec la liste des machines actuelles.
    """
    if request.method == "POST":
        nom = request.form.get("nom")
        ip = request.form.get("ip")
        user_ssh = request.form.get("user_ssh")
        key_ssh = request.form.get("key_ssh")
        
        try:
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

    liste_serveurs = Serveur.query.filter_by(id_utilisateur=current_user.id).all()
    return render_template("servers.html", serveurs=liste_serveurs)




@bp.route("/servers/delete/<int:id_serveur>", methods=["POST"])
@login_required
def supprimer_serveur(id_serveur):
    """
    Supprime définitivement un serveur et purge ses données d'alertes associées.
    
    Vérifie les droits de propriété avant d'effectuer la suppression en cascade 
    pour maintenir l'intégrité de la base de données.
    
    Args:
        id_serveur (int): L'identifiant du serveur à supprimer.
        
    Returns:
        Response: Redirection vers la page de gestion des serveurs.
    """
    serveur_a_supprimer = Serveur.query.get_or_404(id_serveur)
    
    if serveur_a_supprimer.id_utilisateur != current_user.id:
        return redirect(url_for('main.gestion_serveurs'))

    try:
        Alerte.query.filter_by(id_serveur=id_serveur).delete()
        db.session.delete(serveur_a_supprimer)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Erreur technique : {e}")
    
    return redirect(url_for('main.gestion_serveurs'))




@bp.route("/scan/run", methods=["POST"])
@login_required
def lancer_scan():
    """
    Déclenche manuellement l'analyse de sécurité sur tout le serveur de l'utilisateur.
    
    Boucle sur chaque serveur enregistré et appelle le moteur de scan pour 
    mettre à jour la base de données d'alertes.
    
    Returns:
        Response: Redirection vers le tableau de bord une fois le scan terminé.
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
    Affiche l'historique exhaustif des attaques provenant d'une adresse IP spécifique.
    
    Args:
        ip (str): L'adresse IP dont on souhaite consulter l'historique d'infractions.
        
    Returns:
        render_template: Page de détails filtrée par adresse IP source.
    """
    mes_serveurs = Serveur.query.filter_by(id_utilisateur=current_user.id).all()
    ids = [s.id for s in mes_serveurs]
    
    alertes_details = Alerte.query.filter(
        Alerte.ip_source == ip,
        Alerte.id_serveur.in_(ids)
    ).order_by(Alerte.date_heure.desc()).all()

    return render_template("details_ip.html", ip=ip, alertes=alertes_details)