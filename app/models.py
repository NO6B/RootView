from app import db


class Utilisateur(db.Model):
    __tablename__ = "Utilisateur"
    id = db.Column(db.Integer, primary_key=True)
    nom_utilisateur = db.Column(db.String(30), unique=True, nullable=False)
    mot_de_passe_hash = db.Column(db.String(255), nullable=False)

    serveurs = db.relationship("Serveur", backref="proprietaire", lazy=True)


class Serveur(db.Model):
    __tablename__ = "Serveur"
    id = db.Column(db.Integer, primary_key=True)
    id_utilisateur = db.Column(
        db.Integer, db.ForeignKey("Utilisateur.id"), nullable=False
    )
    nom = db.Column(db.String(30), nullable=False)
    adresse_ip = db.Column(db.String(100), nullable=False)
    utilisateur_ssh = db.Column(db.String(100), nullable=False)
    clef_ssh = db.Column(db.Text)

    alertes = db.relationship("Alerte", backref="serveur_cible", lazy=True)


class Alerte(db.Model):
    __tablename__ = "Alerte"
    id = db.Column(db.Integer, primary_key=True)
    id_serveur = db.Column(db.Integer, db.ForeignKey("Serveur.id"), nullable=False)
    type = db.Column(db.String(40), nullable=False)
    ip_source = db.Column(db.String(100))
    ip_liste = db.Column(db.Boolean)
    log_brut = db.Column(db.Text)
    date_heure = db.Column(db.DateTime, nullable=False)
