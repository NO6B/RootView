from flask import Blueprint

# Instancie un objet Blueprint (un module de routes indépendant)
bp = Blueprint('main', __name__)

@bp.route('/')
def home():
    return "Test serveur"