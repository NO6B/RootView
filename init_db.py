from app import db, creer_application

# sotckage de l'instance de application dans app
app = creer_application()

with app.app_context():
    try:
        db.create_all()
    except Exception as ex:
        print(f"echec de la creation de la db: {ex}")
