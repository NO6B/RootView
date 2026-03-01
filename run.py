from app import creer_application

app = creer_application()

if __name__ == "__main__":
    app.run(debug=False, port=5000)
