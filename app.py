from flask import Flask, render_template
from api import api_blueprint
import os

app = Flask(__name__)
app.register_blueprint(api_blueprint)

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    # Port dynamique pour Render
    port = int(os.environ.get("PORT", 5050))
    # Debug False en production
    debug = os.environ.get("FLASK_ENV") != "production"
    app.run(debug=debug, host="0.0.0.0", port=port)
