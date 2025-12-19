from flask import Flask, render_template
from api import api_blueprint
import os

app = Flask(__name__)
app.register_blueprint(api_blueprint)

@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    # En dev : port 5050
    # En prod : port fourni par l'hébergeur
    port = int(os.environ.get("PORT", 5050))
    app.run(debug=False, host="0.0.0.0", port=port)
