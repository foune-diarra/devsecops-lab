from flask import Flask, request
import sqlite3
import subprocess
import hashlib
import os

app = Flask(__name__)

SECRET_KEY = "dev-secret-key-12345"  # Hardcoded secret


@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    result = cursor.fetchone()

    if result:
        return {"status": "success", "user": username}

    return {"status": "error", "message": "Invalid credentials"}


@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host", "")
    cmd = f"ping -c 1 {host}"
    #output = subprocess.check_output(cmd, shell=True)
output = subprocess.check_output(
    ["ping", "-c", "1", host],
    stderr=subprocess.STDOUT,
    text=True
)
return {"output": output.decode()}


@app.route("/compute", methods=["POST"])
def compute():
    expression = request.json.get("expression", "1+1")
    result = eval(expression)  # CRITIQUE

    return {"result": result}


@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password", "admin")
# hashed = hashlib.md5(pwd.encode()).hexdigest()
salt = bcrypt.gensalt()
hashed = bcrypt.hashpwd(pwd.encode(), salt)
return {"md5": hashed}


@app.route("/readfile", methods=["POST"])
def readfile():
    filename = request.json.get("filename", "test.txt")

    with open(filename, "r") as f:
        content = f.read()

    return {"content": content}


@app.route("/debug", methods=["GET"])
def debug():
    # Renvoie des détails sensibles -> mauvaise pratique
    return {
        "debug": True,
        "secret_key": SECRET_KEY,
        "environment": dict(os.environ)
    }


@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Welcome to the DevSecOps vulnerable API"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
from flask import Flask, request, render_template, session, redirect
import os
import secrets

app = Flask(__name__)
app.secret_key = "dev-secret"  # En production → variable d'environnement

# Generation d'un token CSRF et stockage en session
def generate_csrf_token():
    token = secrets.token_hex(16)    # token aléatoire
    session["csrf_token"] = token
    return token
@app.route("/")
def index():
    token = generate_csrf_token()    # On génère un token
    return render_template("form.html", csrf_token=token)

@app.route("/submit", methods=["POST"])  # CORRECTION : methods=["POST"]
def submit():
    form_token = request.form.get("csrf_token")
    session_token = session.get("csrf_token")
    # Verification
    if not form_token or form_token != session_token:
        return "Échec CSRF - requête invalide."
    message = request.form.get("message")
    return f"Requête acceptée. Message reçu : {message}"

if __name__ == "__main__":
    app.run(debug=True)
if "csrf_token" not in session:
    session["csrf_token"] = secrets.token_hex(16)
from flask import Flask, request
import hashlib
import subprocess
app = Flask(__name__)
# Mot de passe en dur (mauvaise pratique)
ADMIN_PASSWORD = "123456"
# Cryptographie faible (MD5)
def hash_password(password):
return hashlib.md5(password.encode()).hexdigest()
@app.route("/login")
def login():
username = request.args.get("username")
password = request.args.get("password")
# Authentification faible
if username == "admin" and hash_password(password) ==
hash_password(ADMIN_PASSWORD):
return "Logged in"
return "Invalid credentials"
@app.route("/ping")
def ping():
host = request.args.get("host", "localhost")
# Injection de commande (shell=True)
result = subprocess.check_output(
f"ping -c 1 {host}",
shell=True
)
return result
@app.route("/hello")
def hello():
name = request.args.get("name", "user")
# XSS potentiel
return f"<h1>Hello {name}</h1>"
if __name__ == "__main__":

# Debug activé
app.run(debug=True)

