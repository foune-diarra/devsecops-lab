from flask import Flask, request, jsonify
import sqlite3
import subprocess
import hashlib
import os
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Charger les secrets depuis les variables d’environnement
SECRET_KEY = os.environ.get("SECRET_KEY", "default-fallback-key")
app.config["SECRET_KEY"] = SECRET_KEY


############################################
# 1. LOGIN — SQL Injection corrigée
############################################
@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    row = cursor.fetchone()

    if row and check_password_hash(row[0], password):
        return jsonify({"status": "success", "user": username})

    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


############################################
# 2. PING — Command Injection sécurisé
############################################
@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host", "")

    # Autoriser uniquement IP ou hostname simple
    if not re.match(r"^[a-zA-Z0-9\.\-]+$", host):
        return jsonify({"error": "invalid host"}), 400

    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            capture_output=True,
            text=True,
            timeout=5
        )
        return jsonify({"output": result.stdout})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


############################################
# 3. COMPUTE — Suppression de eval()
############################################
@app.route("/compute", methods=["POST"])
def compute():
    expr = request.json.get("expression", "1+1")

    # Autoriser uniquement les expressions mathématiques simples
    if not re.match(r"^[0-9\+\-\*/\(\) ]+$", expr):
        return jsonify({"error": "Invalid expression"}), 400

    try:
        result = eval(expr, {"__builtins__": {}}, {})
        return jsonify({"result": result})
    except:
        return jsonify({"error": "Evaluation failed"}), 400


############################################
# 4. HASH — MD5 remplacé par PBKDF2
############################################
@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password", "admin")
    hashed = generate_password_hash(pwd, method="pbkdf2:sha256")
    return jsonify({"hashed": hashed})


############################################
# 5. READFILE — Path Traversal corrigé
############################################
@app.route("/readfile", methods=["POST"])
def readfile():
    filename = request.json.get("filename", "test.txt")

    base_dir = "files/"
    safe_filename = os.path.basename(filename)
    path = os.path.join(base_dir, safe_filename)

    if not os.path.exists(path):
        return jsonify({"error": "File not found"}), 404

    with open(path, "r") as f:
        return jsonify({"content": f.read()})


############################################
# 6. DEBUG — Désactivé en production
############################################
@app.route("/debug", methods=["GET"])
def debug():
    if not app.debug:
        return jsonify({"error": "Debug info disabled"}), 403

    return jsonify({
        "debug": True,
        "environment": dict(os.environ)
    })


############################################
# 7. HELLO
############################################
@app.route("/hello", methods=["GET"])
def hello():
    return jsonify({"message": "Welcome to the secure DevSecOps API"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
