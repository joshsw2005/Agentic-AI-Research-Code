import os
import sqlite3
import pickle
import hashlib
import random
import tempfile
import subprocess
import re
import json
from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

# ==========================================================
# Vulnerability 1: Hardcoded Secret (CWE-798)
# ==========================================================

API_KEY = "SUPER_SECRET_API_KEY_12345"
DB_PASSWORD = "AdminPassword123"


# ==========================================================
# Vulnerability 2: Weak Password Hashing (CWE-328)
# ==========================================================

def hash_password(password):
    salt = os.urandom(16)
    return hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=32).hex() + ':' + salt.hex()


# ==========================================================
# Vulnerability 3: Predictable Random Values (CWE-330)
# ==========================================================

def generate_reset_code():
    return str(random.randint(100000, 999999))


# ==========================================================
# Vulnerability 4: SQL Injection (CWE-89)
# ==========================================================

@app.route("/user")
def get_user():
    username = request.args.get("username")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))

    result = cursor.fetchall()

    conn.close()

    return str(result)


# ==========================================================
# Vulnerability 5: Command Injection (CWE-78)
# ==========================================================

@app.route("/ping")
def ping():
    host = request.args.get("host")

    # Validate host input against safe pattern
    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        return "Invalid host", 400

    try:
        subprocess.run(['ping', '-c', '1', host], check=True, timeout=5)
    except Exception:
        return "Ping failed", 500

    return "done"


# ==========================================================
# Vulnerability 6: Path Traversal (CWE-22)
# ==========================================================

@app.route("/read")
def read_file():
    filename = request.args.get("file")

    # Sanitize filename and prevent path traversal
    safe_filename = secure_filename(filename)
    if not safe_filename:
        return "Invalid filename", 400

    # Construct and validate full path
    base_dir = os.path.abspath("uploads")
    full_path = os.path.abspath(os.path.join(base_dir, safe_filename))

    if not full_path.startswith(base_dir + os.sep):
        return "Access denied", 403

    try:
        with open(full_path, "r") as f:
            return f.read()
    except FileNotFoundError:
        return "File not found", 404


# ==========================================================
# Vulnerability 7: Unsafe Deserialization (CWE-502)
# ==========================================================

@app.route("/deserialize", methods=["POST"])
def deserialize():
    data = request.data

    try:
        obj = json.loads(data.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "Invalid data", 400

    return str(obj)


# ==========================================================
# Vulnerability 8: Insecure Temporary File (CWE-377)
# ==========================================================

def create_temp():
    fd, temp_name = tempfile.mkstemp()

    try:
        with os.fdopen(fd, 'w') as f:
            f.write("temporary data")
    except Exception:
        os.unlink(temp_name)
        raise

    return temp_name


if __name__ == "__main__":
    app.run(debug=False)