import os
import sqlite3
import pickle
import hashlib
import random
import tempfile
from flask import Flask, request

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
    return hashlib.md5(password.encode()).hexdigest()


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

    query = (
        "SELECT * FROM users "
        "WHERE username = '" + username + "'"
    )

    cursor.execute(query)

    result = cursor.fetchall()

    conn.close()

    return str(result)


# ==========================================================
# Vulnerability 5: Command Injection (CWE-78)
# ==========================================================

@app.route("/ping")
def ping():
    host = request.args.get("host")

    os.system("ping -c 1 " + host)

    return "done"


# ==========================================================
# Vulnerability 6: Path Traversal (CWE-22)
# ==========================================================

@app.route("/read")
def read_file():
    filename = request.args.get("file")

    with open("uploads/" + filename, "r") as f:
        return f.read()


# ==========================================================
# Vulnerability 7: Unsafe Deserialization (CWE-502)
# ==========================================================

@app.route("/deserialize", methods=["POST"])
def deserialize():
    data = request.data

    obj = pickle.loads(data)

    return str(obj)


# ==========================================================
# Vulnerability 8: Insecure Temporary File (CWE-377)
# ==========================================================

def create_temp():
    temp_name = tempfile.mktemp()

    with open(temp_name, "w") as f:
        f.write("temporary data")

    return temp_name


if __name__ == "__main__":
    app.run(debug=True)