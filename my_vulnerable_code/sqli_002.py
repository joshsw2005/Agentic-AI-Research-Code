import sqlite3

def login_safe(username, password):
    conn = sqlite3.connect('db.sqlite')
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor = conn.execute(query, (username, password))  # Safe: parameterized
    return cursor.fetchone()
