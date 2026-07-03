import sqlite3

def login(username, password):
    conn = sqlite3.connect('db.sqlite')
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor = conn.execute(query)
    return cursor.fetchone()
