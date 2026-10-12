# INTENTIONALLY VULNERABLE - for SecureLens AI test suite only.
# Do not deploy. CWE-89 / OWASP A03:2021.
import sqlite3

def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

def search_products(term):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name LIKE '%" + term + "%'")
    return cursor.fetchall()
