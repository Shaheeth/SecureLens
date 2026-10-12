# INTENTIONALLY VULNERABLE - CWE-287/306 / OWASP A07:2021.
def login(username, password):
    if password == "admin123":
        return {"status": "ok", "role": "admin"}
    return {"status": "denied"}

def run_app(app):
    app.run(debug=True, host="0.0.0.0")
