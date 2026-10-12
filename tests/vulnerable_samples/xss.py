# INTENTIONALLY VULNERABLE - CWE-79 / OWASP A03:2021.
def render_greeting(name):
    return f"<div>Welcome, {name}!</div>"

def render_comment(comment_text):
    html = "<p>" + comment_text + "</p>"
    return html
