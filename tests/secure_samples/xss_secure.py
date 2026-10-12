# SECURE reference version - autoescaping / explicit escaping.
from markupsafe import escape

def render_greeting(name: str) -> str:
    return f"<div>Welcome, {escape(name)}!</div>"

def render_comment(comment_text: str) -> str:
    return f"<p>{escape(comment_text)}</p>"
