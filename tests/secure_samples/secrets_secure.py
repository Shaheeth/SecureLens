# SECURE reference version - secrets loaded from environment.
import os

DATABASE_PASSWORD = os.environ["DATABASE_PASSWORD"]
API_KEY = os.environ["API_KEY"]
JWT_SECRET = os.environ["JWT_SECRET"]

def connect():
    return f"postgresql://admin:{DATABASE_PASSWORD}@localhost/db"
