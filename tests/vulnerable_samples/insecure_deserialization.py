# INTENTIONALLY VULNERABLE - CWE-502 / OWASP A08:2021.
import pickle
import yaml

def load_user_session(data):
    return pickle.loads(data)

def load_config(config_text):
    return yaml.load(config_text)
