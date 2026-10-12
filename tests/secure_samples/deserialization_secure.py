# SECURE reference version - JSON + safe YAML loading.
import json
import yaml

def load_user_session(data: str):
    return json.loads(data)

def load_config(config_text: str):
    return yaml.safe_load(config_text)
