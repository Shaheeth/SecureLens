# INTENTIONALLY VULNERABLE - CWE-918 / OWASP A10:2021.
import requests

def fetch_avatar(url):
    response = requests.get(url)
    return response.content

def proxy_request(target_url):
    return requests.post(target_url, data={"ping": "pong"})
