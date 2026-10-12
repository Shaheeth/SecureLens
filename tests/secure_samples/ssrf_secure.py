# SECURE reference version - allow-listed destinations.
import ipaddress
from urllib.parse import urlparse
import requests

ALLOWED_HOSTS = {"trusted-cdn.example.com"}

def _is_allowed(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        return False
    try:
        ip = ipaddress.ip_address(parsed.hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return False
    except ValueError:
        pass  # hostname, not a literal IP — allow-list check above already applied
    return True

def fetch_avatar(url: str):
    if not _is_allowed(url):
        raise ValueError("URL not permitted")
    response = requests.get(url, allow_redirects=False, timeout=5)
    return response.content
