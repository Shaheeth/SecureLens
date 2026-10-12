# INTENTIONALLY VULNERABLE - CWE-78 / OWASP A03:2021.
import os
import subprocess

def ping_host(host):
    os.system("ping -c 1 " + host)

def run_backup(filename):
    subprocess.call(f"tar -czf backup.tar.gz {filename}", shell=True)
