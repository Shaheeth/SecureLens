# SECURE reference version - no shell interpolation.
import subprocess

def ping_host(host: str):
    # host should additionally be validated against an allow-list/regex
    subprocess.run(["ping", "-c", "1", host], shell=False, check=True)

def run_backup(filename: str):
    subprocess.run(["tar", "-czf", "backup.tar.gz", filename], shell=False, check=True)
