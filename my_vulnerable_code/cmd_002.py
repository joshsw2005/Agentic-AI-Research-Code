import subprocess

def ping_host_safe(hostname):
    result = subprocess.run(["ping", "-c", "1", hostname], capture_output=True)  # Safe: list form
    return result.returncode
