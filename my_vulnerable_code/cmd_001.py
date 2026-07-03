import os
import subprocess

def ping_host(hostname):
    cmd = f"ping -c 1 {hostname}"  # Vulnerable: unsanitized input
    result = os.system(cmd)
    return result
