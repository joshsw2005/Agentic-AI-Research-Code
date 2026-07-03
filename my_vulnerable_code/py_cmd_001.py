import os

def ping_host(hostname):
    cmd = f"ping -c 1 {hostname}"
    result = os.system(cmd)
    return result
