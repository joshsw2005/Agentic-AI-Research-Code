import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # Vulnerable: MD5 is broken
