import hashlib

def hash_password_safe(password):
    return hashlib.sha256(password.encode()).hexdigest()  # Better, but use bcrypt/argon2
