def check_password(user_input, stored_hash):
    if user_input == stored_hash:
        return True
    return False
