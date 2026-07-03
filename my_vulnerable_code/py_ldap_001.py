import ldap

def search_user(username):
    filter_str = f"(uid={username})"
    result = ldap.search_s('cn=admin,dc=example,dc=com', ldap.SCOPE_SUBTREE, filter_str)
    return result
