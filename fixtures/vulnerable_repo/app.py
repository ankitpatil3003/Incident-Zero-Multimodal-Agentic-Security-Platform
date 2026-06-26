# Intentionally vulnerable Python file for CodeScan testing.
# DO NOT use any of these patterns in real code.

import hashlib

# Hardcoded secret
API_KEY = "sk-abc123456789012345678901234567890"
password = "SuperSecretPassword123!"

# SQL injection via f-string
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

# SQL injection via .format()
def search_users(name):
    query = "SELECT * FROM users WHERE name = '{}'".format(name)
    return query

# Weak cryptography
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def hash_token(token):
    return hashlib.sha1(token.encode()).hexdigest()

# Safe code — should NOT trigger
def safe_function():
    x = 42
    return x + 1
