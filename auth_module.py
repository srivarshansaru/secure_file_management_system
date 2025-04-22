
# auth_module.py
users = {}

def register_user(username, password):
    if username in users:
        return False
    users[username] = password
    return True

def authenticate_user(username, password):
    return users.get(username) == password

def generate_static_otp():
    return "123456"

def get_all_users():
    return users
