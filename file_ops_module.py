
import os, time

permissions = {}

def encrypt_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    encrypted_path = file_path + ".enc"
    with open(encrypted_path, 'wb') as f:
        f.write(data[::-1])
    return encrypted_path

def decrypt_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    if file_path.endswith(".enc"):
        output = file_path.replace(".enc", "_decrypted")
        with open(output, 'wb') as f:
            f.write(data[::-1])
        return output
    return None

def get_file_metadata(file_path):
    stats = os.stat(file_path)
    return {
        "name": os.path.basename(file_path),
        "size": stats.st_size,
        "creator": "unknown",
        "created": time.ctime(stats.st_ctime),
        "modified": time.ctime(stats.st_mtime)
    }

def validate_input(file_path):
    return len(file_path) < 255

def detect_malware(file_path):
    return False

def log_threat(user, file_path, reason):
    print(f"[THREAT] {user} -> {file_path} : {reason}")

# Access Control
def set_initial_permissions(file_path, user):
    permissions[file_path] = {"read": [user], "write": [user]}

def get_permissions(file_path):
    return permissions.get(file_path, {"read": [], "write": []})

def add_permission(file_path, user, perm):
    perms = permissions.setdefault(file_path, {"read": [], "write": []})
    if user not in perms[perm]:
        perms[perm].append(user)

def remove_permission(file_path, user, perm):
    if user in permissions.get(file_path, {}).get(perm, []):
        permissions[file_path][perm].remove(user)

def has_permission(file_path, user, perm):
    return user in permissions.get(file_path, {}).get(perm, [])