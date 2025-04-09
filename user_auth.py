import hashlib
import json
import os

# --- Hashing function (SHA-256) ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --- Load users from users.json ---
def load_users():
    if not os.path.exists("users.json"):
        return {}
    with open("users.json", "r") as f:
        return json.load(f)

# --- Save users to users.json ---
def save_users(users):
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)

# --- Register a new user ---
def register_user(username, password, security_answer):
    users = load_users()
    if username in users:
        return False  # User already exists
    users[username] = {
        "password": hash_password(password),
        "security_answer": hash_password(security_answer)
    }
    save_users(users)
    return True

# --- Authenticate login ---
def authenticate_user(username, password):
    users = load_users()
    hashed = hash_password(password)
    return username in users and users[username]["password"] == hashed

# --- Validate security answer for forgot password ---
def validate_security_answer(username, answer):
    users = load_users()
    hashed_answer = hash_password(answer)
    return username in users and users[username]["security_answer"] == hashed_answer

# --- Reset the password ---
def reset_password(username, new_password):
    users = load_users()
    if username not in users:
        return False
    users[username]["password"] = hash_password(new_password)
    save_users(users)
    return True
