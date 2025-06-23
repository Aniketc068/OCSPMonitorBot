from imports import *
from config import BLOCKED_USERS_FILE

def load_blocked_users():
    if not os.path.exists(BLOCKED_USERS_FILE):
        return set()
    with open(BLOCKED_USERS_FILE, "r") as f:
        try:
            data = json.load(f)
            return set(data)
        except json.JSONDecodeError:
            return set()

def block_user(user_id):
    users = load_blocked_users()
    users.add(user_id)
    with open(BLOCKED_USERS_FILE, "w") as f:
        json.dump(list(users), f, indent=2)

def unblock_user(user_id):
    users = load_blocked_users()
    users.discard(user_id)
    with open(BLOCKED_USERS_FILE, "w") as f:
        json.dump(list(users), f, indent=2)

def is_user_blocked(user_id):
    return user_id in load_blocked_users()

