from imports import *


# Constants
BLOCKED_USERS_FILE = "data/blocked_users.json"
USER_WARNINGS_FILE = "data/user_warnings.json"
SPAM_MESSAGES_FILE = "data/spam_messages.json"
BLOCKED_NOTICE_FILE = "data/blocked_notices.json"
COUNTER_FILE = "data/counter.json"

last_ocsp_alert_time = None  # For rate-limiting
last_ocsp_message_id = None  # To track the sent message


# Load environment variables
load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
MONITOR_USER_ID = int(os.getenv("MONITOR_USER_ID"))

def load_json_file(filename, default):
    if not os.path.exists(filename):
        return default
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return default

# Loaded data
USER_WARNINGS = defaultdict(int, load_json_file(USER_WARNINGS_FILE, {}))
SPAM_MESSAGES = defaultdict(list, load_json_file(SPAM_MESSAGES_FILE, {}))
BLOCKED_NOTICE_MESSAGES = load_json_file(BLOCKED_NOTICE_FILE, {})


def increment_certificate_counter():
    try:
        with open(COUNTER_FILE, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {"total_checks": 0}

    data["total_checks"] += 1

    with open(COUNTER_FILE, "w") as f:
        json.dump(data, f)

def get_certificate_counter():
    try:
        with open(COUNTER_FILE, "r") as f:
            data = json.load(f)
            return data.get("total_checks", 0)
    except Exception:
        return 0



def save_json_file(filename, data):
    os.makedirs(os.path.dirname(filename), exist_ok=True)  # 🔧 Yeh line folder auto banayegi
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)