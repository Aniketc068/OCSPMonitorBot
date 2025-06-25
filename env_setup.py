import hashlib
import os

def generate_sha256_hash(input_text):
    return hashlib.sha256(input_text.encode()).hexdigest()

def main():
    print("🔐 Please enter a secure alphanumeric text with special characters (for API Token generation):")
    user_input = input(">> ")

    if not user_input.strip():
        print("❌ Error: Input cannot be empty.")
        return

    hashed_token = generate_sha256_hash(user_input)

    env_path = ".env"  # base directory file

    with open(env_path, "w") as f:
        f.write(f'MASTER_TOKEN = "{hashed_token}"\n')
        f.write("TELEGRAM_BOT_TOKEN = 'Replace With Your Telegaram Bot Token'\n")
        f.write("MONITOR_USER_ID = 'Replace With Your Telegaram User ID'\n")
        f.write("TELEGRAM_CHAT_ID = 'Replace With Your Telegaram reminder Group ID'\n")

    print("\n✅ Token has been generated and saved for API.")
    print("📁 Check the '.env' file in the current directory.")

if __name__ == "__main__":
    main()
