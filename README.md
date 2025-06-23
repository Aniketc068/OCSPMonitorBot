# 🔐 Certificate OCSP & CRL Checker Bot + API

This project provides a powerful Telegram bot and a RESTful API to check X.509 digital certificate validity, OCSP status, CRL updates, and more.

- ✅ Supports `.cer`, `.cert`, `.pem` certificates
- 🚫 Blocks spam users automatically
- 🔁 Real-time OCSP monitoring for Capricorn DSC
- ⚙️ JSON & XML API support
- 💬 Telegram Bot: [@OCSP_CRL_bot](https://t.me/OCSP_CRL_bot)

---

## 📦 Features

### Telegram Bot (`@OCSP_CRL_bot`)
- Upload a certificate file or paste base64 string
- Auto-detect `.pem`, `.der`, and even `.p7b` files
- Auto-warns and blocks spammers after 10 invalid attempts
- Admin panel to unblock users
- Live monitoring of Capricorn `.pem` OCSP status
- ⏰ Sends **OCSP failure alerts** to your group only **once per hour** to prevent spam
- 🧹 Automatically **deletes the alert message after 5 minutes**
- 👮‍♂️ Requires **Admin Rights** in the group to send and delete messages
### Flask API (`/api/certchecker`)
- Accepts `POST` requests with JSON or XML
- Validates certificate format
- Checks OCSP & CRL status
- Returns structured response
- Rejects `.p7b` files via API with user-friendly error

---

## 🚀 Clone Repository

```bash
git clone https://github.com/Aniketc068/OCSPMonitorBot.git
cd OCSPMonitorBot
```

## System Requirements

- Python 3.6 or higher
- Windows, macOS, or Linux

## Installation

### 1. Create and Activate Virtual Environment

#### Windows:
```cmd
python -m venv ocsp
pdf\Scripts\activate
```

#### macOS/Linux:
```cmd
python3 -m venv ocsp
source pdf/bin/activate
```

### 2. Install Dependencies
```cmd
pip install -r requirements.txt
```
### 3. Run the application:
```cmd
python main.py
```

## 🔑 Required Environment Variables
Create a .env file or export them manually:
```env
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_group_chat_id
MONITOR_USER_ID=your_admin_chat_id
```
## 🔗 API Documentation
Endpoint
```bash
POST /api/certchecker
```

Headers
```pgsql
Content-Type: application/json OR application/xml

```

JSON Payload
```json
{
  "request": {
    "command": "certchecker",
    "data": "BASE64_ENCODED_CERT_HERE"
  }
}
```
XML Payload
```xml
<request>
  <command>certchecker</command>
  <data>BASE64_ENCODED_CERT_HERE</data>
</request>

```

## ❌ Error Responses

| Error            | Message                                                                                                                                                          |
|------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Invalid base64   | Invalid base64 certificate data                                                                                                                                  |
| Missing field    | Missing 'command' field or 'data' field                                                                                                                          |
| Invalid command  | Expected 'certchecker'                                                                                                                                           |
| Unsupported file | We only support .cer, .cert, .pem certificates in the API. To check .p7b/.p7c files, please use our Telegram bot @OCSP_CRL_bot.                                 |


## 📊 Realtime Status

Visit:
```bash
GET /cert-count
```
Returns:
```json
{
  "total": 1257
}
```
## 🧪 Tech Stack

- Python  
- Flask  
- python-telegram-bot (async)  
- cryptography  
- lxml / xml.etree.ElementTree  

## 🙋‍♂️ Developer

Made with ❤️ by Aniket Chaturvedi
