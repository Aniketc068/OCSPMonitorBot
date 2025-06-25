# 🔐 Certificate OCSP & CRL Checker Bot + API

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white)
![Telegram](https://img.shields.io/badge/Telegram-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)
![Cryptography](https://img.shields.io/badge/cryptography-%237A1FA2.svg?style=for-the-badge&logo=cryptography&logoColor=white)

![App Flowchart](https://github.com/Aniketc068/OCSPMonitorBot/blob/main/flowchart.png)


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

### 3. Important Changes in imports.py
```cmd
If you are using Windows, keep these imports as they are
   from waitress import serve

If you are using Linux or Mac, remove the waitress import above 
and uncomment/use this import instead:
  from gunicorn.app.base import BaseApplication
```
### 4. Before Run the application:
📌 What is MASTER_TOKEN?
The MASTER_TOKEN is a secure authentication token used by the API to verify if the client requesting a new token is trusted.
Only clients that provide the correct MASTER_TOKEN are issued valid short-lived access tokens for calling protected endpoints (like /api/certchecker).

This mechanism prevents unauthorized access and abuse of the certificate validation API.

⚙️ How to Generate the MASTER_TOKEN

We provide a helper script: env_setup.py
This script helps you generate a strong MASTER_TOKEN and creates a .env file that will be used by your application.

NOTE: Please Genarate The Telegram Bot Token, User Chat-ID and Super Group Chat-ID

```cmd
python env_setup.py For Windows
python3 python env_setup.py For macOS/Linux
```

### 5. Then Run the application:
```cmd
python watcher.py For Windows
python3 watcher.py For macOS/Linux
```

## 🔑 Required Environment Variables
Create a .env file or export them manually:
```env
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_group_chat_id
MONITOR_USER_ID=your_admin_chat_id
```

## 🔑 How to Use MASTER_TOKEN to Get a Temporary Token
Endpoint
```http
POST /api/get-token
```

Headers
```http
Content-Type: application/json   OR   application/xml

```

JSON Payload
```json
{
  "auth_token": "Your_MASTER_TOKEN"
}
```
XML Payload
```xml
<request>
    <auth_token>Your_MASTER_TOKEN</auth_token>
</request>
```

✅ Response
If the auth_token is valid, you will receive a temporary token:

JSON
```json
{
  "token": "TEMPORARY_ACCESS_TOKEN"
}
```
XML
```xml
<response>
    <token>TEMPORARY_ACCESS_TOKEN</token>
</response>
```

⚠️ This token is valid for 60 seconds and can only be used once.




## 🔗 API Documentation
Endpoint
```bash
POST /api/certchecker
```

Headers
```pgsql
Content-Type: application/json OR application/xml
Token: TEMPORARY_ACCESS_TOKEN

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
| Status | Message                                 | Description                                              |
| ------ | --------------------------------------- | -------------------------------------------------------- |
| 400    | Missing 'command' or 'data' field       | Required fields are not found in the request             |
| 400    | Invalid command. Expected 'certchecker' | Wrong command value sent                                 |
| 400    | Invalid base64 certificate data         | `data` field is not properly base64 encoded              |
| 401    | Invalid master token                    | Provided master token is incorrect (in `/api/get-token`) |
| 400    | Token already used                      | Access token was already consumed                        |
| 400    | Token expired                           | Token was not used within 60 seconds                     |
| 400    | Missing or invalid token                | Token is not passed in the header or not found           |





## 🧪 Tech Stack

- Python  
- Flask  
- python-telegram-bot (async)  
- cryptography  
- lxml / xml.etree.ElementTree

## License
[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://github.com/Aniketc068/OCSPMonitorBot/blob/main/LICENSE)

## 🙋‍♂️ Developer

Made with ❤️ by Aniket Chaturvedi

