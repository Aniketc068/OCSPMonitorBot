from datetime import datetime, timedelta, timezone
import html
import time
import requests
import base64
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID, AuthorityInformationAccessOID
from cryptography.x509.ocsp import (
    OCSPRequestBuilder,
    load_der_ocsp_response,
    OCSPResponseStatus,
    OCSPCertStatus
)
import zipfile
import io
import warnings
from cryptography.hazmat.primitives.serialization import pkcs7
import traceback
import os
import json
from dotenv import load_dotenv
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update, Bot
from telegram.ext import ApplicationBuilder, MessageHandler, ContextTypes, filters, CallbackQueryHandler
from collections import defaultdict
from block_utils import block_user, unblock_user, load_blocked_users
from config import (
    TELEGRAM_BOT_TOKEN,
    MONITOR_USER_ID,
    USER_WARNINGS,
    SPAM_MESSAGES,
    BLOCKED_NOTICE_MESSAGES,
    BLOCKED_USERS_FILE,
    USER_WARNINGS_FILE,
    SPAM_MESSAGES_FILE,
    BLOCKED_NOTICE_FILE,
    increment_certificate_counter,
    get_certificate_counter,
    save_json_file,
    last_ocsp_alert_time,
    last_ocsp_message_id
)
import re
from cert_utils import get_ocsp_url1, get_crl_url1, get_issuer_cert1, check_ocsp1, check_crl1, check_certificate, get_issuer_cert, check_ocsp
from flask import Flask, jsonify, render_template, request, Response
import asyncio
import threading
from handlers import handle_certificate, handle_unblock_callback, monitor_capricorn_certificate, handle_cert_convert_callback
import base64
import xml.etree.ElementTree as ET
from parse import parse_html_output
from waitress import serve
import platform
import subprocess
from hashlib import sha256
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
