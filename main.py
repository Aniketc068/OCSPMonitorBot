from imports import *

app = Flask(__name__)

MASTER_TOKEN = os.environ.get("MASTER_TOKEN")
issued_tokens = {}  # token: (timestamp, used_flag)

@app.route('/')
def index():
    return render_template('index.html')

@app.route("/api/get-token", methods=["POST"])
def get_token():
    content_type = request.content_type.lower()

    if "application/json" in content_type:
        data = request.get_json(force=True)
        auth_token = data.get("auth_token")

    elif "application/xml" in content_type or "text/xml" in content_type:
        try:
            root = ET.fromstring(request.data)
            auth_token = root.findtext("auth_token")
        except Exception:
            return Response("Invalid XML format", status=400)
    else:
        return Response("Unsupported Content-Type", status=415)

    # 🔐 Validate token
    if auth_token != MASTER_TOKEN:
        return Response("Invalid master token", status=401)

    # 🧠 Generate new token
    new_token_raw = f"{auth_token}_{time.time()}"
    new_token = sha256(new_token_raw.encode()).hexdigest()
    issued_tokens[new_token] = (time.time(), False)

    # 📤 Return response in requested format
    if "json" in content_type:
        return jsonify({"token": new_token})
    elif "xml" in content_type:
        root = ET.Element("response")
        ET.SubElement(root, "token").text = new_token
        return Response(ET.tostring(root, encoding="utf-8"), content_type="application/xml")

    return Response("Unexpected error", status=500)

def is_valid_token(token, response_type):
    entry = issued_tokens.get(token)
    if not entry:
        return create_error_response("Missing or invalid token", response_type)

    timestamp, used = entry
    if used:
        return create_error_response("Token already used", response_type)

    if time.time() - timestamp > 60:
        return create_error_response("Token expired", response_type)

    # Mark as used
    issued_tokens[token] = (timestamp, True)
    return None  # Means token is valid


@app.route('/cert-count')
def cert_count():
    count = get_certificate_counter()
    return jsonify({'total': count})



@app.route("/api/certchecker", methods=["POST"])
def cert_checker_api():
    content_type = request.content_type.lower()
    response_type = "json" if "json" in content_type else "xml"

    # 🛡️ Token check
    token = request.headers.get("Token")
    token_error = is_valid_token(token, response_type)
    if token_error:
        return token_error  # returns structured error in json/xml
    try:
        content_type = request.content_type.lower()
        request_type = ""
        cert_b64 = None
        command = None

        # Parse JSON request
        if "application/json" in content_type:
            req = request.get_json(force=True)
            command = req.get("request", {}).get("command")
            cert_b64 = req.get("request", {}).get("data")
            request_type = "json"

        # Parse XML request
        elif "application/xml" in content_type or "text/xml" in content_type:
            root = ET.fromstring(request.data)
            command = root.findtext("command")
            cert_b64 = root.findtext("data")
            request_type = "xml"
        else:
            return Response("Unsupported Content-Type", status=415)

        # Validate required fields
        if not command:
            return create_error_response("Missing 'command' field", request_type)

        if command.strip().lower() != "certchecker":
            return create_error_response("Invalid command. Expected 'certchecker'", request_type)

        if not cert_b64:
            return create_error_response("Missing 'data' field (base64 certificate)", request_type)

        # 🛡️ Validate and decode base64
        try:
            cert_bytes = base64.b64decode(cert_b64, validate=True)
        except Exception:
            return create_error_response("Invalid base64 certificate data", request_type)
        
        
        # ✅ Try to load as PKCS7 (.p7b)
        try:
            certificates = pkcs7.load_der_pkcs7_certificates(cert_bytes)
            if not certificates:
                raise ValueError("No certificates found in .p7b file")

            result_dict = {}
            for idx, cert in enumerate(certificates, start=1):
                parsed = parse_html_output(check_certificate(cert.public_bytes(serialization.Encoding.DER)))
                if not parsed.get("common_name") or not parsed.get("serial_number"):
                    continue
                result_dict[f"certificate_{idx}"] = parsed

            if request_type == "json":
                return jsonify({
                    "response": {
                        "status": "success",
                        "result": result_dict
                    }
                })

            elif request_type == "xml":
                response = ET.Element("response")
                ET.SubElement(response, "status").text = "success"
                result_elem = ET.SubElement(response, "result")

                for cert_key, cert_data in result_dict.items():
                    cert_elem = ET.SubElement(result_elem, cert_key)
                    for key, val in cert_data.items():
                        ET.SubElement(cert_elem, key).text = val

                xml_bytes = ET.tostring(response, encoding="utf-8", method="xml")
                return Response(xml_bytes, content_type="application/xml")

            return

        except Exception:
            pass



        # 🧪 Check if it's a real certificate
        html_result = check_certificate(cert_bytes)

        # Fail early if bot says it's not a valid certificate
        if "Invalid certificate format" in html_result or "Could not parse" in html_result:
            return create_error_response("Invalid or corrupt base64 certificate data", request_type)

        # Parse result
        parsed_result = parse_html_output(html_result)

        # Check for empty or missing critical fields
        if not parsed_result.get("common_name") or not parsed_result.get("serial_number"):
            return create_error_response("Certificate structure could not be validated", request_type)
        
        increment_certificate_counter()

        result = parse_html_output(html_result)

        if request_type == "json":
            return jsonify({
                "response": {
                    "status": "success",
                    "result": result
                }
            })

        elif request_type == "xml":
            response = ET.Element("response")
            ET.SubElement(response, "status").text = "success"
            result_elem = ET.SubElement(response, "result")

            for key, val in result.items():
                ET.SubElement(result_elem, key).text = val

            xml_bytes = ET.tostring(response, encoding="utf-8", method="xml")
            return Response(xml_bytes, content_type="application/xml")

    except Exception as e:
        print("Internal Error:", str(e))
        return Response("Internal Server Error", status=500)
    

def cleanup_expired_tokens():
    now = time.time()
    for token in list(issued_tokens):
        timestamp, used = issued_tokens[token]
        if used or now - timestamp > 60:
            del issued_tokens[token]


def create_error_response(message: str, response_type: str):
    """Returns a structured error response in JSON or XML."""
    if response_type == "json":
        return jsonify({
            "response": {
                "status": "error",
                "error": message
            }
        }), 400

    elif response_type == "xml":
        root = ET.Element("response")
        ET.SubElement(root, "status").text = "error"
        ET.SubElement(root, "error").text = message
        xml_bytes = ET.tostring(root, encoding="utf-8", method="xml")
        return Response(xml_bytes, content_type="application/xml", status=400)

    return Response(message, status=400)
        

def main():
    telegram_app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
    telegram_app.add_handler(CallbackQueryHandler(handle_cert_convert_callback, pattern=r"^cert_convert_"))
    telegram_app.add_handler(CallbackQueryHandler(handle_unblock_callback))
    telegram_app.add_handler(MessageHandler(filters.Document.ALL | filters.TEXT, handle_certificate))
    
    

    

    print("✅ Telegram Bot is starting via polling...")

    def run_bot():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # 🧠 Start OCSP monitoring in background
        loop.create_task(monitor_capricorn_certificate(telegram_app.bot))

        telegram_app.run_polling()

    bot_thread = threading.Thread(target=run_bot)
    bot_thread.start()

    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "0.0.0.0")

    print(f"🌐 Flask status page running at http://{host}:{port}")

    system_platform = platform.system().lower()

    if system_platform == 'windows':
        from waitress import serve
        serve(app, host=host, port=port)
    else:
        try:
            from gunicorn.app.base import BaseApplication

            class GunicornApp(BaseApplication):
                def __init__(self, app, options=None):
                    self.options = options or {}
                    self.application = app
                    super().__init__()

                def load_config(self):
                    for key, value in self.options.items():
                        self.cfg.set(key, value)

                def load(self):
                    return self.application

            options = {
                'bind': f'{host}:{port}',
                'workers': 4
            }
            GunicornApp(app, options).run()

        except ImportError:
            print("Gunicorn not available. Falling back to Flask's development server.")
            app.run(host=host, port=port)


if __name__ == "__main__":
    main()
