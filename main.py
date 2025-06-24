from imports import *

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/cert-count')
def cert_count():
    count = get_certificate_counter()
    return jsonify({'total': count})



@app.route("/api/certchecker", methods=["POST"])
def cert_checker_api():
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
        
        # ⛔ Reject .p7b/.p7c certificates via API
        try:
            from cryptography.hazmat.primitives.serialization import pkcs7
            pkcs7.load_der_pkcs7_certificates(cert_bytes)
            return create_error_response(
                "We only support .cer, .cert, .pem certificates in the API. "
                "To check .p7b/.p7c files, please use our Telegram bot https://t.me/OCSP_CRL_bot",
                request_type
            )
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
    telegram_app.add_handler(MessageHandler(filters.Document.ALL | filters.TEXT, handle_certificate))
    telegram_app.add_handler(CallbackQueryHandler(handle_unblock_callback))

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
    print(f"🌐 Flask status page running at http://0.0.0.0:{port}")

    system_platform = platform.system().lower()
    
    if system_platform == 'windows':
        serve(app, host='0.0.0.0', port=port)
    else:
        # Linux/macOS: Use Gunicorn or fallback to app.run
        try:
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
                'bind': f'0.0.0.0:{port}',
                'workers': 4
            }
            GunicornApp(app, options).run()
        except ImportError:
            print("Gunicorn not available. Falling back to Flask's development server.")
            app.run(host='0.0.0.0', port=port)


if __name__ == "__main__":
    main()
