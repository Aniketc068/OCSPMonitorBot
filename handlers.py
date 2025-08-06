from imports import *
from telegram.error import Forbidden


ENV_PATH = ".env"
monitor_user_id = os.getenv("MONITOR_USER_ID")

def append_chat_id_to_env(new_chat_id: str):
    load_dotenv(ENV_PATH)
    existing_ids = os.getenv("TELEGRAM_CHAT_ID", "")
    chat_ids = set(existing_ids.split(",")) if existing_ids else set()

    if new_chat_id not in chat_ids:
        chat_ids.add(new_chat_id)
        new_value = ",".join(chat_ids)
        set_key(ENV_PATH, "TELEGRAM_CHAT_ID", new_value)
        os.environ["TELEGRAM_CHAT_ID"] = new_value  # update current runtime too
        print(f"✅ Added new chat ID: {new_chat_id}")


def remove_chat_id_from_env(chat_id_to_remove: str):
    load_dotenv(ENV_PATH)
    existing_ids = os.getenv("TELEGRAM_CHAT_ID", "")
    chat_ids = set(existing_ids.split(",")) if existing_ids else set()

    if chat_id_to_remove in chat_ids:
        chat_ids.remove(chat_id_to_remove)
        new_value = ",".join(chat_ids)
        set_key(ENV_PATH, "TELEGRAM_CHAT_ID", new_value)
        os.environ["TELEGRAM_CHAT_ID"] = new_value
        print(f"🗑️ Removed invalid chat ID: {chat_id_to_remove}")

async def handle_cert_convert_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print("🛠️ Callback triggered:", update.callback_query.data)

    query = update.callback_query
    await query.answer()  # Required to acknowledge the click

    choice = query.data.replace("cert_convert_", "")

    # Check if P7B certs are stored
    is_p7b = context.user_data.get("is_p7b", False)
    cert_list = context.user_data.get("certs_list")

    if is_p7b and cert_list:
        # 🔁 Convert all P7B certs and zip
        try:
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_mem:
                for cert_bytes in cert_list:
                    try:
                        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
                        subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                        cn = subject[0].value if subject else "converted_cert"

                        if choice == "cer":
                            file_bytes = cert.public_bytes(serialization.Encoding.PEM)
                            filename = f"{cn}.cer"
                        elif choice == "der":
                            file_bytes = cert.public_bytes(serialization.Encoding.DER)
                            filename = f"{cn}.der"
                        elif choice == "base64":
                            base64_str = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()
                            file_bytes = base64_str.encode()
                            filename = f"{cn}_base64.txt"
                        else:
                            continue

                        zip_mem.writestr(filename, file_bytes)

                    except Exception as e:
                        print(f"⚠️ Error converting one cert: {e}")
                        continue

            zip_buffer.seek(0)
            await context.bot.send_document(
                chat_id=query.message.chat_id,
                document=zip_buffer,
                filename="converted_certificates.zip",
                caption=f"✅ All P7B certificates converted to <code>{choice.upper()}</code> and zipped.",
                parse_mode="HTML"
            )

            # ✅ Clear memory after use
            context.user_data.pop("certs_list", None)
            context.user_data.pop("is_p7b", None)

            await query.edit_message_text("✅ All P7B certificates converted and sent.")
            return

        except Exception as e:
            print(f"❌ Error during P7B conversion: {e}")
            await query.edit_message_text("❌ Failed to convert P7B certificates.")
            return

    # 🔹 Else handle regular PEM certificate
    cert_bytes = context.user_data.get("cert_bytes")
    cn = context.user_data.get("cn_name", "converted_cert")

    if not cert_bytes:
        await query.edit_message_text("❌ No certificate found. Please resend using /cert.")
        return

    try:
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
    except Exception:
        await query.edit_message_text("❌ Failed to parse stored certificate.")
        return

    try:
        if choice == "cer":
            filename = f"{cn}.cer"
            file_bytes = cert.public_bytes(serialization.Encoding.PEM)
        elif choice == "der":
            filename = f"{cn}.der"
            file_bytes = cert.public_bytes(serialization.Encoding.DER)
        elif choice == "base64":
            der_bytes = cert.public_bytes(serialization.Encoding.DER)
            base64_str = base64.b64encode(der_bytes).decode()
            file_bytes = base64_str.encode()
            filename = f"{cn}_base64.txt"
        else:
            await query.edit_message_text("❌ Invalid conversion choice.")
            return

        await context.bot.send_document(
            chat_id=query.message.chat_id,
            document=io.BytesIO(file_bytes),
            filename=filename,
            caption=f"✅ Converted as <code>{filename}</code>",
            parse_mode="HTML"
        )

        await query.edit_message_text("✅ Certificate converted and sent.")
        
    except Exception as e:
        print(f"❌ Conversion error: {e}")
        await query.edit_message_text("❌ Failed to convert certificate.")





async def handle_certificate(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.message.from_user.id)
    blocked_users = load_blocked_users()

    # 🔒 If user is blocked, delete the message and return silently
    if user_id in blocked_users:
        try:
            await update.message.delete()
        except:
            pass
        return
    
    # 🚫 Reject if not in a private chat
    if update.message.chat.type != "private":
        return

    try:
        cert_bytes = None
        is_valid_input = False

        if update.message.document:
            file = await update.message.document.get_file()
            cert_bytes = bytes(await file.download_as_bytearray())

            # 🔄 Handle /changecert command via uploaded .pem file
            if update.message.caption and "/changecert" in update.message.caption.lower():
                # ✅ Restrict to MONITOR_USER_ID
                if update.message.from_user.id != MONITOR_USER_ID:
                    await update.message.reply_text("❌ You are not authorized to use this command.")
                    return

                try:
                    pem_dir = "pem"
                    os.makedirs(pem_dir, exist_ok=True)

                    # 🧹 Delete all existing .pem files in the directory
                    for fname in os.listdir(pem_dir):
                        if fname.endswith(".pem"):
                            try:
                                os.remove(os.path.join(pem_dir, fname))
                            except Exception as e:
                                print(f"⚠️ Failed to delete {fname}: {e}")

                    # 💾 Save the new certificate
                    new_path = os.path.join(pem_dir, "capricorn.pem")
                    with open(new_path, "wb") as f:
                        f.write(cert_bytes)

                    await update.message.reply_text("✅ New certificate has been updated successfully for live checking ocsp.")

                except Exception as e:
                    await update.message.reply_text(
                        f"❌ Failed to update Capricorn certificate:\n<pre>{html.escape(str(e))}</pre>",
                        parse_mode="HTML"
                    )
                return  # 🚫 Stop further processing
            
            

            if update.message.document.file_name.endswith(".p7b") or update.message.document.file_name.endswith(".p7c"):
            

                certs = []

                 # ⏳ Notify user that processing will take time
                waiting_msg = await update.message.reply_text(
                    "⏳ Please wait... This file may contain multiple certificates and can take some time to process."
                )
                try:
                    # Try loading PKCS7 as DER, suppressing BER fallback warning
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", UserWarning)
                        certs = pkcs7.load_der_pkcs7_certificates(cert_bytes)
                except Exception:
                    try:
                        # Try decoding as PEM and parsing
                        pem_data = cert_bytes.decode()
                        certs = pkcs7.load_pem_pkcs7_certificates(pem_data.encode())
                    except Exception:
                        certs = []


                if not certs:
                    await waiting_msg.delete()
                    await update.message.reply_text("❌ Could not parse any certificate from the .p7b file.")
                    return
                

                # ⚙️ If caption has /pem, return PEMs first
                if update.message.caption and "/pem" in update.message.caption.lower():
                    try:
                        zip_buffer = io.BytesIO()
                        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_mem:
                            for cert in certs:
                                try:
                                    cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                                    cn = cn_attr[0].value if cn_attr else "converted_cert"
                                    filename = f"{cn}.pem"
                                    pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
                                    zip_mem.writestr(filename, pem_bytes)
                                except Exception as e:
                                    print(f"❌ Error converting one of the certificates: {e}")
                                    continue

                        zip_buffer.seek(0)
                        original_filename = update.message.document.file_name.rsplit(".", 1)[0]
                        zip_filename = f"{original_filename}.zip"

                        await context.bot.send_document(
                            chat_id=update.message.chat_id,
                            document=zip_buffer,
                            filename=zip_filename,
                            caption=f"✅ Extracted and zipped PEMs from <code>{update.message.document.file_name}</code>",
                            parse_mode="HTML",
                            reply_to_message_id=update.message.message_id
                        )

                    except Exception as e:
                        await update.message.reply_text(
                            f"❌ Error while creating zip:\n<pre>{html.escape(str(e))}</pre>",
                            parse_mode="HTML"
                        )

                    await waiting_msg.delete()
                    return  # 🚫 Skip further processing
                

                if update.message.caption and "/cert" in update.message.caption.lower():
                    if not certs:
                        await waiting_msg.delete()
                        await update.message.reply_text("❌ No certificate found inside the .p7b/.p7c file.")
                        return

                    context.user_data["certs_list"] = [cert.public_bytes(serialization.Encoding.DER) for cert in certs]
                    context.user_data["is_p7b"] = True

                    # ✅ Delete the waiting message before sending the buttons
                    try:
                        await waiting_msg.delete()
                    except Exception as e:
                        print(f"⚠️ Could not delete waiting message (cert): {e}")

                    await update.message.reply_text(
                        "✅ Extracted certificates from .p7b.\nChoose format to convert:",
                        reply_markup=InlineKeyboardMarkup([
                            [
                                InlineKeyboardButton("🔹 .cer (PEM)", callback_data="cert_convert_cer"),
                                InlineKeyboardButton("🔸 .der", callback_data="cert_convert_der"),
                            ],
                            [
                                InlineKeyboardButton("📄 Base64", callback_data="cert_convert_base64")
                            ]
                        ])
                    )
                    return



                combined_results = []

                for i, cert in enumerate(certs, start=1):
                    try:
                        cert_der = cert.public_bytes(serialization.Encoding.DER)
                        result = check_certificate(cert_der)
                        increment_certificate_counter()
                        combined_results.append(f"<b>Certificate {i}:</b>\n{result}")
                    except Exception as e:
                        combined_results.append(f"<b>Certificate {i}:</b>\n❌ Error parsing certificate: <pre>{html.escape(str(e))}</pre>")

                # Send a single combined message
                final_output = "\n\n".join(combined_results)
                await context.bot.send_message(
                    chat_id=update.message.chat_id,
                    text=final_output,
                    parse_mode="HTML",
                    reply_to_message_id=update.message.message_id
                )
                # ✅ Delete the "please wait" message after sending response
                try:
                    await waiting_msg.delete()
                except Exception as e:
                    print(f"⚠️ Failed to delete waiting message: {e}")

                return  # ⛔ Don't process further
            
            
            

            # 🔄 Convert to PEM if caption contains '/pem'
            if update.message.caption and "/pem" in update.message.caption.lower():
                try:
                    cert = None
                    try:
                        # Try DER first
                        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
                    except Exception:
                        try:
                            # Try PEM format
                            decoded_text = cert_bytes.decode(errors="ignore")
                            if "-----BEGIN CERTIFICATE-----" not in decoded_text:
                                # Add missing PEM headers if not present
                                cleaned = base64.b64decode(cert_bytes)
                                pem_candidate = (
                                    b"-----BEGIN CERTIFICATE-----\n"
                                    + base64.encodebytes(cleaned)
                                    + b"-----END CERTIFICATE-----\n"
                                )
                                cert = x509.load_pem_x509_certificate(pem_candidate, default_backend())
                            else:
                                cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
                        except Exception:
                            cert = None

                    if cert is None:
                        await update.message.reply_text("❌ Unable to parse certificate to convert to PEM.")
                        return

                    # Get CN for filename
                    subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                    cn = subject[0].value if subject else "converted_cert"
                    filename = f"{cn}.pem"

                    # Export as proper PEM
                    pem_data = cert.public_bytes(serialization.Encoding.PEM)

                    # 📤 Send PEM file
                    await context.bot.send_document(
                        chat_id=update.message.chat_id,
                        document=io.BytesIO(pem_data),
                        filename=filename,
                        caption=f"✅ Converted to PEM format as <code>{filename}</code>",
                        parse_mode="HTML",
                        reply_to_message_id=update.message.message_id
                    )
                    return
                except Exception as e:
                    await update.message.reply_text(
                        f"❌ Failed to convert certificate to proper PEM:\n<pre>{html.escape(str(e))}</pre>",
                        parse_mode="HTML"
                    )
                    return
                

            if update.message.caption and "/cert" in update.message.caption.lower():
                try:
                    cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
                except Exception:
                    await update.message.reply_text("❌ Invalid PEM certificate.")
                    return

                # Get CN for later use
                subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                cn = subject[0].value if subject else "converted_cert"

                # 🧠 Store cert in memory (to convert after button press)
                context.user_data["cert_bytes"] = cert_bytes
                context.user_data["cn_name"] = cn

                # ⬇️ Show format options to user
                keyboard = InlineKeyboardMarkup([
                    [
                        InlineKeyboardButton("🔹 .cer (PEM)", callback_data="cert_convert_cer"),
                        InlineKeyboardButton("🔸 .der", callback_data="cert_convert_der"),
                    ],
                    [
                        InlineKeyboardButton("📄 Base64", callback_data="cert_convert_base64")
                    ]
                ])

                await update.message.reply_text(
                    f"✅ Certificate parsed.\nChoose format to convert:",
                    reply_markup=keyboard
                )
                return

                

        elif update.message.text:
            text = update.message.text.strip()

            if "-----BEGIN CERTIFICATE-----" in text:
                cert_bytes = text.encode()
            else:
                try:
                    decoded = base64.b64decode(text)
                    cert_bytes = decoded
                except Exception:
                    cert_bytes = None

        if cert_bytes:
            result = check_certificate(cert_bytes)

            if result.startswith("❌ <b>Invalid certificate format</b>") or "not found" in result:
                is_valid_input = False
            else:
                is_valid_input = True
                increment_certificate_counter()

        if not is_valid_input:
            USER_WARNINGS[user_id] += 1
            save_json_file(USER_WARNINGS_FILE, dict(USER_WARNINGS))
            warning_count = USER_WARNINGS[user_id]
            SPAM_MESSAGES[user_id].append(update.message.message_id)
            save_json_file(SPAM_MESSAGES_FILE, dict(SPAM_MESSAGES))
            if warning_count >= 10:
                block_user(user_id)

                # 🧹 Delete all tracked spam + warning messages
                for msg_id in SPAM_MESSAGES[user_id]:
                    try:
                        await context.bot.delete_message(chat_id=update.message.chat_id, message_id=msg_id)
                    except Exception as e:
                        print(f"⚠️ Failed to delete message {msg_id}: {e}")
                SPAM_MESSAGES[user_id].clear()
                

                notice = await update.message.reply_text(
                    "❌ You’ve been blocked due to spam.\n"
                    "📩 Please contact the admin: @AniketChaturvedi to request an unblock.",
                    parse_mode="HTML"
                )
                BLOCKED_NOTICE_MESSAGES[user_id] = notice.message_id
                save_json_file(BLOCKED_NOTICE_FILE, BLOCKED_NOTICE_MESSAGES)

                # 🚨 Alert to admin
                user = update.message.from_user
                full_name = user.full_name
                username = f"@{user.username}" if user.username else f"ID: {user_id}"
                admin_text = (
                    f"🚫 <b>User Blocked</b>\n"
                    f"👤 Name: <code>{full_name}</code>\n"
                    f"🔗 Username: {username}\n"
                    f"❗ Reason: Spam after 10 warnings"
                )

                keyboard = InlineKeyboardMarkup([
                    [InlineKeyboardButton("✅ Unblock User", callback_data=f"unblock_{user_id}")]
                ])

                await context.bot.send_message(
                    chat_id=MONITOR_USER_ID,
                    text=admin_text,
                    parse_mode='HTML',
                    reply_markup=keyboard
                )
            else:
                warning_msg = await update.message.reply_text(
                    f"⚠️ Warning {warning_count}/10: Please send a valid certificate file or base64 text."
                )
                SPAM_MESSAGES[user_id].append(warning_msg.message_id)

            return

        # ✅ If input is valid, reset warnings
        USER_WARNINGS[user_id] = 0
        SPAM_MESSAGES[user_id].clear()
        save_json_file(USER_WARNINGS_FILE, dict(USER_WARNINGS))
        save_json_file(SPAM_MESSAGES_FILE, dict(SPAM_MESSAGES))

        await context.bot.send_message(
            chat_id=update.message.chat_id,
            text=result,
            parse_mode="HTML",
            reply_to_message_id=update.message.message_id
        )

    except Exception as e:
        error_msg = traceback.format_exc()
        print("Error in handle_certificate:", error_msg)
        await update.message.reply_text(f"❌ Internal error occurred:\n<pre>{error_msg}</pre>", parse_mode='HTML')



async def handle_unblock_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()

    if not query.data.startswith("unblock_"):
        return

    user_id = query.data.replace("unblock_", "")
    unblock_user(user_id)
    USER_WARNINGS[user_id] = 0
    save_json_file(USER_WARNINGS_FILE, dict(USER_WARNINGS))

    # 🧹 Clear spam messages
    if user_id in SPAM_MESSAGES:
        SPAM_MESSAGES[user_id].clear()
        save_json_file(SPAM_MESSAGES_FILE, dict(SPAM_MESSAGES))

    # 🧹 Delete the "You've been blocked" notice if it exists
    if user_id in BLOCKED_NOTICE_MESSAGES:
        try:
            await context.bot.delete_message(
                chat_id=int(user_id),
                message_id=BLOCKED_NOTICE_MESSAGES[user_id]
            )
        except Exception as e:
            print(f"❗ Failed to delete blocked notice message for {user_id}: {e}")
        del BLOCKED_NOTICE_MESSAGES[user_id]
        save_json_file(BLOCKED_NOTICE_FILE, BLOCKED_NOTICE_MESSAGES)

    # 👤 Try to get user info
    try:
        user_chat = await context.bot.get_chat(int(user_id))
        display_name = f"@{user_chat.username}" if user_chat.username else user_chat.full_name
    except Exception as e:
        print(f"❗ Couldn't fetch user info for {user_id}: {e}")
        display_name = f"ID: {user_id}"

    # 🛡️ Notify admin (edit callback message)
    await query.edit_message_text(
        f"✅ User <b>{display_name}</b> has been unblocked.",
        parse_mode='HTML'
    )

    # 📬 Notify the unblocked user
    try:
        await context.bot.send_message(
            chat_id=int(user_id),
            text=(
                "✅ Your account has been unblocked.\n\n"
                "You can now send certificates again to check their details.\n\n"
                "🚫 Please do not send unrelated content or spam, or your access will be blocked again."
            )
        )
    except Exception as e:
        print(f"❗ Failed to notify user {user_id}: {e}")


async def monitor_capricorn_certificate(bot: Bot):
    global last_ocsp_alert_time, last_ocsp_message_id

    cert_path = os.path.join("pem", "capricorn.pem")
    last_env_load_time = None
    chat_ids = []

    while True:
        try:
            # 🔁 Reload .env every 5 minutes to get new chat IDs
            now = datetime.now()
            if last_env_load_time is None or (now - last_env_load_time).seconds > 300:
                load_dotenv()
                chat_ids = os.getenv("TELEGRAM_CHAT_ID", "").split(",")
                last_env_load_time = now
                print(f"🔄 Refreshed TELEGRAM_CHAT_ID: {chat_ids}")

            if not os.path.exists(cert_path):
                print("⏳ Capricorn certificate not found. Waiting for upload...")
                await asyncio.sleep(10)
                continue

            with open(cert_path, "rb") as f:
                cert_bytes = f.read()

            cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
            issuer_cert = get_issuer_cert(cert)

            if not issuer_cert:
                print("❌ Issuer certificate not found.")
                await asyncio.sleep(5)
                continue

            success, message, ocsp_url = check_ocsp(cert, issuer_cert)

            if success:
                last_ocsp_alert_time = None  # Reset alert timer
            else:
                now_utc = datetime.now(timezone.utc)

                if last_ocsp_alert_time is None or now_utc - last_ocsp_alert_time > timedelta(hours=1):
                    escaped_message = html.escape(message)
                    escaped_ocsp_url = html.escape(ocsp_url or 'N/A')

                    for chat_id in chat_ids:
                        try:
                            msg = await bot.send_message(
                                chat_id=int(chat_id),
                                text=(
                                    "🚨 <b>Certificate Status Check Failed</b>\n\n"
                                    "We were unable to verify the certificate's current status.\n"
                                    "This may be due to a network issue or the server not responding.\n\n"
                                    f"❌ <b>Problem:</b> Unable to contact the OCSP verification server.\n"
                                    f"🌐 <b>OCSP URL:</b> <code>{escaped_ocsp_url}</code>\n\n"
                                    "⏳ We will retry automatically. If this keeps happening, please contact support."
                                ),
                                parse_mode="HTML"
                            )

                            last_ocsp_alert_time = now_utc
                            last_ocsp_message_id = msg.message_id

                            # 🧹 Auto-delete message after 5 minutes
                            async def delete_later(chat_id, message_id):
                                await asyncio.sleep(300)
                                try:
                                    await bot.delete_message(chat_id=chat_id, message_id=message_id)
                                except Exception as e:
                                    print(f"⚠️ Failed to delete message in {chat_id}: {e}")

                            asyncio.create_task(delete_later(chat_id, msg.message_id))

                        except Forbidden:
                            print(f"⛔ Bot was removed from group {chat_id}")
                            remove_chat_id_from_env(chat_id)

                            if monitor_user_id:
                                try:
                                    await bot.send_message(
                                        chat_id=int(monitor_user_id),
                                        text=(
                                            f"🚫 Bot was <b>removed</b> from group.\n"
                                            f"🆔 <code>{chat_id}</code>\n\n"
                                            "It has been removed from TELEGRAM_CHAT_ID list."
                                        ),
                                        parse_mode="HTML"
                                    )
                                except Exception as e:
                                    print(f"⚠️ Failed to notify MONITOR_USER_ID: {e}")

                        except Exception as e:
                            print(f"❌ Failed to send alert to {chat_id}: {e}")


        except Exception as e:
            print(f"❌ Error during monitoring: {e}")

        await asyncio.sleep(5)


async def handle_new_chat_member(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat = update.effective_chat
    if chat and chat.type in ["group", "supergroup"]:
        chat_id = str(chat.id)
        append_chat_id_to_env(chat_id)

        group_name = html.escape(chat.title or "Unknown Group")

        # Try sending welcome message
        try:

            await context.bot.send_message(
                chat_id=chat_id,
                text=(
                    "<b>✅ Bot Successfully Added!</b>\n"
                    "This group is now <b>registered</b> for <b>OCSP Certificate Expiry Alerts</b>. "
                    "You will receive timely notifications to keep your certificates up to date.\n\n"
                    "<b>📝 Note:</b>\n"
                    "If you'd like the bot to automatically remove its messages after sending alerts, "
                    "please make sure to <b>promote the bot as an admin</b> of this group."
                ),
                parse_mode="HTML"
            )


        except Forbidden:
            print(f"⛔ Bot was kicked from group {chat_id} before it could send message.")
            remove_chat_id_from_env(chat_id)

            # Notify MONITOR_USER_ID
            monitor_user_id = os.getenv("MONITOR_USER_ID")
            if monitor_user_id:
                try:
                    await context.bot.send_message(
                        chat_id=int(monitor_user_id),
                        text=(
                            f"🚫 Bot was <b>removed</b> from group right after joining.\n"
                            f"🆔 <code>{chat_id}</code>\n"
                            f"⛔ Group name: <b>{group_name}</b>\n\n"
                            "The chat ID has been removed from .env"
                        ),
                        parse_mode="HTML"
                    )
                except Exception as e:
                    print(f"⚠️ Could not notify monitor: {e}")
