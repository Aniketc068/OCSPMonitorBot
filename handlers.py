from imports import *


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

                    await update.message.reply_text("✅ New Capricorn certificate has been updated successfully.")

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
    chat_id = os.getenv("TELEGRAM_CHAT_ID")

    while True:
        try:
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
                last_ocsp_alert_time = None  # Reset
            else:
                now = datetime.now(timezone.utc)

                if last_ocsp_alert_time is None or now - last_ocsp_alert_time > timedelta(hours=1):
                    # Escape message & URL for Telegram HTML
                    escaped_message = html.escape(message)
                    escaped_ocsp_url = html.escape(ocsp_url or 'N/A')

                    msg = await bot.send_message(
                        chat_id=chat_id,
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

                    last_ocsp_alert_time = now
                    last_ocsp_message_id = msg.message_id

                    # Delete the message after 5 minutes (300 seconds)
                    async def delete_later(chat_id, message_id):
                        await asyncio.sleep(300)
                        try:
                            await bot.delete_message(chat_id=chat_id, message_id=message_id)
                        except Exception as e:
                            print(f"⚠️ Failed to delete message: {e}")

                    asyncio.create_task(delete_later(chat_id, msg.message_id))

        except Exception as e:
            print(f"❌ Error during monitoring: {e}")

        await asyncio.sleep(5)
