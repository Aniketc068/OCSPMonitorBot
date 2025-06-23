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

    try:
        cert_bytes = None
        is_valid_input = False

        if update.message.document:
            file = await update.message.document.get_file()
            cert_bytes = bytes(await file.download_as_bytearray())

            # 🔄 Handle /changecert command via uploaded .pem file
            if update.message.caption and "/changecert" in update.message.caption.lower():
                try:
                    os.makedirs("pem", exist_ok=True)
                    new_path = os.path.join("pem", "capricorn.pem")

                    # 🔥 Remove old certificate if exists
                    if os.path.exists(new_path):
                        os.remove(new_path)

                    with open(new_path, "wb") as f:
                        f.write(cert_bytes)

                    await update.message.reply_text("✅ New Capricorn certificate has been updated successfully.")
                except Exception as e:
                    await update.message.reply_text(f"❌ Failed to update Capricorn certificate:\n<pre>{html.escape(str(e))}</pre>", parse_mode="HTML")
                return  # 🚫 Don't proceed further

            if update.message.document.file_name.endswith(".p7b") or update.message.document.file_name.endswith(".p7c"):
                try:
                    # Try loading PKCS7 as DER format
                    certs = pkcs7.load_der_pkcs7_certificates(cert_bytes)
                except Exception:
                    try:
                        # Try decoding as PEM then DER
                        pem_data = cert_bytes.decode()
                        certs = pkcs7.load_pem_pkcs7_certificates(pem_data.encode())
                    except Exception:
                        certs = []

                if not certs:
                    await update.message.reply_text("❌ Could not parse any certificate from the .p7b file.")
                    return

                for cert in certs:
                    cert_der = cert.public_bytes(serialization.Encoding.DER)
                    result = check_certificate(cert_der)
                    increment_certificate_counter()
                    await context.bot.send_message(
                        chat_id=update.message.chat_id,
                        text=result,
                        parse_mode="HTML",
                        reply_to_message_id=update.message.message_id
                    )
                return  # ⛔ Don't process further; already done


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