from imports import *
import datetime

# Disable SSL warnings when verify=False is used
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_ocsp_url1(cert):
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for access_desc in aia.value:
            if access_desc.access_method == AuthorityInformationAccessOID.OCSP:
                return access_desc.access_location.value
    except x509.ExtensionNotFound:
        pass
    return None

def get_crl_url1(cert):
    try:
        crl_dist = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        for point in crl_dist.value:
            for name in point.full_name:
                return name.value
    except x509.ExtensionNotFound:
        pass
    return None


def get_issuer_cert1(cert):
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for access_desc in aia.value:
            if access_desc.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
                issuer_url = access_desc.access_location.value
                r = requests.get(issuer_url, timeout=30, verify=False)
                if r.status_code == 200:
                    try:
                        return x509.load_der_x509_certificate(r.content, default_backend())
                    except Exception:
                        return x509.load_pem_x509_certificate(r.content, default_backend())
    except x509.ExtensionNotFound:
        pass
    return None

def check_ocsp1(cert, issuer_cert):
    ocsp_url = get_ocsp_url1(cert)
    if not ocsp_url:
        return "❌ No OCSP URL found in certificate."

    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer_cert, hashes.SHA1())
    req = builder.build()
    req_data = req.public_bytes(serialization.Encoding.DER)

    headers = {'Content-Type': 'application/ocsp-request'}
    try:
        response = requests.post(ocsp_url, data=req_data, headers=headers, timeout=30)
    except Exception as e:
        return f"❌ OCSP request failed: {str(e)}"

    if response.status_code != 200:
        return f"❌ OCSP HTTP error: {response.status_code}"

    try:
        ocsp_resp = load_der_ocsp_response(response.content)
    except Exception as e:
        return f"❌ Failed to parse OCSP response: {e}"

    if ocsp_resp.response_status != OCSPResponseStatus.SUCCESSFUL:
        return f"❌ OCSP not successful: {ocsp_resp.response_status.name}"

    single_resp = next(ocsp_resp.responses)
    status = single_resp.certificate_status

    if status == OCSPCertStatus.GOOD:
        return "✅ OCSP Status: GOOD"
    elif status == OCSPCertStatus.REVOKED:
        revoked_time = single_resp.revocation_time_utc.astimezone(datetime.timezone(datetime.timedelta(hours=5, minutes=30)))
        return f"❌ OCSP Status: REVOKED at {revoked_time.strftime('%Y-%m-%d %H:%M:%S %Z')}"
    elif status == OCSPCertStatus.UNKNOWN:
        return "⚠️ OCSP Status: UNKNOWN"
    return "❓ OCSP Status: Unable to determine"



def check_crl1(cert):
    IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    crl_url = get_crl_url1(cert)
    if not crl_url:
        return "❌ <b>No CRL URL found in certificate.</b>"

    try:
        r = requests.get(crl_url, timeout=30)
        crl = x509.load_der_x509_crl(r.content, default_backend())
    except Exception as e:
        return f"❌ <b>Failed to load CRL:</b> {e}"

    # Check revocation
    serial = cert.serial_number
    revoked_cert = next((rc for rc in crl if rc.serial_number == serial), None)

    ist = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    last_update = crl.last_update_utc.astimezone(ist).strftime("%Y-%m-%d %H:%M:%S %Z")
    next_update = crl.next_update_utc.astimezone(ist).strftime("%Y-%m-%d %H:%M:%S %Z")

    if revoked_cert:
        rev_time = revoked_cert.revocation_date_utc.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S %Z")
        status = f"❌ <b>Revoked at:</b> {rev_time}"
    else:
        status = "✅ <b>Not Revoked</b>"

    return (
        f"{status}\n"
        f"🌐 <b>CRL URL:</b> <code>{crl_url}</code>\n"
        f"🕓 <b>CRL Last Update:</b> {last_update}\n"
        f"⏭️ <b>CRL Next Update:</b> {next_update}"
    )


def check_certificate(cert_bytes):
    ist = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    # Try DER
    try:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
    except Exception:
        try:
            # Try PEM
            cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        except Exception:
            try:
                # Try base64-decoded DER (no headers)
                decoded = base64.b64decode(cert_bytes)
                cert = x509.load_der_x509_certificate(decoded, default_backend())
            except Exception:
                return "❌ <b>Invalid certificate format</b>"

    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    serial_hex = hex(cert.serial_number).upper().replace("0X", "")

    now = datetime.datetime.now(datetime.timezone.utc)
    left = cert.not_valid_after_utc.astimezone(ist) - now.astimezone(ist)
    validity = f"{left.days}d {left.seconds // 3600}h {(left.seconds % 3600) // 60}m {left.seconds % 60}s"

    # ✅ Key Usage Check
    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return "❌ <b>Key Usage extension not found in certificate.</b>"

    usage_mapping = {
        "digital_signature": "Digital Signature",
        "content_commitment": "Non-Repudiation",
        "key_encipherment": "Key Encipherment",
        "data_encipherment": "Data Encipherment",
        "key_agreement": "Key Agreement",
        "key_cert_sign": "Certificate Signing",
        "crl_sign": "CRL Signing",
        "encipher_only": "Encipher Only",
        "decipher_only": "Decipher Only"
    }

    key_usage_list = []
    cert_type_labels = set()

    for attr, label in usage_mapping.items():
        try:
            if attr in ["encipher_only", "decipher_only"] and not key_usage.key_agreement:
                continue  # Don't access these unless key_agreement is True

            if getattr(key_usage, attr):
                key_usage_list.append(label)

                if attr in ["digital_signature", "content_commitment"]:
                    cert_type_labels.add("Signing Certificate")
                if attr in ["key_encipherment", "data_encipherment", "key_agreement"]:
                    cert_type_labels.add("Encryption Certificate")
                if attr == "key_cert_sign":
                    cert_type_labels.add("CA Certificate")
                if attr == "crl_sign":
                    cert_type_labels.add("CRL Signing Certificate")
        except Exception:
            continue  # In case getattr fails for any reason


    if not key_usage_list:
        return "❌ <b>None of the Key Usages are enabled in the certificate.</b>"

    cert_type_str = ", ".join(cert_type_labels)


    # 🔗 OCSP + CRL checks
    issuer_cert = None  # Initialize to avoid UnboundLocalError

    if cert.issuer == cert.subject:
        # Root certificate
        ocsp_result = "🔒 <b>Root certificate detected. No OCSP check needed.</b>"
        crl_result = check_crl1(cert)
    else:
        issuer_cert = get_issuer_cert1(cert)
        if issuer_cert is None:
            return "❌ <b>Failed to download issuer certificate.</b>"
        ocsp_result = check_ocsp1(cert, issuer_cert)
        crl_result = check_crl1(cert)

        
    ocsp_result = check_ocsp1(cert, issuer_cert)
    crl_result = check_crl1(cert)

    ocsp_result = check_ocsp1(cert, issuer_cert)
    crl_result = check_crl1(cert)

    #  📋 Final Response
    response = (
        f"📄 <b>Certificate CN:</b> {cn}\n"
        f"🏢 <b>Issuer:</b> {issuer}\n"
        f"🔑 <b>Serial No.:</b> {serial_hex}\n"
        f"🏷️ <b>Certificate Type:</b> {cert_type_str}\n"
        f"⏳ <b>Validity Left:</b> {validity}\n"
        f"{crl_result}\n"
        f"{ocsp_result}"
    )

    return response


def get_ocsp_url(cert):
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for access_desc in aia.value:
            if access_desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                return access_desc.access_location.value
    except x509.ExtensionNotFound:
        return None
    return None

def get_issuer_cert(cert):
    try:
        aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        for access_desc in aia.value:
            if access_desc.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                issuer_url = access_desc.access_location.value
                r = requests.get(issuer_url, timeout=30, verify=False)
                if r.status_code == 200:
                    try:
                        return x509.load_der_x509_certificate(r.content, default_backend())
                    except Exception:
                        return x509.load_pem_x509_certificate(r.content, default_backend())
    except x509.ExtensionNotFound:
        pass
    return None

def build_ocsp_request(cert, issuer):
    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(cert, issuer, hashes.SHA1())
    req = builder.build()
    return req.public_bytes(serialization.Encoding.DER)

def check_ocsp(cert, issuer_cert):
    ocsp_url = get_ocsp_url(cert)
    if not ocsp_url:
        return False, "No OCSP URL found in certificate.", None

    ocsp_req_data = build_ocsp_request(cert, issuer_cert)
    headers = {'Content-Type': 'application/ocsp-request'}

    # Retry loop
    for attempt in range(3):
        try:
            response = requests.post(ocsp_url, data=ocsp_req_data, headers=headers, timeout=30)
            break
        except Exception as e:
            if attempt < 2:
                time.sleep(5)  # wait and retry
                continue
            return False, f"OCSP request failed after retries: {e}", ocsp_url
            
    if response.status_code != 200:
        return False, f"OCSP responder returned HTTP status {response.status_code}", ocsp_url

    try:
        ocsp_resp = load_der_ocsp_response(response.content)
    except Exception as e:
        return False, f"Failed to parse OCSP response: {e}", ocsp_url

    status = ocsp_resp.response_status

    if status != OCSPResponseStatus.SUCCESSFUL:
        return False, f"OCSP response status not successful: {status}", ocsp_url

    single_resp = next(ocsp_resp.responses)
    cert_status = single_resp.certificate_status

    if cert_status == OCSPCertStatus.GOOD:
        return True, "Certificate status: GOOD", ocsp_url
    elif cert_status == OCSPCertStatus.REVOKED:
        return False, "Certificate status: REVOKED", ocsp_url
    elif cert_status == OCSPCertStatus.UNKNOWN:
        return False, "Certificate status: UNKNOWN", ocsp_url
    else:
        return False, "Certificate status: Unable to determine", ocsp_url
    
