from imports import *


def parse_html_output(html_text: str) -> dict:
    """Extracts structured certificate fields from the HTML string returned by check_certificate()."""
    def extract(label, text):
        match = re.search(rf"<b>{re.escape(label)}:</b>\s*(.*?)\n", text)
        return match.group(1).strip() if match else ""

    def extract_code(label, text):
        match = re.search(rf"<b>{re.escape(label)}:</b>\s*<code>(.*?)</code>", text)
        return match.group(1).strip() if match else ""

    return {
        "common_name": extract("Certificate CN", html_text),
        "issuer": extract("Issuer", html_text),
        "serial_number": extract("Serial No.", html_text),
        "certificate_type": extract("Certificate Type", html_text),
        "validity_left": extract("Validity Left", html_text),
        "revocation_status": "Not Revoked" if "Not Revoked" in html_text else "Revoked",
        "crl_url": extract_code("CRL URL", html_text),
        "crl_last_update": extract("CRL Last Update", html_text),
        "crl_next_update": extract("CRL Next Update", html_text),
        "ocsp_status": extract("OCSP Status", html_text)
    }
