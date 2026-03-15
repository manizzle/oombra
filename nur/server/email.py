"""Send verification emails via SMTP."""
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def send_verification_email(to_email: str, verify_url: str) -> bool:
    """Send a magic link verification email. Returns True on success."""
    smtp_host = os.environ.get("SMTP_HOST", "")
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASS", "")

    if not smtp_host or not smtp_user or not smtp_pass:
        print("[nur] SMTP not configured (set SMTP_HOST, SMTP_USER, SMTP_PASS)")
        return False

    # Build email
    msg = MIMEMultipart("alternative")
    msg["From"] = f"nur <{smtp_user}>"
    msg["To"] = to_email
    msg["Subject"] = "nur — verify your email"

    text = f"""nur — verify your email

Click the link below to get your API key:

{verify_url}

This link expires in 24 hours.

---
nur — collective security intelligence
https://nur.saramena.us
"""

    html = f"""<html><body style="background:#0a0a0a;color:#c0c0c0;font-family:monospace;padding:40px">
<h1 style="color:#f0f0f0">nur</h1>
<p>Click to verify your email and get your API key:</p>
<p><a href="{verify_url}" style="display:inline-block;padding:12px 24px;background:#1a1a1a;border:1px solid #444;color:#e0e0e0;text-decoration:none;border-radius:4px;font-family:monospace">verify email &rarr; get API key</a></p>
<p style="color:#555;font-size:0.85em">Or copy this link: {verify_url}</p>
<p style="color:#444;font-size:0.8em;margin-top:32px">This link expires in 24 hours.</p>
<hr style="border:none;border-top:1px solid #1a1a1a;margin:24px 0">
<p style="color:#333;font-size:0.75em">nur — collective security intelligence<br><a href="https://nur.saramena.us" style="color:#444">nur.saramena.us</a></p>
</body></html>"""

    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
            s.ehlo()
            s.starttls()
            s.login(smtp_user, smtp_pass)
            s.sendmail(smtp_user, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"[nur] Email send error: {e}")
        return False
