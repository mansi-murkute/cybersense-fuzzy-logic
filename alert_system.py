"""
Email Alert System
Sends a Gmail SMTP alert when a CRITICAL threat is detected.
Uses an App Password (not your Gmail password).
"""

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def send_email_alert(to_email: str, smtp_user: str, smtp_pass: str, event: dict):
    """
    Send a CRITICAL threat alert email via Gmail SMTP.

    Parameters
    ----------
    to_email  : recipient email
    smtp_user : Gmail address used to send
    smtp_pass : Gmail App Password (16-char, spaces removed)
    event     : threat event dict from FuzzyThreatEngine.assess()
    """
    subject = f"⚠️ CRITICAL CYBER THREAT DETECTED — Score {event.get('risk_score','?')}/100"

    html_body = f"""
    <html><body style="background:#050a0f;color:#c8d8e8;font-family:monospace;padding:24px;">
    <div style="border:2px solid #ff0033;border-radius:8px;padding:24px;max-width:600px;margin:auto;background:#0a1628;">
      <h2 style="color:#ff0033;margin-top:0;">⚠️ CRITICAL THREAT ALERT</h2>
      <p style="color:#4a7fa5;">Your CyberSense AI system has detected a critical-level cyber threat.</p>
      <table style="width:100%;border-collapse:collapse;">
        <tr><td style="color:#4a7fa5;padding:6px 0;">Time</td>
            <td style="color:#00aaff;">{event.get('timestamp','N/A')}</td></tr>
        <tr><td style="color:#4a7fa5;padding:6px 0;">Attack Type</td>
            <td style="color:#ff6600;">{event.get('attack_type','Unknown')}</td></tr>
        <tr><td style="color:#4a7fa5;padding:6px 0;">Source IP</td>
            <td style="color:#ff0033;">{event.get('source_ip','N/A')}</td></tr>
        <tr><td style="color:#4a7fa5;padding:6px 0;">Risk Score</td>
            <td style="color:#ff0033;font-size:1.4rem;font-weight:bold;">{event.get('risk_score','?')} / 100</td></tr>
        <tr><td style="color:#4a7fa5;padding:6px 0;">Packet Rate</td>
            <td style="color:#c8d8e8;">{event.get('packet_rate','?')} pkt/s</td></tr>
        <tr><td style="color:#4a7fa5;padding:6px 0;">Failed Logins</td>
            <td style="color:#c8d8e8;">{event.get('failed_logins','?')}</td></tr>
        <tr><td style="color:#4a7fa5;padding:6px 0;">Port Diversity</td>
            <td style="color:#c8d8e8;">{event.get('port_diversity','?')} ports</td></tr>
      </table>
      <hr style="border-color:#1a3a5c;margin:16px 0;">
      <p style="color:#4a7fa5;font-size:13px;">{event.get('explanation','')}</p>
      <p style="color:#1a3a5c;font-size:11px;margin-top:20px;">Sent by CyberSense AI · Fuzzy Threat Detection System</p>
    </div>
    </body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = smtp_user
    msg["To"]      = to_email
    msg.attach(MIMEText(html_body, "html"))

    smtp_pass_clean = smtp_pass.replace(" ", "")
    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(smtp_user, smtp_pass_clean)
        server.sendmail(smtp_user, to_email, msg.as_string())
