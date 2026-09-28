#!/usr/bin/env python3
"""
Email Notification Responder
============================
Send formatted security alerts via email with HTML support.
"""

import argparse
import json
import logging
import os
import smtplib
import ssl
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, List, Optional
from pathlib import Path

# Configuration
LOG_FILE = Path("/var/log/nids/notify_email.log")

# Default SMTP settings (override with env vars)
DEFAULT_SMTP_SERVER = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
DEFAULT_SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
DEFAULT_USERNAME = os.environ.get("SMTP_USERNAME", "")
DEFAULT_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
DEFAULT_FROM_EMAIL = os.environ.get("FROM_EMAIL", "nids@company.com")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('notify-email')

# HTML Email Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NIDS Security Alert</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }}
        .container {{ background: #fff; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }}
        .header {{ background: {severity_color}; color: white; padding: 30px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .header .severity-badge {{ display: inline-block; background: rgba(255,255,255,0.2); padding: 8px 16px; border-radius: 20px; font-size: 14px; font-weight: bold; margin-top: 10px; }}
        .content {{ padding: 30px; }}
        .alert-summary {{ background: #f8f9fa; border-radius: 8px; padding: 20px; margin-bottom: 20px; border-left: 4px solid {severity_color}; }}
        .alert-summary h2 {{ margin: 0 0 15px 0; color: {severity_color}; }}
        .details {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .detail-item {{ background: #f8f9fa; padding: 15px; border-radius: 6px; }}
        .detail-label {{ font-size: 12px; text-transform: uppercase; color: #666; font-weight: 600; }}
        .detail-value {{ font-size: 16px; font-weight: 500; color: #333; word-break: break-all; }}
        .payload-section {{ background: #f8f9fa; border-radius: 8px; padding: 20px; margin-top: 20px; }}
        .payload-section h3 {{ margin: 0 0 15px 0; color: #333; }}
        .payload-content {{ background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 6px; font-family: 'Monaco', 'Menlo', monospace; font-size: 13px; overflow-x: auto; white-space: pre-wrap; }}
        .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 13px; border-top: 1px solid #eee; }}
        .footer a {{ color: #007bff; text-decoration: none; }}
        .severity-critical {{ background: #dc3545; }}
        .severity-high {{ background: #fd7e14; }}
        .severity-medium {{ background: #ffc107; }}
        .severity-low {{ background: #28a745; }}
        .severity-info {{ background: #17a2b8; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header severity-{severity_class}">
            <h1>🛡️ NIDS Security Alert</h1>
            <div class="severity-badge">{severity_upper} SEVERITY</div>
        </div>
        <div class="content">
            <div class="alert-summary">
                <h2>{rule_msg}</h2>
                <p><strong>Rule ID:</strong> {rule_id} | <strong>Source:</strong> {source} | <strong>Time:</strong> {timestamp}</p>
            </div>

            <div class="details">
                <div class="detail-item">
                    <div class="detail-label">Severity</div>
                    <div class="detail-value severity-{severity_class}">{severity_upper}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Rule ID</div>
                    <div class="detail-value">{rule_id}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Source IP</div>
                    <div class="detail-value">{src_ip}:{src_port}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Destination IP</div>
                    <div class="detail-value">{dst_ip}:{dst_port}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Protocol</div>
                    <div class="detail-value">{protocol}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Source</div>
                    <div class="detail-value">{source}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Category</div>
                    <div class="detail-value">{category}</div>
                </div>
                <div class="detail-item">
                    <div class="detail-label">Flow ID</div>
                    <div class="detail-value">{flow_id}</div>
                </div>
            </div>

            {payload_section}

            <div style="text-align: center; margin-top: 30px;">
                <a href="https://rules.emergingthreats.net/open/suricata/{rule_id}" style="display: inline-block; background: #007bff; color: white; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: 600;">View Rule Details</a>
            </div>
        </div>
        <div class="footer">
            <p>This alert was generated by <strong>NIDS (Network Intrusion Detection System)</strong></p>
            <p>Timestamp: {timestamp} | Alert ID: {alert_hash}</p>
            <p>Please investigate and take appropriate action according to your incident response procedures.</p>
        </div>
    </div>
</body>
</html>
"""

# Text Email Template
TEXT_TEMPLATE = """
NIDS SECURITY ALERT - {severity_upper} SEVERITY
=================================================

Alert: {rule_msg}
Rule ID: {rule_id}
Severity: {severity_upper}
Time: {timestamp}
Source: {source}

Network Details:
----------------
Source IP:      {src_ip}:{src_port}
Destination IP: {dst_ip}:{dst_port}
Protocol:       {protocol}
Category:       {category}
Flow ID:        {flow_id}

{payload_section}

------------------------------------------------
This alert was generated by NIDS (Network Intrusion Detection System)
Please investigate and take appropriate action according to your incident response procedures.

Rule Details: https://rules.emergingthreats.net/open/suricata/{rule_id}
Alert Hash: {alert_hash}
"""

# Severity color mapping
SEVERITY_COLORS = {
    "critical": "#dc3545",
    "high": "#fd7e14",
    "medium": "#ffc107",
    "low": "#28a745",
    "info": "#17a2b8"
}


def send_email_alert(
    alert_data: Dict[str, Any],
    recipients: List[str],
    smtp_server: str = DEFAULT_SMTP_SERVER,
    smtp_port: int = DEFAULT_SMTP_PORT,
    username: str = DEFAULT_USERNAME,
    password: str = DEFAULT_PASSWORD,
    from_email: str = DEFAULT_FROM_EMAIL,
    use_tls: bool = True
) -> bool:
    """
    Send security alert via email.

    Args:
        alert_data: Dictionary containing alert information
        recipients: List of recipient email addresses
        smtp_server: SMTP server hostname
        smtp_port: SMTP server port
        username: SMTP username
        password: SMTP password
        from_email: Sender email address
        use_tls: Whether to use TLS

    Returns:
        True if successful, False otherwise
    """
    try:
        # Extract alert data
        rule_id = alert_data.get("rule_id", 0)
        rule_msg = alert_data.get("rule_msg", "Unknown Alert")
        severity = alert_data.get("severity", "medium").lower()
        src_ip = alert_data.get("src_ip", "Unknown")
        src_port = alert_data.get("src_port", 0)
        dst_ip = alert_data.get("dst_ip", "Unknown")
        dst_port = alert_data.get("dst_port", 0)
        protocol = alert_data.get("protocol", "Unknown")
        source = alert_data.get("source", "NIDS")
        timestamp = alert_data.get("timestamp", datetime.utcnow().isoformat())
        category = alert_data.get("metadata", {}).get("category", "General")
        flow_id = alert_data.get("metadata", {}).get("flow_id", "N/A")
        payload = alert_data.get("payload", "")
        alert_hash = alert_data.get("alert_hash", "")

        # Severity formatting
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8"
        }
        severity_color = severity_colors.get(severity, "#ffc107")
        severity_class = severity
        severity_upper = severity.upper()

        # Build payload section
        if payload:
            payload_html = f"""
            <div class="payload-section">
                <h3>Payload Preview</h3>
                <div class="payload-content">{payload[:1000]}</div>
            </div>
            """
            payload_text = f"\nPayload Preview:\n{payload[:1000]}\n"
        else:
            payload_html = ""
            payload_text = ""

        # Generate alert hash if not present
        if not alert_hash:
            hash_input = f"{rule_id}_{src_ip}_{dst_ip}_{timestamp[:16]}"
            import hashlib
            alert_hash = hashlib.md5(hash_input.encode()).hexdigest()[:16]

        # Create message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[NIDS {severity_upper}] {rule_msg} (SID: {rule_id})"
        msg["From"] = from_email
        msg["To"] = ", ".join(recipients)
        msg["X-Priority"] = "1" if severity in ("critical", "high") else "3"
        msg["X-MSMail-Priority"] = "High" if severity in ("critical", "high") else "Normal"

        # Text part
        text_body = TEXT_TEMPLATE.format(
            severity_upper=severity_upper,
            rule_msg=rule_msg,
            rule_id=rule_id,
            severity=severity,
            timestamp=timestamp,
            source=source,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            category=category,
            flow_id=flow_id,
            payload_section=payload_text,
            rule_id=rule_id,
            alert_hash=alert_hash
        )
        msg.attach(MIMEText(text_body, "plain", "utf-8"))

        # HTML part
        html_body = HTML_TEMPLATE.format(
            severity_color=severity_color,
            severity_class=severity_class,
            severity_upper=severity_upper,
            rule_msg=rule_msg,
            rule_id=rule_id,
            timestamp=timestamp,
            source=source,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            category=category,
            flow_id=flow_id,
            payload_section=payload_html,
            rule_id=rule_id,
            alert_hash=alert_hash
        )
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        # Send email
        context = ssl.create_default_context()

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            if use_tls:
                server.starttls(context=context)
            if username and password:
                server.login(username, password)
            server.sendmail(from_email, recipients, msg.as_string())

        logger.info(f"Email alert sent to {len(recipients)} recipients for rule {rule_id}")
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP authentication failed")
        return False
    except smtplib.SMTPRecipientsRefused:
        logger.error("Recipients refused")
        return False
    except smtplib.SMTPServerDisconnected:
        logger.error("SMTP server disconnected")
        return False
    except smtplib.SMTPException as e:
        logger.error(f"SMTP error: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending email: {e}")
        return False


def send_bulk_email_alerts(
    alerts: List[Dict[str, Any]],
    recipients: List[str],
    smtp_server: str = DEFAULT_SMTP_SERVER,
    smtp_port: int = DEFAULT_SMTP_PORT,
    username: str = DEFAULT_USERNAME,
    password: str = DEFAULT_PASSWORD,
    from_email: str = DEFAULT_FROM_EMAIL,
    digest_mode: bool = True
) -> bool:
    """
    Send multiple alerts in a single digest email.

    Args:
        alerts: List of alert dictionaries
        recipients: List of recipient emails
        Other args same as send_email_alert

    Returns:
        True if successful
    """
    if not alerts:
        return True

    if len(alerts) == 1:
        return send_email_alert(alerts[0], recipients, smtp_server, smtp_port, username, password, from_email)

    if not digest_mode:
        # Send individual emails
        success = True
        for alert in alerts:
            if not send_email_alert(alert, recipients, smtp_server, smtp_port, username, password, from_email):
                success = False
        return success

    # Digest mode - single email with all alerts
    try:
        # Group by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        alerts_sorted = sorted(alerts, key=lambda a: severity_order.get(a.get("severity", "medium"), 2))

        # Build digest
        critical_count = sum(1 for a in alerts if a.get("severity") == "critical")
        high_count = sum(1 for a in alerts if a.get("severity") == "high")
        total_count = len(alerts)

        # Determine overall severity
        overall_severity = "info"
        for sev in ["critical", "high", "medium", "low", "info"]:
            if any(a.get("severity") == sev for a in alerts):
                overall_severity = sev
                break

        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8"
        }
        overall_color = severity_colors.get(overall_severity, "#ffc107")

        # Build HTML
        alerts_html = ""
        for alert in alerts_sorted:
            sev = alert.get("severity", "medium").lower()
            sev_color = {
                "critical": "#dc3545", "high": "#fd7e14",
                "medium": "#ffc107", "low": "#28a745", "info": "#17a2b8"
            }.get(sev, "#ffc107")

            alerts_html += f"""
            <div style="border-left: 4px solid {sev_color}; background: #f8f9fa; padding: 15px; margin-bottom: 15px; border-radius: 4px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                    <strong>{alert.get('rule_msg', 'Unknown')}</strong>
                    <span style="background: {sev_color}; color: white; padding: 2px 8px; border-radius: 12px; font-size: 12px;">{sev.upper()}</span>
                </div>
                <div style="font-size: 13px; color: #666;">
                    Rule ID: {alert.get('rule_id')} | Source: {alert.get('src_ip')}:{alert.get('src_port')} → {alert.get('dst_ip')}:{alert.get('dst_port')} | Protocol: {alert.get('protocol')} | Time: {alert.get('timestamp')}
                </div>
            </div>
            """

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }}
                .header {{ background: {overall_color}; color: white; padding: 30px; text-align: center; border-radius: 8px 8px 0 0; }}
                .content {{ padding: 30px; background: white; }}
                .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
                .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 13px; border-radius: 0 0 8px 8px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1 style="margin: 0;">🛡️ NIDS Security Alert Digest</h1>
                <div style="margin-top: 10px; opacity: 0.9;">{total_count} alerts | {critical_count} critical | {high_count} high</div>
            </div>
            <div class="content">
                <div class="summary">
                    <h3 style="margin: 0 0 10px 0;">Alert Summary</h3>
                    <p>Generated at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
                </div>
                {alerts_html}
            </div>
            <div class="footer">
                <p>This digest was generated by <strong>NIDS</strong> at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</p>
                <p>Please review all alerts and take appropriate action.</p>
            </div>
        </body>
        </html>
        """

        text_body = f"""
NIDS SECURITY ALERT DIGEST
==========================

Total Alerts: {total_count}
Critical: {critical_count}
High: {high_count}

Generated at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC

Please review all alerts in the HTML version of this email.

------------------------------------------------
This digest was generated by NIDS (Network Intrusion Detection System)
"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[NIDS Digest] {total_count} Security Alerts ({critical_count} Critical, {high_count} High)"
        msg["From"] = from_email
        msg["To"] = ", ".join(recipients)

        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        msg.attach(MIMEText(html_body, "html", "utf-8"))

        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls(context=ssl.create_default_context())
            if username and password:
                server.login(username, password)
            server.sendmail(from_email, recipients, msg.as_string())

        logger.info(f"Digest email sent to {len(recipients)} recipients with {total_count} alerts")
        return True

    except Exception as e:
        logger.error(f"Failed to send digest email: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Send NIDS alert via email")
    parser.add_argument("--smtp-server", default=DEFAULT_SMTP_SERVER, help="SMTP server")
    parser.add_argument("--smtp-port", type=int, default=DEFAULT_SMTP_PORT, help="SMTP port")
    parser.add_argument("--username", default=DEFAULT_USERNAME, help="SMTP username")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="SMTP password")
    parser.add_argument("--from-email", default=DEFAULT_FROM_EMAIL, help="From email")
    parser.add_argument("--recipients", required=True, help="Comma-separated recipient emails")
    parser.add_argument("--no-tls", action="store_true", help="Disable TLS")

    # Alert data
    parser.add_argument("--rule-id", type=int, required=True, help="Rule ID")
    parser.add_argument("--rule-msg", required=True, help="Rule message")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default="medium")
    parser.add_argument("--src-ip", required=True, help="Source IP")
    parser.add_argument("--src-port", type=int, default=0, help="Source port")
    parser.add_argument("--dst-ip", required=True, help="Destination IP")
    parser.add_argument("--dst-port", type=int, default=0, help="Destination port")
    parser.add_argument("--protocol", default="TCP", help="Protocol")
    parser.add_argument("--source", default="suricata", help="Alert source")
    parser.add_argument("--category", default="General", help="Alert category")
    parser.add_argument("--flow-id", type=int, default=0, help="Flow ID")
    parser.add_argument("--payload", default="", help="Payload preview")
    parser.add_argument("--timestamp", default=datetime.utcnow().isoformat(), help="Alert timestamp")

    args = parser.parse_args()

    if not args.username or not args.password:
        logger.error("SMTP username and password required")
        sys.exit(1)

    recipients = [r.strip() for r in args.recipients.split(",")]

    alert_data = {
        "rule_id": args.rule_id,
        "rule_msg": args.rule_msg,
        "severity": args.severity,
        "src_ip": args.src_ip,
        "src_port": args.src_port,
        "dst_ip": args.dst_ip,
        "dst_port": args.dst_port,
        "protocol": args.protocol,
        "source": args.source,
        "metadata": {
            "category": args.category,
            "flow_id": args.flow_id
        },
        "payload": args.payload,
        "timestamp": args.timestamp
    }

    success = send_email_alert(
        alert_data,
        recipients,
        smtp_server=args.smtp_server,
        smtp_port=args.smtp_port,
        username=args.username,
        password=args.password,
        from_email=args.from_email,
        use_tls=not args.no_tls
    )

    if success:
        print(f"Email sent successfully to {len(recipients)} recipients")
        sys.exit(0)
    else:
        print("Failed to send email")
        sys.exit(1)


if __name__ == "__main__":
    import sys
    main()