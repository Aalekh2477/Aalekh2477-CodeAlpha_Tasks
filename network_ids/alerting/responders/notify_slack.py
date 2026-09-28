#!/usr/bin/env python3
"""
Slack Notification Responder
============================
Send formatted alerts to Slack channels.
"""

import argparse
import json
import logging
import os
import requests
from datetime import datetime
from typing import Dict, Any

# Configuration
LOG_FILE = Path("/var/log/nids/notify_slack.log")

# Default Slack webhook (override with env var)
DEFAULT_WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL", "")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('notify-slack')

# Severity colors for Slack attachments
SEVERITY_COLORS = {
    "critical": "danger",
    "high": "warning",
    "medium": "#ff9900",
    "low": "good",
    "info": "#36a64f"
}

SEVERITY_EMOJIS = {
    "critical": ":rotating_light:",
    "high": ":warning:",
    "medium": ":exclamation:",
    "low": ":information_source:",
    "info": ":information_source:"
}


def send_slack_alert(
    webhook_url: str,
    alert_data: Dict[str, Any],
    channel: str = "#security-alerts",
    username: str = "NIDS Bot",
    icon_emoji: str = ":shield:",
    mention_users: list = None
) -> bool:
    """
    Send alert to Slack channel.

    Args:
        webhook_url: Slack incoming webhook URL
        alert_data: Dictionary containing alert information
        channel: Slack channel to post to
        username: Bot username
        icon_emoji: Bot icon emoji
        mention_users: List of user IDs to mention (e.g., ["@U123456"])

    Returns:
        True if successful, False otherwise
    """
    try:
        # Extract alert data with defaults
        rule_msg = alert_data.get("rule_msg", "Unknown Alert")
        rule_id = alert_data.get("rule_id", 0)
        severity = alert_data.get("severity", "medium").lower()
        src_ip = alert_data.get("src_ip", "Unknown")
        src_port = alert_data.get("src_port", 0)
        dst_ip = alert_data.get("dst_ip", "Unknown")
        dst_port = alert_data.get("dst_port", 0)
        protocol = alert_data.get("protocol", "Unknown")
        source = alert_data.get("source", "NIDS")
        timestamp = alert_data.get("timestamp", datetime.utcnow().isoformat())
        payload_preview = alert_data.get("payload", "")[:500]
        metadata = alert_data.get("metadata", {})

        # Format severity
        color = SEVERITY_COLORS.get(severity, "warning")
        emoji = SEVERITY_EMOJIS.get(severity, ":warning:")

        # Build user mentions
        mentions = ""
        if mention_users:
            mentions = " ".join(mention_users) + " "

        # Build attachment
        attachment = {
            "color": color,
            "title": f"{emoji} [{severity.upper()}] {rule_msg}",
            "title_link": f"https://rules.emergingthreats.net/open/suricata/{alert_data.get('rule_id', 0)}" if alert_data.get('rule_id') else "",
            "fields": [
                {
                    "title": "Rule ID",
                    "value": str(rule_id),
                    "short": True
                },
                {
                    "title": "Severity",
                    "value": severity.upper(),
                    "short": True
                },
                {
                    "title": "Source IP",
                    "value": f"{src_ip}:{src_port}" if src_port else src_ip,
                    "short": True
                },
                {
                    "title": "Destination IP",
                    "value": f"{dst_ip}:{dst_port}" if dst_port else dst_ip,
                    "short": True
                },
                {
                    "title": "Protocol",
                    "value": protocol,
                    "short": True
                },
                {
                    "title": "Source",
                    "value": source,
                    "short": True
                },
            ]

            # Add metadata fields if present
            if metadata.get("category"):
                attachment["fields"].append({
                    "title": "Category",
                    "value": metadata["category"],
                    "short": True
                })

            if metadata.get("flow_id"):
                attachment["fields"].append({
                    "title": "Flow ID",
                    "value": str(metadata["flow_id"]),
                    "short": True
                })

            # Add payload preview if available
            if payload_preview:
                attachment["fields"].append({
                    "title": "Payload Preview",
                    "value": f"```{payload_preview[:500]}```",
                    "short": False
                })

            # Add user mentions
            if mention_users:
                attachment["pretext"] = " ".join(mention_users)

            # Build payload
            payload = {
                "channel": channel,
                "username": username,
                "icon_emoji": icon_emoji,
                "attachments": [attachment]
            }

            # Send to Slack
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                logger.info(f"Slack alert sent successfully for rule {alert_data.get('rule_id')}")
                return True
            else:
                logger.error(f"Slack webhook returned {response.status_code}: {response.text}")
                return False

        except requests.exceptions.Timeout:
            logger.error("Slack webhook timeout")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Slack request failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending Slack alert: {e}")
            return False


def format_alert_for_slack(alert: Dict) -> Dict:
    """Format alert for Slack Block Kit (richer formatting)"""
    severity = alert.get("severity", "medium").lower()
    color = SEVERITY_COLORS.get(severity, "warning")

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{SEVERITY_EMOJIS.get(severity, ':warning:')} NIDS Alert: {alert.get('rule_msg', 'Unknown')}",
                "emoji": True
            }
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Rule ID:*\n{alert.get('rule_id', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Severity:*\n{alert.get('severity', 'medium').upper()}"},
                {"type": "mrkdwn", "text": f"*Source:*\n{alert.get('src_ip', 'N/A')}:{alert.get('src_port', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Destination:*\n{alert.get('dst_ip', 'N/A')}:{alert.get('dst_port', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Protocol:*\n{alert.get('protocol', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Source:*\n{alert.get('source', 'N/A')}"},
            ]
        }
    ]

    if alert.get("payload"):
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Payload Preview:*\n```{alert.get('payload', '')[:500]}```"
            }
        })

    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": f"Timestamp: {alert.get('timestamp', datetime.utcnow().isoformat())} | Source: {alert.get('source', 'N/A')} | Rule ID: {alert.get('rule_id', 'N/A')}"}
        ]
    })

    return {
        "blocks": blocks,
        "attachments": [{
            "color": color,
            "blocks": blocks
        }]
    }


def send_slack_block_alert(
    webhook_url: str,
    alert_data: Dict[str, Any],
    channel: str = "#security-alerts"
) -> bool:
    """Send alert using Slack Block Kit formatting"""
    try:
        payload = format_alert_for_slack(alert_data)
        payload["channel"] = channel

        response = requests.post(
            webhook_url,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"}
        )

        return response.status_code == 200

    except Exception as e:
        logger.error(f"Slack Block Kit alert failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Send alert to Slack")
    parser.add_argument("--webhook-url", default=DEFAULT_WEBHOOK, help="Slack webhook URL")
    parser.add_argument("--channel", default="#security-alerts", help="Slack channel")
    parser.add_argument("--username", default="NIDS Bot", help="Bot username")
    parser.add_argument("--icon-emoji", default=":shield:", help="Bot icon emoji")
    parser.add_argument("--mention", action="append", help="User IDs to mention (e.g., @U123456)")
    parser.add_argument("--blocks", action="store_true", help="Use Block Kit formatting")

    # Alert data
    parser.add_argument("--rule-id", type=int, required=True, help="Rule ID")
    parser.add_argument("--rule-msg", required=True, help="Rule message")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default="medium")
    parser.add_argument("--src-ip", required=True, help="Source IP")
    parser.add_argument("--src-port", type=int, default=0, help="Source port")
    parser.add_argument("--dst-ip", required=True, help="Destination IP")
    parser.add_argument("--dst-port", type=int, default=0, help="Destination port")
    parser.add_argument("--protocol", default="TCP", help="Protocol")
    parser.add_argument("--source", default="suricata", help="Alert source (suricata/snort)")
    parser.add_argument("--payload", default="", help="Payload preview")
    parser.add_argument("--timestamp", default=datetime.utcnow().isoformat(), help="Alert timestamp")
    parser.add_argument("--category", default="", help="Alert category")
    parser.add_argument("--flow-id", type=int, default=0, help="Flow ID")

    args = parser.parse_args()

    if not args.webhook_url:
        parser.error("Webhook URL required (--webhook-url or SLACK_WEBHOOK_URL env var)")

    # Build alert data
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
        "payload": args.payload,
        "timestamp": args.timestamp,
        "metadata": {
            "category": args.category,
            "flow_id": args.flow_id
        }
    }

    if args.blocks:
        success = send_slack_block_alert(args.webhook_url, alert_data, args.channel)
    else:
        success = send_slack_alert(
            args.webhook_url,
            alert_data,
            channel=args.channel,
            username=args.username,
            icon_emoji=args.icon_emoji,
            mention_users=args.mention
        )

    if success:
        print("Slack notification sent successfully")
        sys.exit(0)
    else:
        print("Failed to send Slack notification")
        sys.exit(1)


if __name__ == "__main__":
    from pathlib import Path
    import sys
    main()