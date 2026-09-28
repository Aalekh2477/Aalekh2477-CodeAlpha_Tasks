#!/usr/bin/env python3
"""
Generic Webhook Responder
=========================
Send alerts to generic HTTP webhook endpoints with customizable payload.
"""

import argparse
import json
import logging
import os
import hmac
import hashlib
import time
import requests
from datetime import datetime
from typing import Dict, Any, List, Optional
from pathlib import Path

# Configuration
LOG_FILE = Path("/var/log/nids/notify_webhook.log")

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('notify-webhook')


def send_webhook_alert(
    webhook_url: str,
    alert_data: Dict[str, Any],
    method: str = "POST",
    headers: Optional[Dict[str, str]] = None,
    auth: Optional[tuple] = None,
    timeout: int = 10,
    sign_payload: bool = False,
    secret: Optional[str] = None,
    template: Optional[str] = None
) -> bool:
    """
    Send alert to generic webhook endpoint.

    Args:
        webhook_url: Target webhook URL
        alert_data: Alert data dictionary
        method: HTTP method (POST, PUT, PATCH)
        headers: Additional HTTP headers
        auth: Tuple of (username, password) for basic auth
        timeout: Request timeout in seconds
        sign_payload: Whether to sign payload with HMAC
        secret: Secret key for HMAC signing
        template: Jinja2 template string for payload transformation

    Returns:
        True if successful, False otherwise
    """
    try:
        # Prepare payload
        if template:
            # Use Jinja2 template if provided
            try:
                from jinja2 import Template
                payload = json.loads(Template(template).render(alert=alert_data))
            except ImportError:
                logger.error("Jinja2 not installed, using raw alert data")
                payload = alert_data
            except Exception as e:
                logger.error(f"Template rendering failed: {e}")
                payload = alert_data
        else:
            payload = alert_data

        # Add webhook metadata
        payload["_webhook"] = {
            "timestamp": datetime.utcnow().isoformat(),
            "source": "nids",
            "version": "1.0"
        }

        # Prepare headers
        req_headers = {
            "Content-Type": "application/json",
            "User-Agent": "NIDS-Webhook/1.0"
        }
        if headers:
            req_headers.update(headers)

        # Sign payload if requested
        if sign_payload and secret:
            payload_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
            signature = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
            req_headers["X-NIDS-Signature"] = f"sha256={signature}"
            req_headers["X-NIDS-Timestamp"] = str(int(time.time()))

        # Send request
        response = requests.request(
            method=method.upper(),
            url=webhook_url,
            json=payload,
            headers=req_headers,
            auth=auth,
            timeout=timeout
        )

        # Check response
        if 200 <= response.status_code < 300:
            logger.info(f"Webhook alert sent successfully to {webhook_url} (status: {response.status_code})")
            return True
        else:
            logger.error(f"Webhook returned {response.status_code}: {response.text[:200]}")
            return False

    except requests.exceptions.Timeout:
        logger.error(f"Webhook timeout after {timeout}s")
        return False
    except requests.exceptions.ConnectionError:
        logger.error(f"Connection error to {webhook_url}")
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Webhook request failed: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending webhook: {e}")
        return False


def send_batch_webhook(
    webhook_url: str,
    alerts: List[Dict[str, Any]],
    batch_size: int = 10,
    **kwargs
) -> int:
    """
    Send multiple alerts in batches.

    Args:
        webhook_url: Target webhook URL
        alerts: List of alert dictionaries
        batch_size: Number of alerts per batch
        **kwargs: Additional arguments passed to send_webhook_alert

    Returns:
        Number of successfully sent batches
    """
    if not alerts:
        return 0

    sent = 0
    for i in range(0, len(alerts), batch_size):
        batch = alerts[i:i + batch_size]
        batch_payload = {
            "batch": True,
            "count": len(batch),
            "timestamp": datetime.utcnow().isoformat(),
            "alerts": batch
        }

        if send_webhook_alert(webhook_url, batch_payload, **kwargs):
            sent += 1
        else:
            logger.error(f"Failed to send batch {i//batch_size + 1}")

    return sent


def test_webhook(webhook_url: str, **kwargs) -> bool:
    """Send test payload to verify webhook connectivity"""
    test_payload = {
        "test": True,
        "message": "NIDS webhook connectivity test",
        "timestamp": datetime.utcnow().isoformat(),
        "source": "nids-webhook-test"
    }

    logger.info(f"Testing webhook: {webhook_url}")
    return send_webhook_alert(webhook_url, test_payload, **kwargs)


class WebhookDispatcher:
    """Manage multiple webhook endpoints with routing"""

    def __init__(self, config_file: Optional[str] = None):
        self.endpoints = {}
        self.default_config = {}
        if config_file:
            self.load_config(config_file)

    def load_config(self, config_file: str):
        """Load webhook endpoints from YAML config"""
        import yaml
        with open(config_file) as f:
            config = yaml.safe_load(f)

        self.default_config = config.get("defaults", {})
        for endpoint in config.get("endpoints", []):
            name = endpoint.get("name")
            if name:
                self.endpoints[name] = endpoint

    def add_endpoint(self, name: str, url: str, **config):
        """Add a webhook endpoint"""
        self.endpoints[name] = {"url": url, **config}

    def dispatch(self, alert_data: Dict[str, Any], endpoint_names: Optional[List[str]] = None) -> Dict[str, bool]:
        """Dispatch alert to specified endpoints"""
        results = {}
        targets = endpoint_names or list(self.endpoints.keys())

        for name in targets:
            if name not in self.endpoints:
                logger.warning(f"Unknown endpoint: {name}")
                results[name] = False
                continue

            endpoint = self.endpoints[name]
            # Merge default config with endpoint config
            config = {**self.default_config, **endpoint}

            success = send_webhook_alert(
                webhook_url=endpoint["url"],
                alert_data=alert_data,
                method=config.get("method", "POST"),
                headers=config.get("headers"),
                auth=tuple(config["auth"]) if config.get("auth") else None,
                timeout=config.get("timeout", 10),
                sign_payload=config.get("sign_payload", False),
                secret=config.get("secret"),
                template=config.get("template")
            )
            results[name] = success

        return results

    def dispatch_batch(self, alerts: List[Dict[str, Any]], endpoint_names: Optional[List[str]] = None) -> Dict[str, int]:
        """Dispatch batch of alerts to endpoints"""
        results = {}
        targets = endpoint_names or list(self.endpoints.keys())

        for name in targets:
            if name not in self.endpoints:
                results[name] = 0
                continue

            endpoint = self.endpoints[name]
            config = {**self.default_config, **endpoint}

            sent = send_batch_webhook(
                webhook_url=endpoint["url"],
                alerts=alerts,
                batch_size=config.get("batch_size", 10),
                method=config.get("method", "POST"),
                headers=config.get("headers"),
                auth=tuple(config["auth"]) if config.get("auth") else None,
                timeout=config.get("timeout", 10),
                sign_payload=config.get("sign_payload", False),
                secret=config.get("secret"),
                template=config.get("template")
            )
            results[name] = sent

        return results


def main():
    parser = argparse.ArgumentParser(description="Send NIDS alert to webhook")
    parser.add_argument("--url", required=True, help="Webhook URL")
    parser.add_argument("--method", choices=["POST", "PUT", "PATCH"], default="POST", help="HTTP method")
    parser.add_argument("--headers", help="Additional headers as JSON")
    parser.add_argument("--auth", help="Basic auth as user:pass")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--sign", action="store_true", help="Sign payload with HMAC")
    parser.add_argument("--secret", help="HMAC secret key")
    parser.add_argument("--template", help="Jinja2 template for payload")
    parser.add_argument("--batch-size", type=int, default=10, help="Batch size for multiple alerts")
    parser.add_argument("--test", action="store_true", help="Send test payload")

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
        "metadata": {
            "category": args.category,
            "flow_id": args.flow_id
        },
        "payload": args.payload,
        "timestamp": args.timestamp
    }

    # Parse headers
    headers = {}
    if args.headers:
        try:
            headers = json.loads(args.headers)
        except json.JSONDecodeError:
            logger.error("Invalid headers JSON")
            sys.exit(1)

    # Parse auth
    auth = None
    if args.auth:
        parts = args.auth.split(":", 1)
        if len(parts) == 2:
            auth = tuple(parts)

    if args.test:
        success = test_webhook(
            args.url,
            method=args.method,
            headers=headers,
            auth=auth,
            timeout=args.timeout,
            sign_payload=args.sign,
            secret=args.secret
        )
    else:
        success = send_webhook_alert(
            webhook_url=args.url,
            alert_data=alert_data,
            method=args.method,
            headers=headers,
            auth=auth,
            timeout=args.timeout,
            sign_payload=args.sign,
            secret=args.secret,
            template=args.template
        )

    if success:
        print("Webhook sent successfully")
        sys.exit(0)
    else:
        print("Failed to send webhook")
        sys.exit(1)


if __name__ == "__main__":
    import sys
    main()