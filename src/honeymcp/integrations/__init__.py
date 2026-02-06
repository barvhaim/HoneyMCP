"""External integrations for HoneyMCP."""

from honeymcp.integrations.slack import build_slack_payload, send_slack_webhook

__all__ = ["build_slack_payload", "send_slack_webhook"]
