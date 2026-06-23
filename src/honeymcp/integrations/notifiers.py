"""Multi-channel notification delivery with retry logic."""

import asyncio
import logging
import smtplib
import inspect
from abc import ABC, abstractmethod
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
import aiohttp

from honeymcp.models.alerts import Alert, AlertChannel, AlertConfig

logger = logging.getLogger(__name__)


async def _post(session: aiohttp.ClientSession, url: str, **kwargs):
    """Call session.post, supporting aiohttp and AsyncMock-style awaitables."""
    response = session.post(url, **kwargs)
    if inspect.isawaitable(response):
        response = await response
    return response


class NotifierBase(ABC):
    """Base class for notification delivery."""

    def __init__(self, config: AlertConfig) -> None:
        """Initialize notifier.

        Args:
            config: Alert configuration
        """
        self.config = config
        self.max_retries = config.max_retries
        self.retry_delay = config.retry_delay_seconds
        self.backoff_multiplier = config.retry_backoff_multiplier

    @abstractmethod
    async def send(self, alert: Alert) -> bool:
        """Send alert notification.

        Args:
            alert: Alert to send

        Returns:
            True if successful, False otherwise
        """
        pass

    async def send_with_retry(self, alert: Alert) -> bool:
        """Send alert with exponential backoff retry.

        Args:
            alert: Alert to send

        Returns:
            True if successful after retries, False otherwise
        """
        channel = self.get_channel_name()
        attempt = alert.delivery_attempts.get(channel, 0)

        while attempt < self.max_retries:
            try:
                alert.delivery_attempts[channel] = attempt + 1
                alert.last_attempt = datetime.utcnow()

                success = await self.send(alert)

                if success:
                    alert.delivery_status[channel] = "sent"
                    logger.info(
                        "Alert %s sent via %s on attempt %d", alert.alert_id, channel, attempt + 1
                    )
                    return True

                # Failed, will retry
                attempt += 1
                if attempt < self.max_retries:
                    delay = self.retry_delay * (self.backoff_multiplier**attempt)
                    logger.warning(
                        "Alert %s failed via %s, retrying in %.1fs (attempt %d/%d)",
                        alert.alert_id,
                        channel,
                        delay,
                        attempt + 1,
                        self.max_retries,
                    )
                    await asyncio.sleep(delay)

            except Exception as e:
                logger.error("Error sending alert %s via %s: %s", alert.alert_id, channel, str(e))
                attempt += 1
                if attempt < self.max_retries:
                    delay = self.retry_delay * (self.backoff_multiplier**attempt)
                    await asyncio.sleep(delay)

        # All retries exhausted
        alert.delivery_status[channel] = "failed"
        logger.error(
            "Alert %s failed via %s after %d attempts", alert.alert_id, channel, self.max_retries
        )
        return False

    @abstractmethod
    def get_channel_name(self) -> str:
        """Get channel name for this notifier."""
        pass


class SlackNotifier(NotifierBase):
    """Slack webhook notification delivery."""

    def get_channel_name(self) -> str:
        return AlertChannel.SLACK.value

    async def send(self, alert: Alert) -> bool:
        """Send alert to Slack.

        Args:
            alert: Alert to send

        Returns:
            True if successful
        """
        if not self.config.slack_webhook_url:
            logger.error("Slack webhook URL not configured")
            return False

        # Map severity to Slack colors
        color_map = {
            "info": "#36a64f",  # Green
            "warning": "#ff9900",  # Orange
            "error": "#ff0000",  # Red
            "critical": "#8b0000",  # Dark red
        }

        # Build Slack message
        payload = {
            "username": "HoneyMCP Security",
            "icon_emoji": ":shield:",
            "attachments": [
                {
                    "color": color_map.get(alert.severity.value, "#808080"),
                    "title": alert.title,
                    "text": alert.message,
                    "footer": f"Alert ID: {alert.alert_id}",
                    "ts": int(alert.timestamp.timestamp()),
                    "fields": [
                        {"title": "Severity", "value": alert.severity.value.upper(), "short": True},
                        {"title": "Rule", "value": alert.rule_id, "short": True},
                    ],
                }
            ],
        }

        # Add event/pattern links if available
        if alert.event_id:
            payload["attachments"][0]["fields"].append(
                {"title": "Event ID", "value": alert.event_id, "short": True}
            )

        if alert.pattern_id:
            payload["attachments"][0]["fields"].append(
                {"title": "Pattern ID", "value": alert.pattern_id, "short": True}
            )

        # Override channel if specified
        if self.config.slack_channel:
            payload["channel"] = self.config.slack_channel

        try:
            async with aiohttp.ClientSession() as session:
                async with await _post(
                    session,
                    self.config.slack_webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    if response.status == 200:
                        return True
                    else:
                        logger.error(
                            "Slack webhook returned status %d: %s",
                            response.status,
                            await response.text(),
                        )
                        return False
        except Exception as e:
            logger.error("Failed to send Slack notification: %s", str(e))
            return False


class PagerDutyNotifier(NotifierBase):
    """PagerDuty Events API v2 notification delivery."""

    def get_channel_name(self) -> str:
        return AlertChannel.PAGERDUTY.value

    async def send(self, alert: Alert) -> bool:
        """Send alert to PagerDuty.

        Args:
            alert: Alert to send

        Returns:
            True if successful
        """
        if not self.config.pagerduty_routing_key:
            logger.error("PagerDuty routing key not configured")
            return False

        # Map severity to PagerDuty severity
        severity_map = {
            "info": "info",
            "warning": "warning",
            "error": "error",
            "critical": "critical",
        }

        # Build PagerDuty event
        payload = {
            "routing_key": self.config.pagerduty_routing_key,
            "event_action": "trigger",
            "dedup_key": f"honeymcp_{alert.alert_id}",
            "payload": {
                "summary": alert.title,
                "severity": severity_map.get(alert.severity.value, "warning"),
                "source": "HoneyMCP",
                "timestamp": alert.timestamp.isoformat(),
                "custom_details": {
                    "message": alert.message,
                    "rule_id": alert.rule_id,
                    "alert_id": alert.alert_id,
                    **alert.metadata,
                },
            },
        }

        # Add links if available
        if alert.event_id or alert.pattern_id:
            payload["payload"]["custom_details"]["links"] = []
            if alert.event_id:
                payload["payload"]["custom_details"]["links"].append(
                    {"text": "View Event", "href": f"/events/{alert.event_id}"}
                )
            if alert.pattern_id:
                payload["payload"]["custom_details"]["links"].append(
                    {"text": "View Pattern", "href": f"/patterns/{alert.pattern_id}"}
                )

        try:
            async with aiohttp.ClientSession() as session:
                async with await _post(
                    session,
                    "https://events.pagerduty.com/v2/enqueue",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    if response.status == 202:
                        return True
                    else:
                        logger.error(
                            "PagerDuty API returned status %d: %s",
                            response.status,
                            await response.text(),
                        )
                        return False
        except Exception as e:
            logger.error("Failed to send PagerDuty notification: %s", str(e))
            return False


class EmailNotifier(NotifierBase):
    """SMTP email notification delivery."""

    def get_channel_name(self) -> str:
        return AlertChannel.EMAIL.value

    async def send(self, alert: Alert) -> bool:
        """Send alert via email.

        Args:
            alert: Alert to send

        Returns:
            True if successful
        """
        if not all([self.config.smtp_host, self.config.smtp_from, self.config.smtp_to]):
            logger.error("Email configuration incomplete")
            return False

        try:
            # Create message
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[{alert.severity.value.upper()}] {alert.title}"
            msg["From"] = self.config.smtp_from
            msg["To"] = ", ".join(self.config.smtp_to)
            msg["Date"] = alert.timestamp.strftime("%a, %d %b %Y %H:%M:%S +0000")

            # Plain text version
            text_body = f"""
HoneyMCP Security Alert

{alert.title}

{alert.message}

---
Alert ID: {alert.alert_id}
Rule: {alert.rule_id}
Severity: {alert.severity.value.upper()}
Time: {alert.timestamp.isoformat()}
"""

            # HTML version
            html_body = f"""
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; }}
        .header {{ background-color: #f44336; color: white; padding: 20px; }}
        .content {{ padding: 20px; }}
        .footer {{ background-color: #f0f0f0; padding: 10px; font-size: 12px; }}
        .severity-critical {{ color: #8b0000; }}
        .severity-error {{ color: #ff0000; }}
        .severity-warning {{ color: #ff9900; }}
        .severity-info {{ color: #36a64f; }}
    </style>
</head>
<body>
    <div class="header">
        <h2>🚨 HoneyMCP Security Alert</h2>
    </div>
    <div class="content">
        <h3 class="severity-{alert.severity.value}">{alert.title}</h3>
        <pre>{alert.message}</pre>
    </div>
    <div class="footer">
        <p>Alert ID: {alert.alert_id}</p>
        <p>Rule: {alert.rule_id}</p>
        <p>Severity: {alert.severity.value.upper()}</p>
        <p>Time: {alert.timestamp.isoformat()}</p>
    </div>
</body>
</html>
"""

            # Attach both versions
            msg.attach(MIMEText(text_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            # Send email (run in thread pool to avoid blocking)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._send_smtp, msg)

            return True

        except Exception as e:
            logger.error("Failed to send email notification: %s", str(e))
            return False

    def _send_smtp(self, msg: MIMEMultipart) -> None:
        """Send email via SMTP (blocking).

        Args:
            msg: Email message to send
        """
        with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port) as server:
            if self.config.smtp_username and self.config.smtp_password:
                server.starttls()
                server.login(self.config.smtp_username, self.config.smtp_password)

            server.send_message(msg)


class WebhookNotifier(NotifierBase):
    """Generic webhook notification delivery."""

    def get_channel_name(self) -> str:
        return AlertChannel.WEBHOOK.value

    async def send(self, alert: Alert) -> bool:
        """Send alert to webhooks.

        Args:
            alert: Alert to send

        Returns:
            True if all webhooks successful
        """
        if not self.config.webhook_urls:
            logger.error("No webhook URLs configured")
            return False

        # Build webhook payload
        payload = {
            "alert_id": alert.alert_id,
            "rule_id": alert.rule_id,
            "timestamp": alert.timestamp.isoformat(),
            "severity": alert.severity.value,
            "title": alert.title,
            "message": alert.message,
            "event_id": alert.event_id,
            "pattern_id": alert.pattern_id,
            "metadata": alert.metadata,
        }

        success_count = 0

        try:
            async with aiohttp.ClientSession() as session:
                tasks = []
                for url in self.config.webhook_urls:
                    tasks.append(self._send_to_webhook(session, url, payload))

                results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in results:
                    if result is True:
                        success_count += 1
                    elif isinstance(result, Exception):
                        logger.error("Webhook error: %s", str(result))

        except Exception as e:
            logger.error("Failed to send webhook notifications: %s", str(e))
            return False

        # Consider successful if at least one webhook succeeded
        return success_count > 0

    async def _send_to_webhook(
        self, session: aiohttp.ClientSession, url: str, payload: dict
    ) -> bool:
        """Send to a single webhook URL.

        Args:
            session: aiohttp session
            url: Webhook URL
            payload: JSON payload

        Returns:
            True if successful
        """
        try:
            async with await _post(
                session,
                url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as response:
                if 200 <= response.status < 300:
                    logger.debug("Webhook %s returned %d", url, response.status)
                    return True
                else:
                    logger.warning(
                        "Webhook %s returned %d: %s", url, response.status, await response.text()
                    )
                    return False
        except Exception as e:
            logger.error("Failed to send to webhook %s: %s", url, str(e))
            return False


class NotificationManager:
    """Manages multi-channel alert delivery."""

    def __init__(self, config: AlertConfig) -> None:
        """Initialize notification manager.

        Args:
            config: Alert configuration
        """
        self.config = config

        # Initialize notifiers
        self.notifiers = {
            AlertChannel.SLACK: SlackNotifier(config),
            AlertChannel.PAGERDUTY: PagerDutyNotifier(config),
            AlertChannel.EMAIL: EmailNotifier(config),
            AlertChannel.WEBHOOK: WebhookNotifier(config),
        }

        logger.info("Notification manager initialized with %d channels", len(self.notifiers))

    async def send_alert(self, alert: Alert) -> bool:
        """Send alert through all configured channels.

        Args:
            alert: Alert to send

        Returns:
            True if at least one channel succeeded
        """
        if not self.config.enabled:
            logger.debug("Alerting disabled, skipping alert %s", alert.alert_id)
            return False

        tasks = []

        for channel in alert.channels:
            if channel in self.notifiers:
                notifier = self.notifiers[channel]
                tasks.append(notifier.send_with_retry(alert))
            else:
                logger.warning("Unknown channel: %s", channel)

        if not tasks:
            logger.warning("No valid channels for alert %s", alert.alert_id)
            return False

        results = await asyncio.gather(*tasks, return_exceptions=True)

        success_count = sum(1 for r in results if r is True)

        logger.info(
            "Alert %s sent: %d/%d channels successful", alert.alert_id, success_count, len(tasks)
        )

        return success_count > 0

    async def send_alerts(self, alerts: list[Alert]) -> int:
        """Send multiple alerts.

        Args:
            alerts: List of alerts to send

        Returns:
            Number of alerts successfully sent
        """
        if not alerts:
            return 0

        tasks = [self.send_alert(alert) for alert in alerts]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        success_count = sum(1 for r in results if r is True)

        logger.info("Batch send complete: %d/%d alerts successful", success_count, len(alerts))

        return success_count
