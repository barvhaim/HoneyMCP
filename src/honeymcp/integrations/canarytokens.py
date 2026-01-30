"""Canarytoken integration for real trap credentials.

Integrates with canarytokens.org to generate real trap credentials that alert
when used externally. This provides confirmation of credential exfiltration.

Docs: https://docs.canarytokens.org/guide/aws-keys-token.html
"""

import random
import string
from typing import Dict

import requests


def create_aws_canarytoken(email: str, memo: str) -> Dict[str, str]:
    """Create an AWS API key Canarytoken via canarytokens.org.

    When these credentials are used anywhere, an alert is sent to the email.

    Args:
        email: Email address to receive alerts
        memo: Description/memo for this token

    Returns:
        Dictionary with:
        - access_key_id: AWS access key ID (starts with AKIA)
        - secret_access_key: AWS secret access key
        - canarytoken_id: Unique token identifier

    Raises:
        requests.RequestException: If API call fails

    Example:
        >>> token = create_aws_canarytoken(
        ...     email="security@company.com",
        ...     memo="HoneyMCP trap - list_cloud_secrets"
        ... )
        >>> print(token['access_key_id'])
        AKIAIOSFODNN7EXAMPLE
    """
    try:
        # Call canarytokens.org API
        response = requests.post(
            "https://canarytokens.org/generate",
            data={
                "type": "aws-id",
                "email": email,
                "memo": memo,
            },
            timeout=10,
        )

        if response.status_code == 200:
            data = response.json()
            return {
                "access_key_id": data.get("aws_access_key_id", ""),
                "secret_access_key": data.get("aws_secret_access_key", ""),
                "canarytoken_id": data.get("token", ""),
            }
        # API call failed - fall back to fake credentials
        raise requests.RequestException(
            f"Canarytoken API returned {response.status_code}"
        )

    except Exception as e:
        # If Canarytoken generation fails, fall back to fake credentials
        # This ensures HoneyMCP still works even if the API is down
        print(f"Warning: Canarytoken generation failed ({e}), using fake credentials")
        return _generate_fake_aws_credentials()


def _generate_fake_aws_credentials() -> Dict[str, str]:
    """Generate fake AWS credentials as fallback.

    These look realistic but won't trigger alerts when used.
    """
    # AWS access keys start with AKIA
    access_key_id = "AKIA" + "".join(
        random.choices(string.ascii_uppercase + string.digits, k=16)
    )

    # AWS secret keys are 40 characters
    secret_access_key = "".join(
        random.choices(string.ascii_letters + string.digits + "+/", k=40)
    )

    return {
        "access_key_id": access_key_id,
        "secret_access_key": secret_access_key,
        "canarytoken_id": None,  # No token ID for fake credentials
    }


def create_webhook_canarytoken(webhook_url: str, memo: str) -> Dict[str, str]:
    """Create a generic webhook Canarytoken.

    Args:
        webhook_url: URL to receive POST when token is triggered
        memo: Description/memo for this token

    Returns:
        Dictionary with token details
    """
    try:
        response = requests.post(
            "https://canarytokens.org/generate",
            data={
                "type": "web",
                "webhook_url": webhook_url,
                "memo": memo,
            },
            timeout=10,
        )

        if response.status_code == 200:
            data = response.json()
            return {
                "canarytoken_url": data.get("url", ""),
                "canarytoken_id": data.get("token", ""),
            }
        raise requests.RequestException(
            f"Canarytoken API returned {response.status_code}"
        )

    except Exception as e:
        print(f"Warning: Webhook Canarytoken generation failed: {e}")
        return {
            "canarytoken_url": None,
            "canarytoken_id": None,
        }


def verify_canarytoken_triggered(
    canarytoken_id: str,
) -> bool:  # pylint: disable=unused-argument
    """Check if a Canarytoken has been triggered.

    Note: This requires access to the Canarytoken API with authentication.
    For the MVP, we rely on email alerts instead.

    Args:
        canarytoken_id: Token identifier

    Returns:
        True if token was triggered, False otherwise
    """
    # TODO: Implement when API authentication is available
    # For now, we update events when receiving webhook callbacks
    return False
