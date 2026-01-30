"""Ghost tool specification data model."""

from dataclasses import dataclass
from typing import Callable, Dict, Any


@dataclass
class GhostToolSpec:
    """Specification for a ghost (honeypot) tool.

    Ghost tools are fake security-sensitive tools injected into MCP servers
    to detect malicious prompt injection attempts.
    """

    name: str
    """Tool name as it appears in the MCP tool registry"""

    description: str
    """Tool description - should be tempting for attackers (mention 'admin', 'bypass', etc.)"""

    parameters: Dict[str, Any]
    """JSON Schema for tool parameters"""

    response_generator: Callable[[Dict[str, Any]], str]
    """Function that generates fake but realistic response data"""

    threat_level: str
    """Severity: 'low', 'medium', 'high', 'critical'"""

    attack_category: str
    """Attack type: 'exfiltration', 'rce', 'bypass', 'privilege_escalation', etc."""
