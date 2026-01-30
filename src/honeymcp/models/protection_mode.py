"""Protection mode enum for HoneyMCP."""

from enum import Enum


class ProtectionMode(Enum):
    """Protection mode determining behavior after attacker detection.

    SCANNER: Lockout mode - all tools return errors after ghost tool is triggered.
             Best for automated scanners and bots.

    COGNITIVE: Deception mode - real tools return fake/mock data, ghost tools
               continue returning fake responses. Best for sophisticated attackers.
    """

    SCANNER = "scanner"
    COGNITIVE = "cognitive"
