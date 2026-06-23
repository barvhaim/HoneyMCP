"""Forensic report generation for attack sessions."""

import logging
from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4

from honeymcp.models.events import AttackFingerprint
from honeymcp.models.forensics import (
    AttackTimeline,
    ComparisonReport,
    ForensicReport,
)

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate forensic reports from attack timelines.

    Features:
    - Executive summaries
    - Attack analysis and IOC extraction
    - MITRE ATT&CK mapping
    - Security recommendations
    - Multi-session comparison
    """

    def __init__(self) -> None:
        """Initialize report generator."""
        # MITRE ATT&CK mappings for common attack categories
        self._mitre_mappings = {
            "exfiltration": {
                "tactics": ["TA0010"],  # Exfiltration
                "techniques": ["T1020", "T1041", "T1567"],  # Automated, C2, Web Service
            },
            "rce": {
                "tactics": ["TA0002", "TA0003"],  # Execution, Persistence
                "techniques": [
                    "T1059",
                    "T1203",
                    "T1569",
                ],  # Command Interpreter, Exploitation, System Services
            },
            "privilege_escalation": {
                "tactics": ["TA0004"],  # Privilege Escalation
                "techniques": [
                    "T1068",
                    "T1078",
                    "T1548",
                ],  # Exploitation, Valid Accounts, Abuse Elevation
            },
            "credential_access": {
                "tactics": ["TA0006"],  # Credential Access
                "techniques": [
                    "T1003",
                    "T1110",
                    "T1555",
                ],  # Credential Dumping, Brute Force, Credentials from Password Stores
            },
            "discovery": {
                "tactics": ["TA0007"],  # Discovery
                "techniques": [
                    "T1083",
                    "T1087",
                    "T1518",
                ],  # File Discovery, Account Discovery, Software Discovery
            },
            "lateral_movement": {
                "tactics": ["TA0008"],  # Lateral Movement
                "techniques": [
                    "T1021",
                    "T1080",
                    "T1550",
                ],  # Remote Services, Taint Shared Content, Use Alternate Auth
            },
            "defense_evasion": {
                "tactics": ["TA0005"],  # Defense Evasion
                "techniques": [
                    "T1027",
                    "T1070",
                    "T1562",
                ],  # Obfuscation, Indicator Removal, Impair Defenses
            },
        }

        logger.info("Report generator initialized")

    async def generate_report(
        self,
        timeline: AttackTimeline,
        analyst_notes: Optional[str] = None,
    ) -> ForensicReport:
        """Generate comprehensive forensic report.

        Args:
            timeline: Attack timeline to analyze
            analyst_notes: Optional analyst notes

        Returns:
            Complete forensic report
        """
        report_id = f"report_{uuid4().hex[:12]}"

        # Generate executive summary
        summary = self._generate_summary(timeline)

        # Determine severity
        severity = self._assess_severity(timeline)

        # Analyze attack vector
        attack_vector = self._identify_attack_vector(timeline)

        # Extract techniques
        techniques = self._extract_techniques(timeline)

        # Extract IOCs
        iocs = self._extract_iocs(timeline)

        # Generate recommendations
        recommendations = self._generate_recommendations(timeline)
        mitigation_steps = self._generate_mitigation_steps(timeline)

        # Map to MITRE ATT&CK
        mitre_tactics, mitre_techniques = self._map_to_mitre(timeline)

        # Generate tags
        tags = self._generate_tags(timeline)

        report = ForensicReport(
            report_id=report_id,
            session_id=timeline.session_id,
            generated_at=datetime.utcnow(),
            title=f"Attack Analysis: Session {timeline.session_id[:8]}",
            summary=summary,
            severity=severity,
            timeline=timeline,
            attack_vector=attack_vector,
            techniques_used=techniques,
            indicators_of_compromise=iocs,
            recommendations=recommendations,
            mitigation_steps=mitigation_steps,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            analyst_notes=analyst_notes,
            tags=tags,
        )

        logger.info(
            "Generated forensic report %s for session %s",
            report_id,
            timeline.session_id,
        )

        return report

    def _generate_summary(self, timeline: AttackTimeline) -> str:
        """Generate executive summary."""
        duration_str = self._format_duration(timeline.duration_seconds)

        summary_parts = [
            f"Attack session detected with {timeline.event_count} malicious attempts over {duration_str}.",
            f"Attacker targeted {len(timeline.unique_tools_used)} different honeypot tools.",
            f"Attack categories observed: {', '.join(timeline.attack_categories)}.",
            f"Maximum threat level: {timeline.max_threat_level.upper()}.",
        ]

        # Add sophistication assessment
        if timeline.event_count >= 10:
            summary_parts.append("High persistence observed - sustained attack campaign.")
        elif len(timeline.unique_tools_used) >= 5:
            summary_parts.append(
                "High sophistication - diverse tool usage indicates skilled attacker."
            )

        return " ".join(summary_parts)

    def _assess_severity(self, timeline: AttackTimeline) -> str:
        """Assess overall attack severity."""
        # Score based on multiple factors
        score = 0

        # Threat level (0-40 points)
        threat_scores = {"low": 10, "medium": 20, "high": 30, "critical": 40}
        score += threat_scores.get(timeline.max_threat_level, 0)

        # Event count (0-30 points)
        if timeline.event_count >= 20:
            score += 30
        elif timeline.event_count >= 10:
            score += 20
        elif timeline.event_count >= 5:
            score += 10

        # Tool diversity (0-20 points)
        if len(timeline.unique_tools_used) >= 5:
            score += 20
        elif len(timeline.unique_tools_used) >= 3:
            score += 10

        # Duration (0-10 points)
        if timeline.duration_seconds >= 3600:  # 1 hour
            score += 10
        elif timeline.duration_seconds >= 600:  # 10 minutes
            score += 5

        # Map score to severity
        if score >= 70:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 30:
            return "medium"
        else:
            return "low"

    def _identify_attack_vector(self, timeline: AttackTimeline) -> str:
        """Identify primary attack vector."""
        # Analyze first few tools to determine initial vector
        if not timeline.tool_sequence:
            return "Unknown"

        first_tools = timeline.tool_sequence[:3]

        # Common patterns
        if any("list" in tool.lower() or "enumerate" in tool.lower() for tool in first_tools):
            return "Reconnaissance and Discovery"
        elif any("execute" in tool.lower() or "command" in tool.lower() for tool in first_tools):
            return "Remote Code Execution"
        elif any(
            "credential" in tool.lower() or "password" in tool.lower() for tool in first_tools
        ):
            return "Credential Access"
        elif any("secret" in tool.lower() or "key" in tool.lower() for tool in first_tools):
            return "Secrets Exfiltration"
        else:
            return f"Tool-based Attack ({first_tools[0]})"

    def _extract_techniques(self, timeline: AttackTimeline) -> List[str]:
        """Extract attack techniques from timeline."""
        techniques = set()

        for event in timeline.events:
            tool = event.tool_name or ""

            # Map tool names to techniques
            if "list" in tool.lower() or "enumerate" in tool.lower():
                techniques.add("System Enumeration")
            if "execute" in tool.lower() or "command" in tool.lower():
                techniques.add("Command Execution")
            if "credential" in tool.lower() or "password" in tool.lower():
                techniques.add("Credential Harvesting")
            if "secret" in tool.lower() or "key" in tool.lower():
                techniques.add("Secrets Extraction")
            if "database" in tool.lower() or "sql" in tool.lower():
                techniques.add("Database Access")
            if "file" in tool.lower() or "read" in tool.lower():
                techniques.add("File System Access")
            if "network" in tool.lower() or "scan" in tool.lower():
                techniques.add("Network Scanning")
            if "privilege" in tool.lower() or "escalate" in tool.lower():
                techniques.add("Privilege Escalation")

        return sorted(list(techniques))

    def _extract_iocs(self, timeline: AttackTimeline) -> List[str]:
        """Extract indicators of compromise."""
        iocs = []

        # Tool usage patterns
        if len(timeline.unique_tools_used) >= 5:
            iocs.append(f"High tool diversity: {len(timeline.unique_tools_used)} unique tools")

        # Rapid succession attacks
        if timeline.avg_time_between_events < 5:
            iocs.append(
                f"Rapid attack sequence: {timeline.avg_time_between_events:.1f}s between attempts"
            )

        # Specific tool sequences
        if len(timeline.tool_sequence) >= 3:
            sequence_str = " -> ".join(timeline.tool_sequence[:3])
            iocs.append(f"Attack sequence: {sequence_str}")

        # Session duration
        if timeline.duration_seconds >= 3600:
            iocs.append(f"Sustained attack: {self._format_duration(timeline.duration_seconds)}")

        # High threat level
        if timeline.max_threat_level in ["high", "critical"]:
            iocs.append(f"Critical threat level: {timeline.max_threat_level}")

        return iocs

    def _generate_recommendations(self, timeline: AttackTimeline) -> List[str]:
        """Generate security recommendations."""
        recommendations = []

        # Based on threat level
        if timeline.max_threat_level in ["high", "critical"]:
            recommendations.append("Immediate investigation required - critical threat detected")
            recommendations.append("Review authentication logs for this session")
            recommendations.append("Consider blocking source if identifiable")

        # Based on persistence
        if timeline.event_count >= 10:
            recommendations.append("Implement rate limiting to prevent sustained attacks")
            recommendations.append("Enable session lockout after repeated honeypot triggers")

        # Based on tool diversity
        if len(timeline.unique_tools_used) >= 5:
            recommendations.append("Attacker shows high sophistication - enhance monitoring")
            recommendations.append("Share threat intelligence with security community")

        # Based on categories
        if "rce" in timeline.attack_categories:
            recommendations.append("Review and harden command execution controls")
        if "exfiltration" in timeline.attack_categories:
            recommendations.append("Implement data loss prevention measures")
        if "credential_access" in timeline.attack_categories:
            recommendations.append("Enforce multi-factor authentication")

        # General recommendations
        recommendations.append("Update ghost tool catalog based on attacker behavior")
        recommendations.append("Document attack patterns for future detection")

        return recommendations

    def _generate_mitigation_steps(self, timeline: AttackTimeline) -> List[str]:
        """Generate specific mitigation steps."""
        steps = []

        steps.append(f"1. Block session {timeline.session_id} from further access")
        steps.append("2. Review all accessed resources during attack window")
        steps.append("3. Verify no actual system compromise occurred")

        if timeline.max_threat_level in ["high", "critical"]:
            steps.append("4. Escalate to security incident response team")
            steps.append("5. Conduct full security audit of affected systems")

        steps.append("6. Update detection rules based on observed patterns")
        steps.append("7. Share IOCs with threat intelligence platforms")

        return steps

    def _map_to_mitre(self, timeline: AttackTimeline) -> tuple[List[str], List[str]]:
        """Map attack to MITRE ATT&CK framework."""
        tactics = set()
        techniques = set()

        for category in timeline.attack_categories:
            mapping = self._mitre_mappings.get(category, {})
            tactics.update(mapping.get("tactics", []))
            techniques.update(mapping.get("techniques", []))

        return sorted(list(tactics)), sorted(list(techniques))

    def _generate_tags(self, timeline: AttackTimeline) -> List[str]:
        """Generate report tags for categorization."""
        tags = []

        # Severity tag
        tags.append(f"severity:{timeline.max_threat_level}")

        # Category tags
        for category in timeline.attack_categories:
            tags.append(f"category:{category}")

        # Sophistication tags
        if len(timeline.unique_tools_used) >= 5:
            tags.append("sophisticated")
        if timeline.event_count >= 10:
            tags.append("persistent")
        if timeline.duration_seconds >= 3600:
            tags.append("sustained")

        return tags

    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable form."""
        if seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            return f"{seconds / 60:.1f} minutes"
        else:
            return f"{seconds / 3600:.1f} hours"

    async def compare_sessions(
        self,
        timelines: List[AttackTimeline],
    ) -> ComparisonReport:
        """Generate comparison report for multiple sessions.

        Args:
            timelines: List of attack timelines to compare

        Returns:
            Comparison report

        Raises:
            ValueError: If fewer than 2 timelines provided
        """
        if len(timelines) < 2:
            raise ValueError("Need at least 2 timelines for comparison")

        report_id = f"comparison_{uuid4().hex[:12]}"
        session_ids = [t.session_id for t in timelines]

        # Find common tools
        tool_sets = [set(t.unique_tools_used) for t in timelines]
        common_tools = list(set.intersection(*tool_sets))

        # Find common categories
        category_sets = [set(t.attack_categories) for t in timelines]
        common_categories = list(set.intersection(*category_sets))

        # Find unique tools per session
        unique_tools_per_session = {}
        for timeline in timelines:
            other_tools = set()
            for other in timelines:
                if other.session_id != timeline.session_id:
                    other_tools.update(other.unique_tools_used)

            unique = set(timeline.unique_tools_used) - other_tools
            unique_tools_per_session[timeline.session_id] = list(unique)

        # Calculate averages
        avg_duration = sum(t.duration_seconds for t in timelines) / len(timelines)
        avg_events = sum(t.event_count for t in timelines) / len(timelines)

        # Calculate sophistication scores (simplified)
        sophistication_scores = {}
        for timeline in timelines:
            score = (
                len(timeline.unique_tools_used) * 0.4
                + timeline.event_count * 0.3
                + (timeline.duration_seconds / 3600) * 0.3
            )
            sophistication_scores[timeline.session_id] = min(1.0, score / 10)

        # Generate analysis
        analysis = self._generate_comparison_analysis(
            timelines,
            common_tools,
            common_categories,
        )

        # Identify similarities and differences
        similarities = self._identify_similarities(timelines, common_tools, common_categories)
        differences = self._identify_differences(timelines, unique_tools_per_session)

        report = ComparisonReport(
            report_id=report_id,
            session_ids=session_ids,
            generated_at=datetime.utcnow(),
            common_tools=common_tools,
            common_categories=common_categories,
            unique_tools_per_session=unique_tools_per_session,
            avg_duration=avg_duration,
            avg_events_per_session=avg_events,
            sophistication_scores=sophistication_scores,
            analysis=analysis,
            similarities=similarities,
            differences=differences,
        )

        logger.info(
            "Generated comparison report for %d sessions",
            len(timelines),
        )

        return report

    def _generate_comparison_analysis(
        self,
        timelines: List[AttackTimeline],
        common_tools: List[str],
        common_categories: List[str],
    ) -> str:
        """Generate comparative analysis summary."""
        parts = []

        parts.append(f"Comparison of {len(timelines)} attack sessions.")

        if common_tools:
            parts.append(
                f"All sessions used {len(common_tools)} common tools: {', '.join(common_tools[:3])}."
            )
        else:
            parts.append("No common tools across all sessions - diverse attack patterns.")

        if common_categories:
            parts.append(f"Common attack categories: {', '.join(common_categories)}.")

        # Analyze timing patterns
        durations = [t.duration_seconds for t in timelines]
        if max(durations) / min(durations) > 5:
            parts.append("Significant variation in attack duration - different attacker profiles.")
        else:
            parts.append("Similar attack durations - potentially coordinated or automated.")

        return " ".join(parts)

    def _identify_similarities(
        self,
        timelines: List[AttackTimeline],
        common_tools: List[str],
        common_categories: List[str],
    ) -> List[str]:
        """Identify key similarities."""
        similarities = []

        if common_tools:
            similarities.append(f"Common tools: {', '.join(common_tools)}")

        if common_categories:
            similarities.append(f"Common categories: {', '.join(common_categories)}")

        # Check for similar timing patterns
        avg_times = [t.avg_time_between_events for t in timelines]
        if max(avg_times) / min(avg_times) < 2:
            similarities.append("Similar attack pacing across sessions")

        return similarities

    def _identify_differences(
        self,
        timelines: List[AttackTimeline],
        unique_tools_per_session: Dict[str, List[str]],
    ) -> List[str]:
        """Identify key differences."""
        differences = []

        # Tool diversity
        tool_counts = [len(t.unique_tools_used) for t in timelines]
        if max(tool_counts) > min(tool_counts) * 2:
            differences.append(
                f"Tool diversity varies: {min(tool_counts)}-{max(tool_counts)} tools per session"
            )

        # Duration variance
        durations = [t.duration_seconds for t in timelines]
        if max(durations) > min(durations) * 3:
            differences.append(
                f"Duration varies significantly: {min(durations):.0f}s to {max(durations):.0f}s"
            )

        # Unique tools
        for session_id, tools in unique_tools_per_session.items():
            if tools:
                differences.append(
                    f"Session {session_id[:8]} uniquely used: {', '.join(tools[:3])}"
                )

        return differences
