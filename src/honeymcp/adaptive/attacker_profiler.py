"""Profile attacker behavior for personalized ghost tool generation."""

import logging
from datetime import datetime
from typing import Dict, List, Optional
from collections import Counter

from honeymcp.models.adaptive_tools import (
    AttackerProfile,
    ToolGenerationHint,
)
from honeymcp.models.events import AttackFingerprint

logger = logging.getLogger(__name__)


class AttackerProfiler:
    """Profile attacker behavior to generate personalized honeypots.
    
    Features:
    - Real-time behavior analysis
    - Sophistication scoring
    - Tool preference learning
    - Attack sequence pattern detection
    - Personalized tool recommendations
    """

    def __init__(self) -> None:
        """Initialize attacker profiler."""
        self._profiles: Dict[str, AttackerProfile] = {}
        self._session_events: Dict[str, List[AttackFingerprint]] = {}
        
        logger.info("Attacker profiler initialized")

    async def analyze_session(
        self,
        session_id: str,
        events: List[AttackFingerprint],
    ) -> AttackerProfile:
        """Analyze session and create/update attacker profile.
        
        Args:
            session_id: Session identifier
            events: Attack events for this session
            
        Returns:
            Attacker profile
        """
        # Store events
        self._session_events[session_id] = events
        
        # Extract behavior patterns
        tool_preferences = self._extract_tool_preferences(events)
        attack_sequence = self._extract_attack_sequence(events)
        timing_pattern = self._analyze_timing_pattern(events)
        
        # Calculate sophistication
        sophistication_score = self._calculate_sophistication(events)
        tool_diversity = len(set(e.ghost_tool_called for e in events))
        uses_automation = self._detect_automation(events)
        
        # Generate recommendations
        recommended_tools = await self._recommend_tools(events)
        bait_chain = await self._generate_bait_chain(events)
        
        # Calculate confidence
        confidence = min(1.0, len(events) / 10.0)  # More events = higher confidence
        
        # Create or update profile
        profile = AttackerProfile(
            session_id=session_id,
            tool_preferences=tool_preferences,
            attack_sequence=attack_sequence,
            timing_pattern=timing_pattern,
            sophistication_score=sophistication_score,
            tool_diversity=tool_diversity,
            uses_automation=uses_automation,
            recommended_tools=recommended_tools,
            bait_chain=bait_chain,
            created_at=events[0].timestamp if events else datetime.utcnow(),
            last_updated=datetime.utcnow(),
            confidence=confidence,
        )
        
        self._profiles[session_id] = profile
        
        logger.info(
            "Created profile for session %s: sophistication=%.2f, diversity=%d",
            session_id,
            sophistication_score,
            tool_diversity,
        )
        
        return profile

    def _extract_tool_preferences(
        self,
        events: List[AttackFingerprint],
    ) -> List[str]:
        """Extract tool preferences from events.
        
        Args:
            events: Attack events
            
        Returns:
            List of preferred tools (most used first)
        """
        tool_counts = Counter(e.ghost_tool_called for e in events)
        return [tool for tool, _ in tool_counts.most_common(5)]

    def _extract_attack_sequence(
        self,
        events: List[AttackFingerprint],
    ) -> List[str]:
        """Extract typical attack sequence.
        
        Args:
            events: Attack events
            
        Returns:
            List of tools in order used
        """
        # Return unique tools in order of first use
        seen = set()
        sequence = []
        for event in events:
            tool = event.ghost_tool_called
            if tool not in seen:
                sequence.append(tool)
                seen.add(tool)
        return sequence

    def _analyze_timing_pattern(
        self,
        events: List[AttackFingerprint],
    ) -> str:
        """Analyze timing pattern of attacks.
        
        Args:
            events: Attack events
            
        Returns:
            Timing pattern: rapid, methodical, or sporadic
        """
        if len(events) < 2:
            return "unknown"
        
        # Calculate time between events
        intervals = []
        for i in range(1, len(events)):
            delta = (events[i].timestamp - events[i-1].timestamp).total_seconds()
            intervals.append(delta)
        
        avg_interval = sum(intervals) / len(intervals)
        
        # Classify pattern
        if avg_interval < 5:
            return "rapid"
        elif avg_interval < 30:
            return "methodical"
        else:
            return "sporadic"

    def _calculate_sophistication(
        self,
        events: List[AttackFingerprint],
    ) -> float:
        """Calculate attacker sophistication score.
        
        Args:
            events: Attack events
            
        Returns:
            Sophistication score (0.0 - 1.0)
        """
        score = 0.0
        
        # Factor 1: Tool diversity (0-0.3)
        unique_tools = len(set(e.ghost_tool_called for e in events))
        score += min(0.3, unique_tools * 0.05)
        
        # Factor 2: Attack categories (0-0.3)
        unique_categories = len(set(e.attack_category for e in events))
        score += min(0.3, unique_categories * 0.1)
        
        # Factor 3: Threat level (0-0.2)
        high_threat_count = sum(
            1 for e in events
            if e.threat_level in ["high", "critical"]
        )
        score += min(0.2, (high_threat_count / len(events)) * 0.2)
        
        # Factor 4: Persistence (0-0.2)
        if len(events) >= 10:
            score += 0.2
        elif len(events) >= 5:
            score += 0.1
        
        return min(1.0, score)

    def _detect_automation(
        self,
        events: List[AttackFingerprint],
    ) -> bool:
        """Detect if attacker is using automation.
        
        Args:
            events: Attack events
            
        Returns:
            True if automation detected
        """
        if len(events) < 3:
            return False
        
        # Check for very consistent timing (indicator of automation)
        intervals = []
        for i in range(1, len(events)):
            delta = (events[i].timestamp - events[i-1].timestamp).total_seconds()
            intervals.append(delta)
        
        if not intervals:
            return False
        
        # Calculate variance
        avg = sum(intervals) / len(intervals)
        variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
        
        # Low variance + rapid timing = likely automation
        return variance < 1.0 and avg < 2.0

    async def _recommend_tools(
        self,
        events: List[AttackFingerprint],
    ) -> List[str]:
        """Recommend tools likely to attract this attacker.
        
        Args:
            events: Attack events
            
        Returns:
            List of recommended tool names
        """
        recommendations = []
        
        # Analyze attack categories
        categories = [e.attack_category for e in events]
        category_counts = Counter(categories)
        
        # Recommend tools based on observed categories
        category_tool_map = {
            "credential_access": ["get_api_keys", "list_passwords", "dump_credentials"],
            "rce": ["execute_shell", "run_script", "spawn_process"],
            "exfiltration": ["download_data", "export_database", "copy_files"],
            "discovery": ["list_services", "enumerate_users", "scan_network"],
            "privilege_escalation": ["sudo_command", "escalate_privileges", "get_root"],
        }
        
        for category, _ in category_counts.most_common(3):
            if category in category_tool_map:
                recommendations.extend(category_tool_map[category])
        
        # Return unique recommendations
        return list(set(recommendations))[:5]

    async def _generate_bait_chain(
        self,
        events: List[AttackFingerprint],
    ) -> List[str]:
        """Generate bait chain to lead attacker deeper.
        
        Args:
            events: Attack events
            
        Returns:
            Sequence of tools to use as bait
        """
        if not events:
            return []
        
        # Start with tools similar to what they've used
        used_tools = [e.ghost_tool_called for e in events]
        
        # Create progression: discovery -> access -> exploitation
        bait_chain = []
        
        # If they've done discovery, offer access tools
        if any("list" in tool or "enumerate" in tool for tool in used_tools):
            bait_chain.append("access_database")
        
        # If they've accessed data, offer exploitation tools
        if any("read" in tool or "get" in tool for tool in used_tools):
            bait_chain.append("execute_query")
        
        # Always end with high-value target
        bait_chain.append("admin_panel")
        
        return bait_chain

    async def generate_hint(
        self,
        session_id: str,
    ) -> Optional[ToolGenerationHint]:
        """Generate tool generation hint for a session.
        
        Args:
            session_id: Session to analyze
            
        Returns:
            Generation hint if profile exists
        """
        profile = self._profiles.get(session_id)
        if not profile:
            return None
        
        events = self._session_events.get(session_id, [])
        if not events:
            return None
        
        # Determine suggested tool types
        suggested_types = []
        if profile.sophistication_score > 0.7:
            suggested_types.extend(["advanced", "technical", "privileged"])
        elif profile.sophistication_score > 0.4:
            suggested_types.extend(["intermediate", "common"])
        else:
            suggested_types.extend(["basic", "obvious"])
        
        # Determine suggested categories
        category_counts = Counter(e.attack_category for e in events)
        suggested_categories = [cat for cat, _ in category_counts.most_common(3)]
        
        hint = ToolGenerationHint(
            session_id=session_id,
            attempted_tools=profile.tool_preferences,
            attack_categories=suggested_categories,
            sophistication_level="high" if profile.sophistication_score > 0.7
                                else "medium" if profile.sophistication_score > 0.4
                                else "low",
            suggested_tool_types=suggested_types,
            suggested_categories=suggested_categories,
            timestamp=datetime.utcnow(),
            confidence=profile.confidence,
        )
        
        logger.info(
            "Generated hint for session %s: %s sophistication, %d categories",
            session_id,
            hint.sophistication_level,
            len(suggested_categories),
        )
        
        return hint

    def get_profile(self, session_id: str) -> Optional[AttackerProfile]:
        """Get profile for a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Profile if exists
        """
        return self._profiles.get(session_id)

    def get_all_profiles(self) -> Dict[str, AttackerProfile]:
        """Get all attacker profiles.
        
        Returns:
            Dictionary of session_id to profile
        """
        return self._profiles.copy()

    async def compare_profiles(
        self,
        session1: str,
        session2: str,
    ) -> Dict[str, any]:
        """Compare two attacker profiles.
        
        Args:
            session1: First session ID
            session2: Second session ID
            
        Returns:
            Comparison results
        """
        profile1 = self._profiles.get(session1)
        profile2 = self._profiles.get(session2)
        
        if not profile1 or not profile2:
            return {"error": "One or both profiles not found"}
        
        # Find common tools
        common_tools = set(profile1.tool_preferences) & set(profile2.tool_preferences)
        
        # Compare sophistication
        sophistication_diff = abs(profile1.sophistication_score - profile2.sophistication_score)
        
        # Determine if likely same attacker
        similarity_score = 0.0
        
        # Common tools increase similarity
        if common_tools:
            similarity_score += len(common_tools) * 0.2
        
        # Similar sophistication increases similarity
        if sophistication_diff < 0.2:
            similarity_score += 0.3
        
        # Same timing pattern increases similarity
        if profile1.timing_pattern == profile2.timing_pattern:
            similarity_score += 0.2
        
        similarity_score = min(1.0, similarity_score)
        
        return {
            "session1": session1,
            "session2": session2,
            "common_tools": list(common_tools),
            "sophistication_difference": sophistication_diff,
            "timing_match": profile1.timing_pattern == profile2.timing_pattern,
            "similarity_score": similarity_score,
            "likely_same_attacker": similarity_score > 0.6,
        }

    async def identify_campaigns(self) -> List[Dict[str, any]]:
        """Identify potential attack campaigns across sessions.
        
        Returns:
            List of identified campaigns
        """
        campaigns = []
        processed = set()
        
        # Compare all profile pairs
        session_ids = list(self._profiles.keys())
        
        for i, session1 in enumerate(session_ids):
            if session1 in processed:
                continue
            
            campaign_sessions = [session1]
            
            for session2 in session_ids[i+1:]:
                if session2 in processed:
                    continue
                
                comparison = await self.compare_profiles(session1, session2)
                
                if comparison.get("likely_same_attacker"):
                    campaign_sessions.append(session2)
                    processed.add(session2)
            
            if len(campaign_sessions) > 1:
                # Found a campaign
                profile1 = self._profiles[session1]
                campaigns.append({
                    "campaign_id": f"campaign_{len(campaigns) + 1}",
                    "sessions": campaign_sessions,
                    "session_count": len(campaign_sessions),
                    "sophistication": profile1.sophistication_score,
                    "common_tools": profile1.tool_preferences,
                })
                processed.add(session1)
        
        logger.info("Identified %d potential campaigns", len(campaigns))
        
        return campaigns

    async def get_statistics(self) -> Dict[str, any]:
        """Get profiling statistics.
        
        Returns:
            Statistics dictionary
        """
        if not self._profiles:
            return {
                "total_profiles": 0,
                "avg_sophistication": 0.0,
            }
        
        sophistication_scores = [p.sophistication_score for p in self._profiles.values()]
        
        return {
            "total_profiles": len(self._profiles),
            "avg_sophistication": sum(sophistication_scores) / len(sophistication_scores),
            "sophistication_distribution": {
                "high": len([s for s in sophistication_scores if s >= 0.7]),
                "medium": len([s for s in sophistication_scores if 0.4 <= s < 0.7]),
                "low": len([s for s in sophistication_scores if s < 0.4]),
            },
            "automation_detected": len([
                p for p in self._profiles.values()
                if p.uses_automation
            ]),
            "avg_tool_diversity": sum(
                p.tool_diversity for p in self._profiles.values()
            ) / len(self._profiles),
        }

    async def export_profiles(self) -> List[Dict[str, any]]:
        """Export all profiles for analysis.
        
        Returns:
            List of profile dictionaries
        """
        return [
            profile.model_dump(mode='json')
            for profile in self._profiles.values()
        ]

    async def clear_profiles(self, session_id: Optional[str] = None) -> None:
        """Clear profiles.
        
        Args:
            session_id: Specific session to clear, or None for all
        """
        if session_id:
            if session_id in self._profiles:
                del self._profiles[session_id]
            if session_id in self._session_events:
                del self._session_events[session_id]
            logger.info("Cleared profile for session: %s", session_id)
        else:
            self._profiles.clear()
            self._session_events.clear()
            logger.info("Cleared all profiles")
