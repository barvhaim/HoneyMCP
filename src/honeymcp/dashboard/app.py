"""HoneyMCP Dashboard - Real-time attack visualization with Streamlit."""

import asyncio
import sys
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import List

import streamlit as st

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# pylint: disable=wrong-import-position
from honeymcp.models.events import AttackFingerprint
from honeymcp.storage.event_store import list_events

# Page configuration
st.set_page_config(
    page_title="HoneyMCP Dashboard",
    page_icon="🍯",
    layout="wide",
    initial_sidebar_state="expanded",
)


def load_events() -> List[AttackFingerprint]:
    """Load attack events from storage."""
    try:
        events = asyncio.run(list_events())
        return events
    except Exception as e:
        st.error(f"Failed to load events: {e}")
        return []


def get_threat_emoji(threat_level: str) -> str:
    """Get emoji for threat level."""
    emoji_map = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
    }
    return emoji_map.get(threat_level.lower(), "⚪")


def format_timestamp(dt: datetime) -> str:
    """Format timestamp for display."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def main():  # pylint: disable=too-many-branches,too-many-statements
    """Main dashboard application."""

    # Header
    st.title("🍯 HoneyMCP Dashboard")
    st.markdown("**Real-time AI Agent Attack Detection & Intelligence**")
    st.markdown("---")

    # Load events
    events = load_events()

    # Sidebar filters
    st.sidebar.header("Filters")

    # Date range filter
    if events:
        min_date = min(e.timestamp for e in events).date()
        max_date = max(e.timestamp for e in events).date()
    else:
        min_date = date.today() - timedelta(days=7)
        max_date = date.today()

    st.sidebar.date_input(
        "Date Range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date,
    )

    # Threat level filter
    threat_filter = st.sidebar.selectbox(
        "Threat Level",
        ["All", "Critical", "High", "Medium", "Low"],
    )

    # Attack category filter
    if events:
        categories = sorted(set(e.attack_category for e in events))
    else:
        categories = []

    category_filter = st.sidebar.selectbox(
        "Attack Category",
        ["All"] + categories,
    )

    # Apply filters
    filtered_events = events

    if threat_filter != "All":
        filtered_events = [
            e for e in filtered_events if e.threat_level.lower() == threat_filter.lower()
        ]

    if category_filter != "All":
        filtered_events = [e for e in filtered_events if e.attack_category == category_filter]

    # Metrics row
    st.header("📊 Attack Metrics")
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        today_attacks = len([e for e in events if (datetime.utcnow() - e.timestamp).days < 1])
        st.metric(
            "Total Attacks",
            len(events),
            delta=f"+{today_attacks} today",
        )

    with col2:
        critical_count = len([e for e in events if e.threat_level == "critical"])
        st.metric("Critical Threats", critical_count)

    with col3:
        unique_tools = len(set(e.ghost_tool_called for e in events)) if events else 0
        st.metric("Unique Ghost Tools", unique_tools)

    with col4:
        if events:
            unique_sessions = len(set(e.session_id for e in events))
            st.metric("Unique Sessions", unique_sessions)
        else:
            st.metric("Unique Sessions", 0)

    st.markdown("---")

    # Attack breakdown
    if events:
        st.header("🎯 Attack Breakdown")
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("By Threat Level")
            threat_counts = {}
            for e in events:
                threat_counts[e.threat_level] = threat_counts.get(e.threat_level, 0) + 1
            st.bar_chart(threat_counts)

        with col2:
            st.subheader("By Category")
            category_counts = {}
            for e in events:
                category_counts[e.attack_category] = category_counts.get(e.attack_category, 0) + 1
            st.bar_chart(category_counts)

        st.markdown("---")

    # Event feed
    st.header("🚨 Recent Attacks")

    if not filtered_events:
        st.info("No attacks detected yet. Ghost tools are active and monitoring.")
    else:
        # Sort by timestamp (newest first)
        filtered_events.sort(key=lambda e: e.timestamp, reverse=True)

        # Display events
        for event in filtered_events:
            threat_emoji = get_threat_emoji(event.threat_level)

            # Expander header with key info
            header = (
                f"{threat_emoji} **{event.ghost_tool_called}** | "
                f"{format_timestamp(event.timestamp)} | "
                f"Session: {event.session_id[:8]}... | "
                f"Threat: {event.threat_level.upper()}"
            )

            with st.expander(header):
                # Event details
                col1, col2 = st.columns(2)

                with col1:
                    st.markdown("**Event Details**")
                    st.text(f"Event ID: {event.event_id}")
                    st.text(f"Timestamp: {format_timestamp(event.timestamp)}")
                    st.text(f"Session ID: {event.session_id}")
                    st.text(f"Threat Level: {event.threat_level}")
                    st.text(f"Category: {event.attack_category}")

                with col2:
                    st.markdown("**Tool Call Sequence**")
                    for i, tool in enumerate(event.tool_call_sequence, 1):
                        if tool == event.ghost_tool_called:
                            st.markdown(f"{i}. **{tool}** ⚠️ (honeypot)")
                        else:
                            st.text(f"{i}. {tool}")

                # Arguments
                if event.arguments:
                    st.markdown("**Arguments Passed**")
                    st.json(event.arguments)

                # Response sent
                st.markdown("**Fake Response Sent to Attacker**")
                st.code(event.response_sent, language="text")

                # Full event data
                with st.expander("View Full Event JSON"):
                    st.json(event.model_dump(mode="json"))

    # Footer
    st.markdown("---")
    st.markdown("🍯 **HoneyMCP** - Deception Middleware for AI Agents")

    # Auto-refresh button
    if st.button("🔄 Refresh", key="refresh_btn"):
        st.rerun()

    # Auto-refresh timer info
    st.sidebar.markdown("---")
    st.sidebar.info("💡 Click 'Refresh' to reload events")


if __name__ == "__main__":
    main()
