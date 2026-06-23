"""HoneyMCP FastAPI service for dashboard consumption."""

from __future__ import annotations

import os
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from honeymcp.models.config import HoneyMCPConfig
from honeymcp.models.events import AttackFingerprint
from honeymcp.models.attack_patterns import AttackPattern, AttackerProfile, PatternSummary
from honeymcp.models.forensics import (
    AttackTimeline,
    ExportFormat,
    ForensicReport,
    ReplayControl,
    ReplayState,
)
from honeymcp.storage.event_store import clear_events, get_event, list_events
from honeymcp.analysis.pattern_detector import PatternDetector
from honeymcp.integrations.streaming import StreamManager
from honeymcp.forensics.replay_engine import ReplayEngine
from honeymcp.forensics.report_generator import ReportGenerator
from honeymcp.forensics.exporters import ForensicsExporter


class EventListResponse(BaseModel):
    """Paginated event list response."""

    total: int = Field(description="Total events matching the filters")
    count: int = Field(description="Number of events returned in this page")
    offset: int = Field(description="Offset for pagination")
    limit: int = Field(description="Limit for pagination")
    events: List[AttackFingerprint] = Field(description="Event records")


class MetricsResponse(BaseModel):
    """Aggregate metrics for dashboard summaries."""

    total_attacks: int
    attacks_last_24h: int
    critical_threats: int
    unique_tools: int
    unique_sessions: int
    by_threat_level: Dict[str, int]
    by_category: Dict[str, int]


class FiltersResponse(BaseModel):
    """Distinct filter values for UI dropdowns."""

    threat_levels: List[str]
    categories: List[str]
    tools: List[str]


class ClearEventsResponse(BaseModel):
    """Response returned when stored events are deleted."""

    deleted_events: int
    storage_path: str


def _apply_filters(
    events: List[AttackFingerprint],
    threat_level: Optional[str],
    category: Optional[str],
    tool: Optional[str],
) -> List[AttackFingerprint]:
    filtered = events
    if threat_level:
        filtered = [
            event for event in filtered if event.threat_level.lower() == threat_level.lower()
        ]
    if category:
        filtered = [event for event in filtered if event.attack_category == category]
    if tool:
        filtered = [event for event in filtered if event.ghost_tool_called == tool]
    return filtered


def _metrics(events: List[AttackFingerprint]) -> MetricsResponse:
    now = datetime.utcnow()
    total_attacks = len(events)
    attacks_last_24h = len([event for event in events if now - event.timestamp < timedelta(days=1)])
    critical_threats = len([event for event in events if event.threat_level == "critical"])
    unique_tools = len({event.ghost_tool_called for event in events})
    unique_sessions = len({event.session_id for event in events})

    by_threat_level: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    for event in events:
        by_threat_level[event.threat_level] = by_threat_level.get(event.threat_level, 0) + 1
        by_category[event.attack_category] = by_category.get(event.attack_category, 0) + 1

    return MetricsResponse(
        total_attacks=total_attacks,
        attacks_last_24h=attacks_last_24h,
        critical_threats=critical_threats,
        unique_tools=unique_tools,
        unique_sessions=unique_sessions,
        by_threat_level=by_threat_level,
        by_category=by_category,
    )


def _configure_cors(app: FastAPI) -> None:
    origins_raw = os.getenv("HONEYMCP_API_CORS_ORIGINS", "").strip()
    if not origins_raw:
        return
    origins = [origin.strip() for origin in origins_raw.split(",") if origin.strip()]
    if not origins:
        return
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


def create_app(config_path: Optional[Path | str] = None) -> FastAPI:
    """Create a FastAPI app configured with HoneyMCP settings."""
    config = HoneyMCPConfig.load(config_path)

    app = FastAPI(
        title="HoneyMCP API",
        version="0.1.0",
        description="HTTP API for HoneyMCP dashboard consumption",
    )
    _configure_cors(app)

    app.state.config = config
    app.state.event_storage_path = config.event_storage_path
    dashboard_root = Path(__file__).resolve().parent.parent / "dashboard" / "react_umd"
    app.state.dashboard_root = dashboard_root

    # Initialize forensics components
    app.state.replay_engine = ReplayEngine()
    app.state.report_generator = ReportGenerator()
    app.state.forensics_exporter = ForensicsExporter()

    if dashboard_root.exists():
        app.mount(
            "/dashboard/assets",
            StaticFiles(directory=str(dashboard_root)),
            name="dashboard_assets",
        )

    @app.get("/health")
    async def health() -> Dict[str, str]:
        return {"status": "ok", "timestamp": datetime.utcnow().isoformat() + "Z"}

    @app.get("/dashboard")
    @app.get("/dashboard/", include_in_schema=False)
    async def react_dashboard() -> FileResponse:
        index_path = app.state.dashboard_root / "index.html"
        if not index_path.exists():
            raise HTTPException(status_code=404, detail="Dashboard UI not found")
        return FileResponse(index_path)

    @app.get("/events", response_model=EventListResponse)
    async def get_events(
        start_date: Optional[date] = Query(default=None),
        end_date: Optional[date] = Query(default=None),
        threat_level: Optional[str] = Query(default=None),
        category: Optional[str] = Query(default=None),
        tool: Optional[str] = Query(default=None),
        limit: int = Query(default=200, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
    ) -> EventListResponse:
        events = await list_events(
            storage_path=app.state.event_storage_path,
            start_date=start_date,
            end_date=end_date,
        )
        filtered = _apply_filters(events, threat_level, category, tool)
        total = len(filtered)
        page = filtered[offset : offset + limit]
        return EventListResponse(
            total=total,
            count=len(page),
            offset=offset,
            limit=limit,
            events=page,
        )

    @app.get("/events/{event_id}", response_model=AttackFingerprint)
    async def get_event_by_id(event_id: str) -> AttackFingerprint:
        event = await get_event(event_id, storage_path=app.state.event_storage_path)
        if event is None:
            raise HTTPException(status_code=404, detail="Event not found")
        return event

    @app.delete("/events", response_model=ClearEventsResponse)
    async def delete_events() -> ClearEventsResponse:
        deleted_count = await clear_events(storage_path=app.state.event_storage_path)
        return ClearEventsResponse(
            deleted_events=deleted_count,
            storage_path=str(app.state.event_storage_path),
        )

    @app.get("/metrics", response_model=MetricsResponse)
    async def get_metrics(
        start_date: Optional[date] = Query(default=None),
        end_date: Optional[date] = Query(default=None),
        threat_level: Optional[str] = Query(default=None),
        category: Optional[str] = Query(default=None),
        tool: Optional[str] = Query(default=None),
    ) -> MetricsResponse:
        events = await list_events(
            storage_path=app.state.event_storage_path,
            start_date=start_date,
            end_date=end_date,
        )
        filtered = _apply_filters(events, threat_level, category, tool)
        return _metrics(filtered)

    @app.get("/filters", response_model=FiltersResponse)
    async def get_filters(
        start_date: Optional[date] = Query(default=None),
        end_date: Optional[date] = Query(default=None),
    ) -> FiltersResponse:
        events = await list_events(
            storage_path=app.state.event_storage_path,
            start_date=start_date,
            end_date=end_date,
        )
        threat_levels = sorted({event.threat_level for event in events})
        categories = sorted({event.attack_category for event in events})
        tools = sorted({event.ghost_tool_called for event in events})
        return FiltersResponse(
            threat_levels=threat_levels,
            categories=categories,
            tools=tools,
        )

    @app.get("/patterns", response_model=List[AttackPattern])
    async def get_patterns(
        pattern_type: Optional[str] = Query(
            default=None, description="Filter by pattern type: coordinated, campaign, anomaly"
        ),
        min_confidence: float = Query(
            default=0.5, ge=0.0, le=1.0, description="Minimum confidence score"
        ),
        start_date: Optional[date] = Query(default=None),
        end_date: Optional[date] = Query(default=None),
    ) -> List[AttackPattern]:
        """Get detected attack patterns with optional filtering."""
        events = await list_events(
            storage_path=app.state.event_storage_path,
            start_date=start_date,
            end_date=end_date,
        )

        if not events:
            return []

        detector = PatternDetector()

        # Run all detection algorithms
        all_patterns = []
        all_patterns.extend(await detector.detect_coordinated_attacks(events))
        all_patterns.extend(await detector.detect_attack_campaigns(events))
        all_patterns.extend(await detector.detect_anomalies(events))

        # Filter by type and confidence
        filtered = [
            p
            for p in all_patterns
            if p.confidence >= min_confidence
            and (pattern_type is None or p.pattern_type == pattern_type)
        ]

        # Sort by confidence (highest first)
        filtered.sort(key=lambda p: p.confidence, reverse=True)

        return filtered

    @app.get("/patterns/summary", response_model=PatternSummary)
    async def get_pattern_summary(
        start_date: Optional[date] = Query(default=None),
        end_date: Optional[date] = Query(default=None),
    ) -> PatternSummary:
        """Get summary statistics for detected patterns."""
        events = await list_events(
            storage_path=app.state.event_storage_path,
            start_date=start_date,
            end_date=end_date,
        )

        if not events:
            return PatternSummary(
                total_patterns=0,
                by_type={},
                by_severity={},
                high_confidence_count=0,
                recent_patterns=[],
            )

        detector = PatternDetector()

        # Run all detection algorithms
        all_patterns = []
        all_patterns.extend(await detector.detect_coordinated_attacks(events))
        all_patterns.extend(await detector.detect_attack_campaigns(events))
        all_patterns.extend(await detector.detect_anomalies(events))

        # Calculate summary statistics
        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        high_confidence_count = 0

        for pattern in all_patterns:
            by_type[pattern.pattern_type] = by_type.get(pattern.pattern_type, 0) + 1
            by_severity[pattern.severity] = by_severity.get(pattern.severity, 0) + 1
            if pattern.confidence >= 0.8:
                high_confidence_count += 1

        # Get most recent patterns (last 10)
        sorted_patterns = sorted(all_patterns, key=lambda p: p.last_seen, reverse=True)
        recent_patterns = sorted_patterns[:10]

        return PatternSummary(
            total_patterns=len(all_patterns),
            by_type=by_type,
            by_severity=by_severity,
            high_confidence_count=high_confidence_count,
            recent_patterns=recent_patterns,
        )

    @app.get("/profiles/{session_id}", response_model=AttackerProfile)
    async def get_attacker_profile(
        session_id: str,
        start_date: Optional[date] = Query(default=None),
        end_date: Optional[date] = Query(default=None),
    ) -> AttackerProfile:
        """Get behavioral profile for a specific attacker session."""
        events = await list_events(
            storage_path=app.state.event_storage_path,
            start_date=start_date,
            end_date=end_date,
        )

        detector = PatternDetector()

        try:
            profile = await detector.build_attacker_profile(session_id, events)
            return profile
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

    @app.get("/profiles", response_model=List[AttackerProfile])
    async def get_all_profiles(
        min_sophistication: float = Query(
            default=0.0, ge=0.0, le=1.0, description="Minimum sophistication score"
        ),
        start_date: Optional[date] = Query(default=None),
        end_date: Optional[date] = Query(default=None),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> List[AttackerProfile]:
        """Get behavioral profiles for all attacker sessions."""
        events = await list_events(
            storage_path=app.state.event_storage_path,
            start_date=start_date,
            end_date=end_date,
        )

        if not events:
            return []

        # Get unique session IDs
        session_ids = list(set(e.session_id for e in events))

        detector = PatternDetector()
        profiles = []

        # Build profile for each session
        for session_id in session_ids:
            try:
                profile = await detector.build_attacker_profile(session_id, events)
                if profile.sophistication_score >= min_sophistication:
                    profiles.append(profile)
            except ValueError:
                continue

        # Sort by sophistication (highest first)
        profiles.sort(key=lambda p: p.sophistication_score, reverse=True)

        return profiles[:limit]

    @app.get("/stream")
    async def event_stream(
        event_types: Optional[str] = Query(
            default=None, description="Comma-separated event types to filter (attack,pattern,alert)"
        ),
        send_history: bool = Query(
            default=True, description="Whether to send historical events first"
        ),
    ) -> StreamingResponse:
        """Server-Sent Events (SSE) stream for real-time updates.

        Subscribe to receive real-time notifications of:
        - Attack events as they occur
        - Detected patterns (coordinated, campaigns, anomalies)
        - Alert notifications

        Example:
            GET /stream?event_types=attack,pattern&send_history=true
        """
        import uuid

        # Initialize stream if not already done
        stream = StreamManager.get_stream()
        if stream is None:
            stream = StreamManager.initialize(max_history=100)

        # Generate unique client ID
        client_id = f"client_{uuid.uuid4().hex[:12]}"

        # Parse event types filter
        event_type_list = None
        if event_types:
            event_type_list = [t.strip() for t in event_types.split(",") if t.strip()]

        # Create streaming response
        return StreamingResponse(
            stream.subscribe(
                client_id=client_id,
                event_types=event_type_list,
                send_history=send_history,
            ),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",  # Disable nginx buffering
            },
        )

    # ==================== Forensics & Replay Endpoints ====================

    @app.post("/replay/start", response_model=dict)
    async def start_replay(
        session_id: str = Query(..., description="Session ID to replay"),
    ) -> dict:
        """Start a new replay session for an attack."""
        # Get events for session
        events = await list_events(
            storage_path=app.state.event_storage_path,
            session_id=session_id,
        )

        if not events:
            raise HTTPException(status_code=404, detail=f"No events found for session {session_id}")

        # Create timeline
        timeline = await app.state.replay_engine.create_timeline(events)

        # Start replay
        replay_id = await app.state.replay_engine.start_replay(timeline)

        return {
            "replay_id": replay_id,
            "session_id": session_id,
            "event_count": len(events),
            "duration_seconds": timeline.duration_seconds,
        }

    @app.post("/replay/{replay_id}/control", response_model=ReplayState)
    async def control_replay(
        replay_id: str,
        control: ReplayControl,
    ) -> ReplayState:
        """Control replay session (play, pause, seek, speed)."""
        try:
            state = await app.state.replay_engine.control_replay(replay_id, control)
            return state
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

    @app.get("/replay/{replay_id}/state", response_model=ReplayState)
    async def get_replay_state(replay_id: str) -> ReplayState:
        """Get current state of replay session."""
        try:
            return app.state.replay_engine.get_state(replay_id)
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))

    @app.delete("/replay/{replay_id}")
    async def stop_replay(replay_id: str) -> dict:
        """Stop and remove replay session."""
        await app.state.replay_engine.stop_replay(replay_id)
        return {"message": f"Replay session {replay_id} stopped"}

    @app.get("/replay/active", response_model=List[str])
    async def list_active_replays() -> List[str]:
        """List all active replay sessions."""
        return app.state.replay_engine.list_active_replays()

    @app.post("/reports/generate", response_model=ForensicReport)
    async def generate_report(
        session_id: str = Query(..., description="Session ID to analyze"),
        analyst_notes: Optional[str] = Query(default=None, description="Optional analyst notes"),
    ) -> ForensicReport:
        """Generate forensic report for an attack session."""
        # Get events for session
        events = await list_events(
            storage_path=app.state.event_storage_path,
            session_id=session_id,
        )

        if not events:
            raise HTTPException(status_code=404, detail=f"No events found for session {session_id}")

        # Create timeline
        timeline = await app.state.replay_engine.create_timeline(events)

        # Generate report
        report = await app.state.report_generator.generate_report(
            timeline=timeline,
            analyst_notes=analyst_notes,
        )

        return report

    @app.post("/reports/compare", response_model=dict)
    async def compare_sessions(
        session_ids: List[str] = Query(..., description="Session IDs to compare"),
    ) -> dict:
        """Generate comparison report for multiple sessions."""
        if len(session_ids) < 2:
            raise HTTPException(status_code=400, detail="Need at least 2 sessions for comparison")

        timelines = []
        for session_id in session_ids:
            events = await list_events(
                storage_path=app.state.event_storage_path,
                session_id=session_id,
            )

            if not events:
                raise HTTPException(
                    status_code=404, detail=f"No events found for session {session_id}"
                )

            timeline = await app.state.replay_engine.create_timeline(events)
            timelines.append(timeline)

        # Generate comparison
        comparison = await app.state.report_generator.compare_sessions(timelines)

        return comparison.model_dump(mode="json")

    @app.get("/export/timeline/{session_id}")
    async def export_timeline(
        session_id: str,
        format: ExportFormat = Query(default=ExportFormat.JSON, description="Export format"),
    ) -> Response:
        """Export attack timeline in specified format."""
        # Get events for session
        events = await list_events(
            storage_path=app.state.event_storage_path,
            session_id=session_id,
        )

        if not events:
            raise HTTPException(status_code=404, detail=f"No events found for session {session_id}")

        # Create timeline
        timeline = await app.state.replay_engine.create_timeline(events)

        # Export
        content = await app.state.forensics_exporter.export_timeline(timeline, format)

        # Set content type and filename
        content_types = {
            ExportFormat.JSON: "application/json",
            ExportFormat.CSV: "text/csv",
            ExportFormat.HTML: "text/html",
            ExportFormat.STIX: "application/json",
        }

        extensions = {
            ExportFormat.JSON: "json",
            ExportFormat.CSV: "csv",
            ExportFormat.HTML: "html",
            ExportFormat.STIX: "json",
        }

        return Response(
            content=content,
            media_type=content_types[format],
            headers={
                "Content-Disposition": f'attachment; filename="timeline_{session_id}.{extensions[format]}"'
            },
        )

    @app.get("/export/report/{report_id}")
    async def export_report(
        report_id: str,
        format: ExportFormat = Query(default=ExportFormat.HTML, description="Export format"),
    ) -> Response:
        """Export forensic report in specified format."""
        # Note: In a real implementation, you'd store reports and retrieve them.
        # For now, reports are generated on demand via /reports/generate.
        raise HTTPException(
            status_code=501,
            detail="Report export not yet implemented - use /reports/generate and save the response",
        )

    # ==================== Adaptive Tools Endpoints ====================

    @app.get("/adaptive/metrics", response_model=Dict[str, Any])
    async def get_effectiveness_metrics(
        tool_name: Optional[str] = Query(default=None, description="Specific tool name"),
    ) -> Dict[str, Any]:
        """Get effectiveness metrics for tools."""
        if not hasattr(app.state, "effectiveness_tracker"):
            raise HTTPException(status_code=501, detail="Adaptive tools not enabled")

        tracker = app.state.effectiveness_tracker

        if tool_name:
            metric = tracker.get_metric(tool_name)
            if not metric:
                raise HTTPException(status_code=404, detail=f"No metrics for tool: {tool_name}")
            return metric.model_dump(mode="json")
        else:
            metrics = tracker.get_all_metrics()
            return {
                "metrics": {name: m.model_dump(mode="json") for name, m in metrics.items()},
                "statistics": await tracker.get_statistics(),
            }

    @app.get("/adaptive/top-tools", response_model=List[Dict[str, Any]])
    async def get_top_tools(
        n: int = Query(default=10, ge=1, le=50, description="Number of tools to return"),
    ) -> List[Dict[str, Any]]:
        """Get top performing tools."""
        if not hasattr(app.state, "effectiveness_tracker"):
            raise HTTPException(status_code=501, detail="Adaptive tools not enabled")

        tracker = app.state.effectiveness_tracker
        top_tools = tracker.get_top_tools(n)

        return [tool.model_dump(mode="json") for tool in top_tools]

    @app.get("/adaptive/recommendations", response_model=Dict[str, Any])
    async def get_catalog_recommendations() -> Dict[str, Any]:
        """Get recommendations for catalog optimization."""
        if not hasattr(app.state, "catalog_optimizer"):
            raise HTTPException(status_code=501, detail="Adaptive tools not enabled")

        optimizer = app.state.catalog_optimizer

        # Get current tools from catalog
        from honeymcp.core.ghost_tools import list_ghost_tools

        current_tools = list_ghost_tools()

        # Generate recommendations
        recommendation = await optimizer.analyze_catalog(current_tools)

        return recommendation.model_dump(mode="json")

    @app.post("/adaptive/snapshot", response_model=Dict[str, Any])
    async def create_catalog_snapshot() -> Dict[str, Any]:
        """Create snapshot of current catalog state."""
        if not hasattr(app.state, "catalog_optimizer"):
            raise HTTPException(status_code=501, detail="Adaptive tools not enabled")

        optimizer = app.state.catalog_optimizer

        # Get current tools
        from honeymcp.core.ghost_tools import list_ghost_tools

        current_tools = list_ghost_tools()

        # Create snapshot
        snapshot = await optimizer.create_snapshot(current_tools)

        return snapshot.model_dump(mode="json")

    @app.get("/adaptive/snapshots", response_model=List[Dict[str, Any]])
    async def get_catalog_snapshots(
        limit: int = Query(default=10, ge=1, le=100, description="Maximum snapshots to return"),
    ) -> List[Dict[str, Any]]:
        """Get historical catalog snapshots."""
        if not hasattr(app.state, "catalog_optimizer"):
            raise HTTPException(status_code=501, detail="Adaptive tools not enabled")

        optimizer = app.state.catalog_optimizer
        snapshots = optimizer.get_snapshots(limit=limit)

        return [s.model_dump(mode="json") for s in snapshots]

    @app.get("/adaptive/profiles/{session_id}", response_model=Dict[str, Any])
    async def get_adaptive_attacker_profile(session_id: str) -> Dict[str, Any]:
        """Get attacker profile for a session."""
        if not hasattr(app.state, "attacker_profiler"):
            raise HTTPException(status_code=501, detail="Adaptive tools not enabled")

        profiler = app.state.attacker_profiler
        profile = profiler.get_profile(session_id)

        if not profile:
            raise HTTPException(status_code=404, detail=f"No profile for session: {session_id}")

        return profile.model_dump(mode="json")

    @app.post("/adaptive/profiles/{session_id}/analyze", response_model=Dict[str, Any])
    async def analyze_session_profile(session_id: str) -> Dict[str, Any]:
        """Analyze session and create attacker profile."""
        if not hasattr(app.state, "attacker_profiler"):
            raise HTTPException(status_code=501, detail="Adaptive tools not enabled")

        # Get events for session
        events = await list_events(
            storage_path=app.state.event_storage_path,
            session_id=session_id,
        )

        if not events:
            raise HTTPException(status_code=404, detail=f"No events for session: {session_id}")

        profiler = app.state.attacker_profiler
        profile = await profiler.analyze_session(session_id, events)

        return profile.model_dump(mode="json")

    @app.get("/adaptive/profiles", response_model=Dict[str, Any])
    async def get_all_adaptive_profiles() -> Dict[str, Any]:
        """Get all attacker profiles with statistics."""
        if not hasattr(app.state, "attacker_profiler"):
            raise HTTPException(status_code=501, detail="Adaptive tools not enabled")

        profiler = app.state.attacker_profiler
        profiles = profiler.get_all_profiles()
        stats = await profiler.get_statistics()

        return {
            "profiles": {sid: p.model_dump(mode="json") for sid, p in profiles.items()},
            "statistics": stats,
        }

    @app.get("/adaptive/campaigns", response_model=List[Dict[str, Any]])
    async def identify_campaigns() -> List[Dict[str, Any]]:
        """Identify potential attack campaigns."""
        if not hasattr(app.state, "attacker_profiler"):
            raise HTTPException(status_code=501, detail="Adaptive tools not enabled")

        profiler = app.state.attacker_profiler
        campaigns = await profiler.identify_campaigns()

        return campaigns

    @app.get("/adaptive/hints/{session_id}", response_model=Dict[str, Any])
    async def get_generation_hint(session_id: str) -> Dict[str, Any]:
        """Get tool generation hint for a session."""
        if not hasattr(app.state, "attacker_profiler"):
            raise HTTPException(status_code=501, detail="Adaptive tools not enabled")

        profiler = app.state.attacker_profiler
        hint = await profiler.generate_hint(session_id)

        if not hint:
            raise HTTPException(
                status_code=404, detail=f"No hint available for session: {session_id}"
            )

        return hint.model_dump(mode="json")

    @app.post("/adaptive/compare-profiles", response_model=Dict[str, Any])
    async def compare_attacker_profiles(
        session1: str = Query(..., description="First session ID"),
        session2: str = Query(..., description="Second session ID"),
    ) -> Dict[str, Any]:
        """Compare two attacker profiles."""
        if not hasattr(app.state, "attacker_profiler"):
            raise HTTPException(status_code=501, detail="Adaptive tools not enabled")

        profiler = app.state.attacker_profiler
        comparison = await profiler.compare_profiles(session1, session2)

        return comparison

    return app


app = create_app()
