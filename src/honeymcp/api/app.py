"""HoneyMCP FastAPI service for dashboard consumption."""

from __future__ import annotations

import os
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from honeymcp.models.config import HoneyMCPConfig
from honeymcp.models.events import AttackFingerprint
from honeymcp.storage.event_store import clear_events, get_event, list_events


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
            event
            for event in filtered
            if event.threat_level.lower() == threat_level.lower()
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

    return app


app = create_app()
