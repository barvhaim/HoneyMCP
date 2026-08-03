"""Export attack data in various formats for sharing and analysis."""

import csv
import json
import logging
from datetime import datetime
from io import StringIO
from typing import Any, Dict, List
from uuid import uuid4

from honeymcp.models.forensics import (
    AttackTimeline,
    ExportFormat,
    ForensicReport,
    STIXBundle,
    STIXIndicator,
)

logger = logging.getLogger(__name__)


class ForensicsExporter:
    """Export attack data in multiple formats.

    Supported formats:
    - JSON: Complete data export
    - CSV: Tabular event data
    - STIX 2.1: Threat intelligence sharing
    - HTML: Human-readable report
    """

    def __init__(self) -> None:
        """Initialize exporter."""
        logger.info("Forensics exporter initialized")

    async def export_timeline(
        self,
        timeline: AttackTimeline,
        format: ExportFormat,
    ) -> str:
        """Export attack timeline in specified format.

        Args:
            timeline: Attack timeline to export
            format: Export format

        Returns:
            Exported data as string
        """
        if format == ExportFormat.JSON:
            return self._export_timeline_json(timeline)
        elif format == ExportFormat.CSV:
            return self._export_timeline_csv(timeline)
        elif format == ExportFormat.STIX:
            return await self._export_timeline_stix(timeline)
        elif format == ExportFormat.HTML:
            return self._export_timeline_html(timeline)
        else:
            raise ValueError(f"Unsupported format: {format}")

    async def export_report(
        self,
        report: ForensicReport,
        format: ExportFormat,
    ) -> str:
        """Export forensic report in specified format.

        Args:
            report: Forensic report to export
            format: Export format

        Returns:
            Exported data as string
        """
        if format == ExportFormat.JSON:
            return self._export_report_json(report)
        elif format == ExportFormat.HTML:
            return self._export_report_html(report)
        elif format == ExportFormat.PDF:
            # PDF generation would require additional library (e.g., weasyprint)
            # For now, return HTML that can be converted to PDF
            return self._export_report_html(report)
        else:
            raise ValueError(f"Unsupported format for reports: {format}")

    def _export_timeline_json(self, timeline: AttackTimeline) -> str:
        """Export timeline as JSON."""
        data = timeline.model_dump(mode="json")
        return json.dumps(data, indent=2, default=str)

    def _export_timeline_csv(self, timeline: AttackTimeline) -> str:
        """Export timeline as CSV."""
        output = StringIO()
        writer = csv.writer(output)

        writer.writerow(
            [
                "Timestamp",
                "Elapsed (s)",
                "Event Type",
                "Tool Name",
                "Threat Level",
                "Attack Category",
                "Response",
            ]
        )

        for event in timeline.events:
            writer.writerow(
                [
                    event.timestamp.isoformat(),
                    f"{event.elapsed_seconds:.2f}",
                    event.event_type,
                    event.tool_name or "",
                    event.threat_level or "",
                    event.attack_category or "",
                    (event.response or "")[:100],
                ]
            )

        return output.getvalue()

    async def _export_timeline_stix(self, timeline: AttackTimeline) -> str:
        """Export timeline as STIX 2.1 bundle."""
        indicators = []

        for tool in timeline.unique_tools_used:
            indicator_id = f"indicator--{uuid4()}"

            # x-honeymcp-tool is a custom STIX object type, not a standard one
            pattern = f"[x-honeymcp-tool:name = '{tool}']"

            tool_count = timeline.tool_sequence.count(tool)

            indicator = STIXIndicator(
                id=indicator_id,
                created=timeline.start_time,
                modified=timeline.end_time,
                name=f"HoneyMCP Tool: {tool}",
                description=f"Honeypot tool '{tool}' triggered {tool_count} times during attack session {timeline.session_id}",
                pattern=pattern,
                pattern_type="stix",
                valid_from=timeline.start_time,
                labels=[
                    "honeypot",
                    "attack-pattern",
                    timeline.max_threat_level,
                ]
                + timeline.attack_categories,
                confidence=85,  # High confidence since it's from honeypot
            )
            indicators.append(indicator)

        bundle = STIXBundle(
            id=f"bundle--{uuid4()}",
            objects=indicators,
        )

        data = bundle.model_dump(mode="json")
        return json.dumps(data, indent=2, default=str)

    def _export_timeline_html(self, timeline: AttackTimeline) -> str:
        """Export timeline as HTML."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Attack Timeline - {timeline.session_id}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #e74c3c;
            padding-bottom: 10px;
        }}
        .summary {{
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .summary-item {{
            display: inline-block;
            margin-right: 30px;
            margin-bottom: 10px;
        }}
        .summary-label {{
            font-weight: bold;
            color: #555;
        }}
        .timeline {{
            margin-top: 30px;
        }}
        .event {{
            border-left: 3px solid #3498db;
            padding: 15px;
            margin: 10px 0;
            background-color: #f9f9f9;
            border-radius: 0 5px 5px 0;
        }}
        .event.high {{
            border-left-color: #e74c3c;
        }}
        .event.critical {{
            border-left-color: #8b0000;
            background-color: #ffe6e6;
        }}
        .event-time {{
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        .event-tool {{
            font-weight: bold;
            color: #2c3e50;
            font-size: 1.1em;
        }}
        .event-category {{
            display: inline-block;
            background-color: #3498db;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            margin-left: 10px;
        }}
        .threat-level {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .threat-low {{ background-color: #2ecc71; color: white; }}
        .threat-medium {{ background-color: #f39c12; color: white; }}
        .threat-high {{ background-color: #e74c3c; color: white; }}
        .threat-critical {{ background-color: #8b0000; color: white; }}
        .response {{
            margin-top: 10px;
            padding: 10px;
            background-color: #ecf0f1;
            border-radius: 3px;
            font-family: monospace;
            font-size: 0.9em;
            white-space: pre-wrap;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Attack Timeline Analysis</h1>
        
        <div class="summary">
            <div class="summary-item">
                <span class="summary-label">Session ID:</span> {timeline.session_id}
            </div>
            <div class="summary-item">
                <span class="summary-label">Duration:</span> {self._format_duration(timeline.duration_seconds)}
            </div>
            <div class="summary-item">
                <span class="summary-label">Events:</span> {timeline.event_count}
            </div>
            <div class="summary-item">
                <span class="summary-label">Unique Tools:</span> {len(timeline.unique_tools_used)}
            </div>
            <div class="summary-item">
                <span class="summary-label">Max Threat:</span> 
                <span class="threat-level threat-{timeline.max_threat_level}">{timeline.max_threat_level.upper()}</span>
            </div>
        </div>
        
        <h2>📊 Statistics</h2>
        <ul>
            <li><strong>Tools Used:</strong> {', '.join(timeline.unique_tools_used)}</li>
            <li><strong>Attack Categories:</strong> {', '.join(timeline.attack_categories)}</li>
            <li><strong>Avg Time Between Events:</strong> {timeline.avg_time_between_events:.1f} seconds</li>
        </ul>
        
        <h2>⏱️ Event Timeline</h2>
        <div class="timeline">
"""

        for event in timeline.events:
            threat_class = event.threat_level or "low"
            html += f"""
            <div class="event {threat_class}">
                <div class="event-time">
                    {event.timestamp.strftime('%Y-%m-%d %H:%M:%S')} 
                    (+{event.elapsed_seconds:.1f}s)
                </div>
                <div class="event-tool">
                    {event.tool_name or 'Unknown'}
                    <span class="event-category">{event.attack_category or 'unknown'}</span>
                    <span class="threat-level threat-{threat_class}">{threat_class.upper()}</span>
                </div>
"""

            if event.response:
                html += f"""
                <div class="response">
                    <strong>Response:</strong><br>
                    {event.response[:500]}{'...' if len(event.response) > 500 else ''}
                </div>
"""

            html += "            </div>\n"

        html += """
        </div>
    </div>
</body>
</html>
"""

        return html

    def _export_report_json(self, report: ForensicReport) -> str:
        """Export report as JSON."""
        data = report.model_dump(mode="json")
        return json.dumps(data, indent=2, default=str)

    def _export_report_html(self, report: ForensicReport) -> str:
        """Export report as HTML."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Forensic Report - {report.report_id}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #e74c3c;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #2c3e50;
            margin-top: 30px;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 5px;
        }}
        .header {{
            background-color: #ecf0f1;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
        }}
        .severity {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 5px;
            font-weight: bold;
            font-size: 1.2em;
        }}
        .severity-critical {{ background-color: #8b0000; color: white; }}
        .severity-high {{ background-color: #e74c3c; color: white; }}
        .severity-medium {{ background-color: #f39c12; color: white; }}
        .severity-low {{ background-color: #2ecc71; color: white; }}
        .summary {{
            background-color: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 20px 0;
        }}
        .section {{
            margin: 20px 0;
        }}
        ul {{
            line-height: 1.8;
        }}
        .ioc {{
            background-color: #f8d7da;
            border-left: 4px solid #dc3545;
            padding: 10px;
            margin: 5px 0;
            font-family: monospace;
        }}
        .recommendation {{
            background-color: #d1ecf1;
            border-left: 4px solid #17a2b8;
            padding: 10px;
            margin: 5px 0;
        }}
        .mitre {{
            display: inline-block;
            background-color: #6c757d;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            margin: 2px;
            font-size: 0.9em;
        }}
        .tag {{
            display: inline-block;
            background-color: #6c757d;
            color: white;
            padding: 3px 8px;
            border-radius: 3px;
            margin: 2px;
            font-size: 0.85em;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #ecf0f1;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Forensic Analysis Report</h1>
        
        <div class="header">
            <h2 style="margin-top: 0;">{report.title}</h2>
            <p><strong>Report ID:</strong> {report.report_id}</p>
            <p><strong>Session ID:</strong> {report.session_id}</p>
            <p><strong>Generated:</strong> {report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            <p><strong>Severity:</strong> <span class="severity severity-{report.severity}">{report.severity.upper()}</span></p>
        </div>
        
        <div class="summary">
            <h3>📋 Executive Summary</h3>
            <p>{report.summary}</p>
        </div>
        
        <div class="section">
            <h2>🎯 Attack Analysis</h2>
            <p><strong>Primary Attack Vector:</strong> {report.attack_vector}</p>
            <p><strong>Techniques Used:</strong></p>
            <ul>
"""

        for technique in report.techniques_used:
            html += f"                <li>{technique}</li>\n"

        html += """
            </ul>
        </div>
        
        <div class="section">
            <h2>🚨 Indicators of Compromise (IOCs)</h2>
"""

        for ioc in report.indicators_of_compromise:
            html += f'            <div class="ioc">{ioc}</div>\n'

        html += """
        </div>
        
        <div class="section">
            <h2>🛠️ MITRE ATT&CK Mapping</h2>
            <p><strong>Tactics:</strong></p>
            <div>
"""

        for tactic in report.mitre_tactics:
            html += f'                <span class="mitre">{tactic}</span>\n'

        html += """
            </div>
            <p><strong>Techniques:</strong></p>
            <div>
"""

        for technique in report.mitre_techniques:
            html += f'                <span class="mitre">{technique}</span>\n'

        html += """
            </div>
        </div>
        
        <div class="section">
            <h2>💡 Recommendations</h2>
"""

        for rec in report.recommendations:
            html += f'            <div class="recommendation">{rec}</div>\n'

        html += """
        </div>
        
        <div class="section">
            <h2>🔧 Mitigation Steps</h2>
            <ol>
"""

        for step in report.mitigation_steps:
            html += f"                <li>{step}</li>\n"

        html += """
            </ol>
        </div>
"""

        if report.analyst_notes:
            html += f"""
        <div class="section">
            <h2>📝 Analyst Notes</h2>
            <p>{report.analyst_notes}</p>
        </div>
"""

        if report.tags:
            html += """
        <div class="section">
            <h2>🏷️ Tags</h2>
            <div>
"""
            for tag in report.tags:
                html += f'                <span class="tag">{tag}</span>\n'

            html += """
            </div>
        </div>
"""

        html += f"""
        <div class="footer">
            <p>Generated by HoneyMCP Forensics System</p>
            <p>Report ID: {report.report_id}</p>
        </div>
    </div>
</body>
</html>
"""

        return html

    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable form."""
        if seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            return f"{seconds / 60:.1f} minutes"
        else:
            return f"{seconds / 3600:.1f} hours"
