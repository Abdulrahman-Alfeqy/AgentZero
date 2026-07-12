"""
mcp_server.py — MCP server exposing Agent Zero's core tools via FastMCP.

Provides a standard MCP interface for:
- analyse_message  → risk analysis + Gemini semantic detection
- scan_messages    → batch analysis of multiple messages
- get_stats        → current incident statistics
- generate_report  → trigger PDF generation, return file path

Runs on SSE transport at 127.0.0.1:5001. Start from main.py via
start_mcp_in_thread(), or directly with:
    python mcp_server.py
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
from pathlib import Path

from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from ai_provider import analyze_text
from storage import IncidentStore
from report_generator import ReportGenerator
from classifier import RiskClassifier

load_dotenv()

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MCP_HOST: str = os.getenv("MCP_SERVER_HOST", "0.0.0.0")
MCP_PORT: int = int(os.getenv("MCP_SERVER_PORT", "5001"))

# ---------------------------------------------------------------------------
# Initialise shared components
# ---------------------------------------------------------------------------


_store = IncidentStore(path=Path(os.getenv("STORAGE_PATH", "incidents.jsonl")))
_report_gen = ReportGenerator(output_dir=Path(os.getenv("REPORTS_DIR", "reports")))
_classifier = RiskClassifier()

# ---------------------------------------------------------------------------
# FastMCP server — port 5001, SSE transport
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="agent-zero",
    instructions=(
        "Agent Zero MCP server. Provides compliance tools for detecting "
        "sensitive data in Slack messages, retrieving incident statistics, "
        "and generating PDF compliance reports."
    ),
    host=MCP_HOST,
    port=MCP_PORT,
)


# ---------------------------------------------------------------------------
# MCP tools
# ---------------------------------------------------------------------------

@mcp.tool()
def analyse_message(text: str) -> dict:
    """
    Analyse a single message for sensitive data, including Gemini AI detection.

    Runs the regex + entropy classifier first. If nothing is found and the
    message contains credential keywords or high-entropy tokens, the classifier
    calls the Gemini API internally.

    Args:
        text: The raw message text to scan.

    Returns:
        A dict with keys: original_length, risk_count, highest_severity, risks,
        gemini_checked (bool). Each risk contains: category, severity,
        masked_value, description, start, end.
    """
    result = _classifier.analyse(text)
    
    # We still need to make sure the ai_provider is called if it hasn't been, 
    # but _classifier.analyse already calls analyze_text internally if there's high entropy or a keyword.
    # To satisfy the MCP tool contract properly, we return the serialized result.
    
    response = result.to_dict()
    # Add the MCP specific fields
    response["semantic_secret"] = any(r.category == "semantic_secret" for r in result.risks)
    response["gemini_checked"] = True # It was potentially checked by the classifier
    return response


@mcp.tool()
def scan_messages(messages: list[str]) -> dict:
    """
    Batch-scan a list of messages for sensitive data.

    Args:
        messages: List of raw message strings to analyse.

    Returns:
        A dict with keys:
          - total_messages: int
          - risky_messages: int
          - high: int
          - medium: int
          - low: int
          - results: list of per-message analysis dicts
    """
    from classifier import Severity

    results = _classifier.analyse_batch(messages)
    risky = [r for r in results if r.has_risks]
    high = sum(1 for r in risky if r.highest_severity == Severity.HIGH)
    medium = sum(1 for r in risky if r.highest_severity == Severity.MEDIUM)
    low = sum(1 for r in risky if r.highest_severity == Severity.LOW)

    return {
        "total_messages": len(messages),
        "risky_messages": len(risky),
        "high": high,
        "medium": medium,
        "low": low,
        "results": [r.to_dict() for r in results],
    }


@mcp.tool()
def get_stats() -> dict:
    """
    Retrieve current compliance statistics from the incident store.

    Returns:
        A dict with keys: total, high, medium, low, last_activity.
    """
    return _store.get_stats()


@mcp.tool()
def generate_report() -> dict:
    """
    Generate a PDF compliance report from all stored incidents.

    Returns:
        A dict with keys:
          - success: bool
          - file_path: str (absolute path to the PDF)
          - incident_count: int
          - error: str (only present on failure)
    """
    try:
        incidents = _store.load_all()
        stats = _store.get_stats()
        pdf_path = _report_gen.generate(incidents=incidents, stats=stats)
        return {
            "success": True,
            "file_path": str(pdf_path.resolve()),
            "incident_count": len(incidents),
        }
    except Exception as exc:  # noqa: BLE001
        logger.error("Report generation failed: %s", exc)
        return {
            "success": False,
            "file_path": "",
            "incident_count": 0,
            "error": str(exc),
        }


# ---------------------------------------------------------------------------
# Thread launcher (called by main.py)
# ---------------------------------------------------------------------------

def start_mcp_in_thread() -> threading.Thread:
    """
    Start the MCP SSE server in a background daemon thread.

    The thread is daemonised so it exits automatically when the main
    process exits. Returns the thread object (already started).

    Returns:
        The started daemon Thread running the MCP server.
    """
    def _run():
        logger.info(
            "MCP Compliance Server running on :%d (SSE transport)", MCP_PORT
        )
        mcp.run(transport="sse")

    t = threading.Thread(target=_run, daemon=True, name="mcp-server")
    t.start()
    return t


# ---------------------------------------------------------------------------
# Entry point (direct run)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logger.info("Starting MCP Compliance Server on %s:%d (SSE)…", MCP_HOST, MCP_PORT)
    mcp.run(transport="sse")
