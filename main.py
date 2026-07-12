"""
main.py — Agent Zero entry point.

Architecture (HTTP mode):
- ONE Flask app object (importable as `application` for WSGI hosts, aliased
  from `flask_app`) handling:
    POST /slack/events  — Slack Events API + slash commands + interactivity
    GET  /dashboard     — compliance dashboard UI
    GET  /dashboard/data — dashboard JSON data endpoint
    GET  /healthz       — unauthenticated health check for load balancers
- MCP Compliance Server (SSE, port 5001) in a daemon thread for agentic tool use
- Local dev: `python main.py` starts Flask dev server on DASHBOARD_HOST:PORT

Slack integration uses HTTP Events API (not Socket Mode). Bolt's Flask adapter
dispatches all payload types (events, commands, interactivity) through the
single POST /slack/events route. SLACK_SIGNING_SECRET is the verification
mechanism — never disable it.

SLACK_APP_TOKEN is only needed when running Socket Mode locally (see README).
Run with:
    python main.py
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from typing import Optional, Any, Callable

from dotenv import load_dotenv
from flask import Flask, jsonify, send_from_directory, request, Response

load_dotenv()

# ---------------------------------------------------------------------------
# Logging — must be configured before any other imports that use logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal imports
# ---------------------------------------------------------------------------

from classifier import RiskClassifier, Severity, build_alert_blocks, build_scan_summary_blocks
from storage import IncidentStore, IncidentRecord
from report_generator import ReportGenerator
from app_home import build_app_home_view
import mcp_server as _mcp_server_module
from ai_provider import set_rate_limit_callback

# ---------------------------------------------------------------------------
# Slack Bolt imports — HTTP mode uses SlackRequestHandler (Flask adapter)
# ---------------------------------------------------------------------------

from slack_bolt import App
from slack_bolt.adapter.flask import SlackRequestHandler
from slack_sdk.errors import SlackApiError

# ---------------------------------------------------------------------------
# Config from .env
# ---------------------------------------------------------------------------

SLACK_BOT_TOKEN: str = os.environ["SLACK_BOT_TOKEN"]
SLACK_SIGNING_SECRET: str = os.environ["SLACK_SIGNING_SECRET"]
STORAGE_PATH: Path = Path(os.getenv("STORAGE_PATH", "incidents.jsonl"))
REPORTS_DIR: Path = Path(os.getenv("REPORTS_DIR", "reports"))
COMPLIANCE_OFFICER_ID: Optional[str] = os.getenv("COMPLIANCE_OFFICER_ID")
DASHBOARD_HOST: str = os.getenv("DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT: int = int(os.getenv("PORT", os.getenv("DASHBOARD_PORT", "5000")))
MCP_SERVER_PORT: int = int(os.getenv("MCP_SERVER_PORT", "5001"))

# ---------------------------------------------------------------------------
# Shared component instances
# ---------------------------------------------------------------------------

classifier = RiskClassifier()
store = IncidentStore(path=STORAGE_PATH)
report_gen = ReportGenerator(output_dir=REPORTS_DIR)

# ---------------------------------------------------------------------------
# Slack Bolt app — process_before_response=True is required for HTTP mode.
# Slack expects an HTTP 200 ack within 3 seconds; any work that can take
# longer (AI calls, file uploads) must be dispatched to a background thread
# AFTER ack() is called, which Bolt handles when this flag is set.
# ---------------------------------------------------------------------------

app = App(
    token=SLACK_BOT_TOKEN,
    signing_secret=SLACK_SIGNING_SECRET,
    process_before_response=True,
)


def _notify_rate_limit_admin():
    if COMPLIANCE_OFFICER_ID:
        try:
            app.client.chat_postMessage(
                channel=COMPLIANCE_OFFICER_ID,
                text="⚠️ *Gemini API rate limit reached.* Consider adding more keys via `GEMINI_API_KEYS`.",
            )
            logger.info("Admin notified about Gemini rate limit.")
        except Exception as e:
            logger.error("Failed to notify admin about rate limit: %s", e)


set_rate_limit_callback(_notify_rate_limit_admin)


# ---------------------------------------------------------------------------
# Exponential back-off helper
# ---------------------------------------------------------------------------

def _slack_call_with_backoff(fn, *args, max_retries: int = 5, **kwargs):
    """
    Execute a Slack API call with exponential back-off on rate-limit errors.

    Args:
        fn:          Callable Slack SDK method.
        *args:       Positional arguments forwarded to fn.
        max_retries: Maximum number of retry attempts.
        **kwargs:    Keyword arguments forwarded to fn.

    Returns:
        The Slack API response object.

    Raises:
        SlackApiError: After max_retries attempts, re-raises the last error.
    """
    for attempt in range(max_retries):
        try:
            return fn(*args, **kwargs)
        except SlackApiError as exc:
            if exc.response.get("error") == "ratelimited":
                wait = min(2 ** attempt, 30)
                logger.warning("Rate limited by Slack. Waiting %ds (attempt %d).", wait, attempt + 1)
                time.sleep(wait)
            else:
                raise
    raise SlackApiError("Max retries exceeded", response={})


# ---------------------------------------------------------------------------
# Preview sanitiser
# ---------------------------------------------------------------------------

def _sanitise_preview(text: str, result=None) -> str:
    """
    Build a safe message preview with every matched sensitive value masked.

    If result is provided, uses it instead of re-analysing.
    """
    if result is None:
        result = classifier.analyse(text)
    if not result.risks:
        return text.replace("\n", " ")

    # Replace spans in reverse order so earlier indices stay valid
    chars = list(text)
    for risk in sorted(result.risks, key=lambda r: r.start, reverse=True):
        if risk.start >= len(chars):
            continue
        start, end = risk.start, min(risk.end, len(chars))
        replacement = list(f"[{risk.masked_value}]")
        chars[start:end] = replacement

    return "".join(chars).replace("\n", " ")


# ---------------------------------------------------------------------------
# Compliance Officer DM helper (Feature 4)
# ---------------------------------------------------------------------------

def _notify_compliance_officer(
    client,
    channel_name: str,
    channel_id: str,
    message_ts: str,
    result,
    preview: str,
) -> None:
    """
    Send a DM to the compliance officer when a HIGH severity incident is stored.

    Skipped silently if COMPLIANCE_OFFICER_ID is not set.

    Args:
        client:       Slack WebClient.
        channel_name: Human-readable channel name.
        channel_id:   Slack channel ID.
        message_ts:   Original message timestamp.
        result:       AnalysisResult from the classifier.
        preview:      Sanitised message preview.
    """
    if not COMPLIANCE_OFFICER_ID:
        return
    if not result.highest_severity or result.highest_severity != Severity.HIGH:
        return

    risk_types = ", ".join({r.category for r in result.risks})
    permalink = f"https://slack.com/archives/{channel_id}/p{message_ts.replace('.', '')}"

    dm_text = (
        f"🚨 *Agent Zero — HIGH Severity Incident*\n"
        f"*Channel:* #{channel_name}\n"
        f"*Message:* <{permalink}|View message>\n"
        f"*Risk Types:* `{risk_types}`\n"
        f"*Preview (masked):* {preview}"
    )

    try:
        _slack_call_with_backoff(
            client.chat_postMessage,
            channel=COMPLIANCE_OFFICER_ID,
            text=dm_text,
            mrkdwn=True,
        )
        logger.info("Compliance officer DM sent to %s", COMPLIANCE_OFFICER_ID)
    except SlackApiError as exc:
        logger.error(
            "Failed to DM compliance officer %s: %s",
            COMPLIANCE_OFFICER_ID,
            exc.response.get("error"),
        )


# ---------------------------------------------------------------------------
# Event: message — real-time monitoring (Feature 1: Thread Support)
# ---------------------------------------------------------------------------

@app.event("message")
def handle_message(event: dict, client, **kwargs) -> None:
    """
    Handle incoming Slack messages (all channels/DMs the bot has access to).
    """
    subtype = event.get("subtype")
    if subtype in ("bot_message", "message_deleted"):
        return

    notes = None
    # Handle message_changed
    if subtype == "message_changed":
        message_obj = event.get("message", {})
        text = message_obj.get("text", "")
        user_id = message_obj.get("user", "")
        msg_ts = message_obj.get("ts", "")
        channel_id = event.get("channel", "")
        notes = "edited_message"
    else:
        text = event.get("text", "")
        user_id = event.get("user", "")
        msg_ts = event.get("ts", "")
        channel_id = event.get("channel", "")

    if not text or not user_id or not msg_ts:
        return

    # Only process human users
    try:
        if not hasattr(handle_message, "_bot_cache"):
            handle_message._bot_cache = {}

        is_bot = handle_message._bot_cache.get(user_id)
        if is_bot is None:
            user_info = _slack_call_with_backoff(client.users_info, user=user_id)
            is_bot = user_info.get("user", {}).get("is_bot", False)
            handle_message._bot_cache[user_id] = is_bot

        if is_bot:
            return
    except SlackApiError as exc:
        logger.warning("Failed to fetch user info for %s: %s", user_id, exc)
        return

    _process_and_flag_message(
        text=text,
        user_id=user_id,
        channel_id=channel_id,
        msg_ts=msg_ts,
        client=client,
        notes=notes,
    )

def _process_and_flag_message(text: str, user_id: str, channel_id: str, msg_ts: str, client: Any, notes: str = None):
    result = classifier.analyse(text)
    if not result.has_risks:
        return

    # Resolve info
    username = user_id
    channel_name = channel_id
    try:
        user_info = _slack_call_with_backoff(client.users_info, user=user_id)
        username = user_info["user"].get("real_name") or user_id
        chan_info = _slack_call_with_backoff(client.conversations_info, channel=channel_id)
        channel_name = chan_info["channel"].get("name") or channel_id
    except SlackApiError as exc:
        logger.warning("Failed to resolve user/channel info: %s", exc)

    # Ephemeral Alert
    blocks = build_alert_blocks(result, channel_id=channel_id, username=username, message_ts=msg_ts, original_text=text)
    _slack_call_with_backoff(
        client.chat_postEphemeral,
        channel=channel_id,
        user=user_id,
        text="⚠️ Compliance Alert.",
        blocks=blocks,
    )

    # Store
    preview = _sanitise_preview(text[:80], result=result)
    record = IncidentRecord(
        incident_id=IncidentStore.make_incident_id(),
        timestamp=IncidentStore.current_timestamp(),
        user_id=user_id,
        username=username,
        channel_id=channel_id,
        channel_name=channel_name,
        message_preview=preview,
        risk_count=len(result.risks),
        highest_severity=result.highest_severity.value if result.highest_severity else "LOW",
        risks=[r.to_dict() for r in result.risks],
        notes=notes or "message_scan",
    )
    store.append(record)

    # Compliance DM
    if result.highest_severity == Severity.HIGH:
        _notify_compliance_officer(client, channel_name, channel_id, msg_ts, result, preview)


# ---------------------------------------------------------------------------
# Action handlers
# ---------------------------------------------------------------------------

def _parse_action_value(value: str) -> tuple[str, str]:
    parts = value.split(":", 1)
    return (parts[0] if len(parts) > 0 else ""), (parts[1] if len(parts) > 1 else "")

@app.action("dismiss_alert")
def handle_dismiss_alert(ack, body, respond) -> None:
    ack()
    respond(delete_original=True)

@app.action("mark_safe_pattern")
def handle_mark_safe(ack, body: dict, respond) -> None:
    ack()
    original_text = body.get("actions", [{}])[0].get("value", "")
    if original_text:
        classifier.learn_from_message(original_text)
    respond(delete_original=True, text="✅ Done! The system has learned from your input and will no longer flag this pattern in the future.")


# ---------------------------------------------------------------------------
# Slash commands
# ---------------------------------------------------------------------------

@app.command("/audit-scan")
def audit_scan(ack, command: dict, client, respond) -> None:
    """
    Handle /audit-scan slash command.
    Manually triggers a scan of the last 50 messages in the channel.
    """
    ack()
    channel_id = command.get("channel_id")
    respond(text="⏳ Scanning the last 50 messages...")
    try:
        channel_info = client.conversations_info(channel=channel_id)
        if not channel_info.get("channel", {}).get("is_member", False):
            respond(text="I can't scan this channel because I'm not a member. Please add me to the channel first.")
            return

        history = client.conversations_history(channel=channel_id, limit=50)
        messages = history.get("messages", [])

        flagged = 0
        for msg in messages:
            if msg.get("subtype") in ("bot_message", "message_deleted"):
                continue

            text = msg.get("text", "")
            if not text:
                continue

            result = classifier.analyse(text)
            if result.has_risks:
                flagged += 1

        respond(text=f"✅ Scan complete! Found {flagged} flagged messages.")
    except Exception as e:
        logger.error("Error in /audit-scan: %s", e)
        respond(text=f"❌ Error scanning channel: {e}")

@app.command("/audit-report")
def handle_audit_report(ack, command: dict, client, respond) -> None:
    """
    Handle /audit-report slash command.
    Generates a PDF audit report in the background and uploads it.
    """
    ack()
    respond(text="⏳ Generating your audit report...")

    def _generate_and_upload():
        try:
            incidents = store.load_all()
            stats = store.get_stats()
            pdf_path = report_gen.generate(incidents=incidents, stats=stats)

            client.files_upload_v2(
                channel=command.get("channel_id"),
                initial_comment="📄 Here is your generated audit report.",
                file=str(pdf_path),
                title="Compliance Audit Report"
            )
            Path(pdf_path).unlink(missing_ok=True)
        except Exception as e:
            logger.error("Failed to generate/upload PDF: %s", e)
            client.chat_postMessage(
                channel=command.get("channel_id"),
                text=f"❌ Error generating report: {e}"
            )

    threading.Thread(target=_generate_and_upload, daemon=True).start()

@app.command("/audit-status")
def audit_status(ack, respond) -> None:
    """
    Handle /audit-status slash command.

    Returns the current aggregate compliance metrics.

    Args:
        ack:     Acknowledgement function.
        respond: Respond function.
    """
    ack()
    stats = store.get_stats()
    text = (
        f"📊 *Agent Zero Status*\n"
        f"Total incidents logged: {stats['total']}\n"
        f"🔴 High: {stats['high']} | 🟡 Medium: {stats['medium']} | 🟢 Low: {stats['low']}"
    )
    respond(text=text)

@app.command("/audit-search")
def audit_search(ack, command: dict, client, respond) -> None:
    ack()
    topic = command.get("text", "").strip()
    if not topic:
        respond(text="Please provide a topic. Usage: `/audit-search [topic]`")
        return

    respond(text=f"⏳ Scanning incident log for *{topic}*…")

    # Local incidents search
    records = store.load_all()
    matches = []
    lower_topic = topic.lower()
    for rec in reversed(records):
        risk_cats = " ".join([r.get("category", "") for r in rec.risks]).lower()
        if (
            lower_topic in (rec.channel_name or "").lower() or
            lower_topic in (rec.username or "").lower() or
            lower_topic in (rec.notes or "").lower() or
            lower_topic in risk_cats
        ):
            matches.append(rec)

    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{topic}* — {len(matches)} flagged incident(s) found"
            }
        }
    ]

    if not matches:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"✅ No flagged incidents match *{topic}*."}
        })
    else:
        for rec in matches:
            risk_str = " · ".join(r.get("category", "unknown") for r in rec.risks)

            sev_upper = rec.highest_severity.upper() if rec.highest_severity else "LOW"
            if sev_upper == "HIGH":
                emoji = "🔴"
            elif sev_upper == "MEDIUM":
                emoji = "🟡"
            else:
                emoji = "🔵"

            ts_str = rec.timestamp[:10]

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{emoji} *{sev_upper}* — {risk_str}\n📍 #{rec.channel_name}  👤 {rec.username}  🕐 {ts_str}"
                }
            })
            blocks.append({"type": "divider"})

    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": "Use /audit-report to export the full compliance report as PDF"
            }
        ]
    })

    respond(blocks=blocks)


# ---------------------------------------------------------------------------
# Events: member_joined_channel / App Home
# ---------------------------------------------------------------------------

@app.event("member_joined_channel")
def handle_member_joined(event: dict, client) -> None:
    """Send a welcome message when Agent Zero is invited to a channel."""
    user_id = event.get("user")
    inviter = event.get("inviter")
    channel_id = event.get("channel")
    try:
        bot_id = client.auth_test()["user_id"]
        if user_id == bot_id and inviter:
            _slack_call_with_backoff(
                client.chat_postEphemeral,
                channel=channel_id,
                user=inviter,
                text="👋 Hello! I'm Agent Zero, your compliance guardian.",
                blocks=[
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "👋 *Hello! I'm Agent Zero, your compliance guardian.*\nI'm now monitoring this channel for leaked credentials, API keys, and sensitive data to keep our workspace secure. Nobody else can see my alerts unless explicitly needed."
                        }
                    }
                ],
            )
            logger.info("Sent welcome message to inviter %s in channel %s", inviter, channel_id)
    except Exception as exc:
        logger.error("Failed to send welcome message: %s", exc)

@app.event("app_home_opened")
def handle_app_home_opened(event: dict, client) -> None:
    """
    Publish the App Home view when a user opens the bot's home tab.

    Args:
        event:  Slack event payload.
        client: Slack WebClient.
    """
    user_id = event.get("user", "")
    stats = store.get_stats()
    view = build_app_home_view(stats=stats)
    try:
        _slack_call_with_backoff(
            client.views_publish,
            user_id=user_id,
            view=view,
        )
        logger.debug("App Home published for user %s", user_id)
    except SlackApiError as exc:
        logger.error("Failed to publish App Home: %s", exc.response.get("error"))


# ---------------------------------------------------------------------------
# Dashboard data helpers
# ---------------------------------------------------------------------------

def _build_dashboard_data() -> dict:
    """
    Aggregate incident data for the dashboard JSON endpoint.

    Returns:
        Dict with keys: risk_type_distribution, top_channels, severity_counts, total.
    """
    records = store.load_all()

    # ── Risk type distribution ─────────────────────────────────────────────
    type_counts: dict[str, int] = defaultdict(int)
    for rec in records:
        for risk in rec.risks:
            type_counts[risk.get("category", "unknown")] += 1

    # ── Top 3 riskiest channels ────────────────────────────────────────────
    channel_counts: dict[str, int] = defaultdict(int)
    for rec in records:
        name = rec.channel_name or rec.channel_id or "unknown"
        channel_counts[name] += 1
    top_channels = sorted(channel_counts.items(), key=lambda x: x[1], reverse=True)[:3]

    # ── Severity counts ────────────────────────────────────────────────────
    severity: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for rec in records:
        sev = rec.highest_severity.upper()
        if sev in severity:
            severity[sev] += 1

    return {
        "risk_type_distribution": {
            "labels": list(type_counts.keys()),
            "data": list(type_counts.values()),
        },
        "top_channels": [{"channel": ch, "count": cnt} for ch, cnt in top_channels],
        "severity_counts": severity,
        "total": len(records),
    }


def _check_auth(username, password):
    expected_u = os.getenv("DASHBOARD_USERNAME")
    expected_p = os.getenv("DASHBOARD_PASSWORD")
    if not expected_u or not expected_p:
        return True
    return username == expected_u and password == expected_p

def _authenticate():
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        expected_u = os.getenv("DASHBOARD_USERNAME")
        if not expected_u:
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or not _check_auth(auth.username, auth.password):
            return _authenticate()
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Flask app — single object for both Slack events and the dashboard.
# Importable as `flask_app` for WSGI hosts (see PythonAnywhere setup below).
# ---------------------------------------------------------------------------

def _create_flask_app() -> Flask:
    """
    Build and return the consolidated Flask application.

    Registers:
      POST /slack/events  — Bolt adapter (events, commands, interactivity)
      GET  /dashboard     — Dashboard UI
      GET  /dashboard/data — Dashboard JSON
      GET  /healthz       — Unauthenticated health check
    """
    app_flask = Flask(__name__)
    app_flask.logger.setLevel(logging.WARNING)

    handler = SlackRequestHandler(app)

    dashboard_dir = Path(__file__).parent

    @app_flask.route("/slack/events", methods=["POST"])
    def slack_events():
        """Receive all Slack HTTP Events, slash commands, and interactivity."""
        return handler.handle(request)

    @app_flask.route("/dashboard")
    @requires_auth
    def dashboard():
        """Serve the dashboard HTML page."""
        return send_from_directory(str(dashboard_dir), "dashboard.html")

    @app_flask.route("/dashboard/data")
    @requires_auth
    def dashboard_data():
        """Return aggregated incident data as JSON."""
        return jsonify(_build_dashboard_data())

    @app_flask.route("/healthz")
    def healthz():
        """Unauthenticated health check for load balancers and uptime monitors."""
        return jsonify({"status": "ok"}), 200

    return app_flask


# ---------------------------------------------------------------------------
# Module-level Flask app — importable by PythonAnywhere's WSGI config:
#   from main import flask_app as application
# ---------------------------------------------------------------------------

flask_app = _create_flask_app()

# PythonAnywhere WSGI convention: `application`
application = flask_app


# ---------------------------------------------------------------------------
# Entry point — local development server only
# ---------------------------------------------------------------------------

def main() -> None:
    """Start Agent Zero: MCP server (daemon thread) + Flask dev server."""
    # 1. Start MCP Compliance Server in a daemon thread (SSE on :5001)
    _mcp_server_module.start_mcp_in_thread()
    logger.info("MCP Compliance Server running on :%d", MCP_SERVER_PORT)

    # 2. Run the consolidated Flask app (Slack events + dashboard)
    import logging as _logging
    _logging.getLogger("werkzeug").setLevel(_logging.ERROR)
    logger.info(
        "Agent Zero starting at http://%s:%d  (Slack events: POST /slack/events)",
        DASHBOARD_HOST, DASHBOARD_PORT,
    )
    flask_app.run(
        host=DASHBOARD_HOST,
        port=DASHBOARD_PORT,
        debug=False,
        use_reloader=False,
    )


if __name__ == "__main__":
    main()
