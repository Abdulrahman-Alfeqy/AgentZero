"""
app_home.py — Slack App Home tab builder for Agent Zero.

Constructs the Block Kit view displayed when a user opens the bot's
App Home tab in Slack.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def build_app_home_view(stats: dict) -> dict:
    """
    Build the Slack App Home view payload with live compliance statistics.

    Args:
        stats: Dict from IncidentStore.get_stats() containing keys:
               total, high, medium, low, last_activity.

    Returns:
        A dict representing the full Slack view payload for App Home.
    """
    total = stats.get("total", 0)
    high = stats.get("high", 0)
    medium = stats.get("medium", 0)
    low = stats.get("low", 0)
    last_activity: Optional[str] = stats.get("last_activity")

    last_activity_text = (
        last_activity[:19].replace("T", " ") + " UTC"
        if last_activity
        else "No incidents yet"
    )

    blocks = [
        # ── Header ───────────────────────────────────────────────────────
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🛡️ Agent Zero — Compliance Guardian",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    "I silently monitor your Slack channels for sensitive data leaks "
                    "and alert only the sender — privately, instantly, and without disrupting the conversation."
                ),
            },
        },
        {"type": "divider"},
        # ── Live Stats ───────────────────────────────────────────────────
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*📊 Live Compliance Dashboard*",
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Total Incidents*\n`{total}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Last Activity*\n`{last_activity_text}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*🔴 High Severity*\n`{high}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*🟡 Medium Severity*\n`{medium}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*🟢 Low Severity*\n`{low}`",
                },
                {
                    "type": "mrkdwn",
                    "text": (
                        f"*Status*\n"
                        + ("🔴 Active Incidents" if high > 0 else "🟢 All Clear")
                    ),
                },
            ],
        },
        {"type": "divider"},
        # ── What gets detected ───────────────────────────────────────────
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*🔍 What I Detect*",
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": (
                        "*🔴 HIGH*\n"
                        "• AWS Access Keys\n"
                        "• GitHub Tokens\n"
                        "• JWT Tokens\n"
                        "• Private Keys\n"
                        "• DB Connection Strings\n"
                        "• API Keys & Secrets\n"
                        "• Credit Card Numbers\n"
                        "• Plaintext Passwords"
                    ),
                },
                {
                    "type": "mrkdwn",
                    "text": (
                        "*🟡 MEDIUM*\n"
                        "• Email Addresses\n"
                        "• Internal IP Addresses\n\n"
                        "*🟢 LOW*\n"
                        "• Phone Numbers"
                    ),
                },
            ],
        },
        {"type": "divider"},
        # ── Commands ─────────────────────────────────────────────────────
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*⚡ Available Commands*",
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": (
                        "`/audit-scan`\n"
                        "Scan the last 100 messages in the current channel and get a risk summary."
                    ),
                },
                {
                    "type": "mrkdwn",
                    "text": (
                        "`/audit-report`\n"
                        "Generate and upload a PDF compliance report of all logged incidents."
                    ),
                },
                {
                    "type": "mrkdwn",
                    "text": (
                        "`/audit-status`\n"
                        "Get current compliance stats: total incidents, severity breakdown, last activity."
                    ),
                },
                {
                    "type": "mrkdwn",
                    "text": (
                        "*Auto-Monitoring*\n"
                        "Invite Agent Zero to any channel and it will silently "
                        "monitor all messages automatically."
                    ),
                },
            ],
        },
        {"type": "divider"},
        # ── Getting started ──────────────────────────────────────────────
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*🚀 Getting Started*",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    "1️⃣  *Invite Agent Zero* to any channel you want monitored:\n"
                    "   `/invite @Agent Zero`\n\n"
                    "2️⃣  *Post a test message* containing a fake credential to see the alert.\n\n"
                    "3️⃣  *Run `/audit-scan`* in any monitored channel to see a risk summary.\n\n"
                    "4️⃣  *Run `/audit-report`* to get a PDF compliance report uploaded to the channel.\n\n"
                    "5️⃣  *Run `/audit-status`* to check the current compliance health at any time."
                ),
            },
        },
        # ── Footer ───────────────────────────────────────────────────────
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        "🔒 *Agent Zero* — Your compliance guardian | "
                        "All alerts are ephemeral and visible only to the sender. "
                        "No sensitive values are ever stored."
                    ),
                }
            ],
        },
    ]

    return {
        "type": "home",
        "blocks": blocks,
    }
