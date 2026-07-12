"""
classifier.py — Risk detection and classification engine for Agent Zero.

Detects sensitive data patterns (API keys, passwords, PII, etc.) using
compiled regex rules, Shannon entropy analysis, and optional Gemini AI
semantic analysis. Masks matched values before returning results.
Never stores raw sensitive values.
"""

from __future__ import annotations

import json
import logging
import math
import re
import threading
import time
import json
from pathlib import Path
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from ai_provider import analyze_text

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Severity levels for detected risks."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Risk:
    """Represents a single detected risk in a message."""

    category: str
    severity: Severity
    masked_value: str
    description: str
    start: int
    end: int

    def to_dict(self) -> dict:
        """Serialize to plain dict for JSON storage."""
        return {
            "category": self.category,
            "severity": self.severity.value,
            "masked_value": self.masked_value,
            "description": self.description,
            "start": self.start,
            "end": self.end,
        }


@dataclass
class AnalysisResult:
    """Result of analysing a single message."""

    original_length: int
    risks: list[Risk] = field(default_factory=list)

    @property
    def has_risks(self) -> bool:
        """Return True if any risks were detected."""
        return len(self.risks) > 0

    @property
    def highest_severity(self) -> Optional[Severity]:
        """Return the highest severity found, or None."""
        priority = {Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}
        if not self.risks:
            return None
        return max(self.risks, key=lambda r: priority[r.severity]).severity

    def to_dict(self) -> dict:
        """Serialize to plain dict."""
        return {
            "original_length": self.original_length,
            "risk_count": len(self.risks),
            "highest_severity": self.highest_severity.value if self.highest_severity else None,
            "risks": [r.to_dict() for r in self.risks],
        }


# ---------------------------------------------------------------------------
# Risk pattern definitions
# ---------------------------------------------------------------------------

# Each entry: (category, severity, regex_pattern, description)
_RISK_PATTERNS: list[tuple[str, Severity, str, str]] = [
    # ── HIGH ──────────────────────────────────────────────────────────────
    (
        "slack_token",
        Severity.HIGH,
        r"\bxox[baprs]-[0-9]+-[0-9]+-[a-zA-Z0-9]+\b",
        "Slack Bot/User Token",
    ),
    (
        "stripe_key",
        Severity.HIGH,
        r"(?i)\b(?:sk|rk)_(?:test|live)_[a-zA-Z0-9]{24,99}\b",
        "Stripe API Key",
    ),
    (
        "aws_access_key",
        Severity.HIGH,
        r"\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b",
        "AWS Access Key ID",
    ),
    (
        "aws_secret_key",
        Severity.HIGH,
        r"(?i)\baws.{0,20}?['\"]([A-Za-z0-9/+]{40})['\"]\b",
        "AWS Secret Access Key",
    ),
    (
        "github_token",
        Severity.HIGH,
        r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b",
        "GitHub Personal Access Token",
    ),
    (
        "jwt_token",
        Severity.HIGH,
        r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",
        "JWT Token",
    ),
    (
        "private_key",
        Severity.HIGH,
        r"-----\bBEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY\b-----",
        "Private Key Header",
    ),
    (
        "database_connection_string",
        Severity.HIGH,
        r"(?i)(?:\b(?:mysql|postgresql|postgres|mongodb|redis|mssql|sqlite):\/\/[^\s\"'<>]+|\bServer=[^;]+;.*?(?:Password|Pwd)=[^;\s]+;?)",
        "Database Connection String",
    ),
    (
        "api_key_generic",
        Severity.HIGH,
        r"(?i)\b(?:api[_\-\s]?key|apikey|api[_\-\s]?secret|access[_\-\s]?token)(?:['\",\s:=]+|\s+(?:is|was|are|be|set to|set as|equal to)\s+)([A-Za-z0-9_\-]{20,})\b",
        "Generic API Key / Secret",
    ),
    (
        "credit_card",
        Severity.HIGH,
        r"\b(?:4[0-9]{3}(?:[- ]?[0-9]{4}){3}|5[1-5][0-9]{2}(?:[- ]?[0-9]{4}){3}|3[47][0-9]{2}[- ]?[0-9]{6}[- ]?[0-9]{5}|6(?:011|5[0-9]{2})[- ]?[0-9]{4}(?:[- ]?[0-9]{4}){2})\b",
        "Credit Card Number",
    ),
    (
        "plaintext_password",
        Severity.HIGH,
        r"(?i)\b(?:password|passwd|pwd|secret|pass)\s*(?:[=:]\s*|\s+(?:is|was|are|be|set to|set as|equal to)\s+)(?![a-zA-Z]+(?:[\s'\",;]|$))([^\s'\",;]{6,})",
        "Plaintext Password",
    ),
    # ── MEDIUM ────────────────────────────────────────────────────────────
    (
        "email_address",
        Severity.MEDIUM,
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "Email Address",
    ),
    (
        "internal_ip",
        Severity.MEDIUM,
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        "Internal / Private IP Address",
    ),
    # ── LOW ───────────────────────────────────────────────────────────────
    (
        "phone_number",
        Severity.LOW,
        r"\b\d{3}-\d{3}-\d{4}\b",
        "Phone Number",
    ),
]

# Pre-compile all patterns for performance
_COMPILED_PATTERNS: list[tuple[str, Severity, re.Pattern, str]] = [
    (cat, sev, re.compile(pat), desc)
    for cat, sev, pat, desc in _RISK_PATTERNS
]

# UUID pattern — used to exclude UUIDs from entropy flagging
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# MD5 / SHA1 hex — used to exclude digests from entropy flagging
_HEX_DIGEST_RE = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$", re.IGNORECASE)

# Pure base64 check (only base64 alphabet chars)
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")

# Credential context keywords (multi-language) for Gemini trigger
_CRED_KEYWORDS = re.compile(
    r"(?i)\b(?:"
    r"password|passwd|pwd|secret|token|api[_\-\s]?key|apikey|credential|"
    r"access[_\-\s]?key|private[_\-\s]?key|auth|bearer|passphrase|"
    r"كلمة.?(?:المرور|سر)|رمز|مفتاح|bitwort|mot.?de.?passe|contraseña"
    r")\b"
)

# MCP result cache: hash(text) → bool (True = credential detected by Gemini)
_mcp_cache: dict[str, bool] = {}

# Gemini Rate Limiter state
_gemini_call_times: deque = deque()

# False Positive Learning state
_safe_patterns_file = Path("safe_patterns.json")

# ---------------------------------------------------------------------------
# Masking utility
# ---------------------------------------------------------------------------

def _mask_value(raw: str) -> str:
    """
    Mask a sensitive value for safe display.

    Shows first 4 chars + '***' + last 4 chars when long enough,
    or just '***' for short values.

    Args:
        raw: The raw matched string (will NOT be stored/logged).

    Returns:
        Masked representation safe for display and storage.
    """
    clean = raw.strip("'\" \t\n\r")
    if len(clean) >= 12:
        return f"{clean[:4]}***{clean[-4:]}"
    elif len(clean) >= 8:
        return f"{clean[:2]}***{clean[-2:]}"
    return "***"


# ---------------------------------------------------------------------------
# Entropy analysis
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """
    Compute the Shannon entropy of a string in bits-per-character.

    Args:
        s: Input string.

    Returns:
        Entropy value in bits/char (0.0 for empty string).
    """
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _is_high_entropy_secret(token: str) -> bool:
    """
    Return True if token passes ALL high-entropy-secret heuristics.

    Criteria (ALL must hold):
    - Length >= 12
    - Shannon entropy >= 3.5 bits/char
    - Contains at least 3 character classes (upper, lower, digit, symbol)
    - NOT a UUID
    - NOT an MD5/SHA1 hex digest
    - NOT pure base64

    Args:
        token: A single whitespace-delimited token from the message.

    Returns:
        True if the token looks like a high-entropy secret.
    """
    if len(token) < 12:
        return False
    if _shannon_entropy(token) < 3.5:
        return False

    classes = sum([
        bool(re.search(r"[A-Z]", token)),
        bool(re.search(r"[a-z]", token)),
        bool(re.search(r"[0-9]", token)),
        bool(re.search(r"[^A-Za-z0-9]", token)),
    ])
    if classes < 3:
        return False

    if _UUID_RE.match(token):
        return False
    if _HEX_DIGEST_RE.match(token):
        return False
    # Likely pure base64 padding with no symbols other than +/=
    if _BASE64_RE.match(token) and "+" not in token and "=" not in token:
        return False

    return True




# ---------------------------------------------------------------------------
# Classification engine
# ---------------------------------------------------------------------------

class RiskClassifier:
    """
    Scans text messages for sensitive data using compiled regex patterns,
    Shannon entropy analysis, and optional Gemini AI semantic detection.

    Thread-safe (stateless after initialisation). Pattern compilation
    occurs once at class instantiation.
    """

    def __init__(self) -> None:
        """Initialise the classifier. Patterns are pre-compiled at module level."""
        self._patterns = _COMPILED_PATTERNS
        self._safe_lock = threading.Lock()
        self._safe_patterns: set[str] = set()
        self._load_safe_patterns()
        logger.debug("RiskClassifier initialised with %d patterns", len(self._patterns))

    def _load_safe_patterns(self) -> None:
        """Load safe patterns from disk."""
        if _safe_patterns_file.exists():
            try:
                with open(_safe_patterns_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        self._safe_patterns = set(data)
            except Exception as e:
                logger.error("Failed to load safe_patterns.json: %s", e)
        else:
            try:
                with open(_safe_patterns_file, "w", encoding="utf-8") as f:
                    json.dump([], f)
            except Exception:
                pass

    def learn_from_message(self, message_text: str) -> bool:
        """Add a sanitized text to the safe patterns list and persist it."""
        clean = message_text.strip()
        if not clean:
            return False
        
        with self._safe_lock:
            if clean not in self._safe_patterns:
                self._safe_patterns.add(clean)
                try:
                    with open(_safe_patterns_file, "w", encoding="utf-8") as f:
                        json.dump(list(self._safe_patterns), f, ensure_ascii=False, indent=2)
                    logger.info("Added new safe pattern: %s...", clean[:20])
                    return True
                except Exception as e:
                    logger.error("Failed to save safe_patterns.json: %s", e)
                    return False
        return True

    def analyse(self, text: str) -> AnalysisResult:
        """
        Analyse a single message for sensitive data.

        Processing pipeline:
        1. Run all compiled regex patterns.
        2. If regex finds nothing, run entropy analysis on each token.
        3. If entropy hits OR credential keywords present, call the MCP server
           (which internally runs Gemini if configured).
        4. If MCP server returns a semantic_secret risk, emit it here.

        Args:
            text: The raw message text to scan.

        Returns:
            AnalysisResult containing all detected risks with masked values.
        """
        result = AnalysisResult(original_length=len(text))

        clean_text = text.strip()
        with self._safe_lock:
            is_safe = clean_text in self._safe_patterns
        if is_safe:
            logger.debug("Message matched safe pattern. Skipping analysis.")
            return result

        # ── Step 1: Regex scan ────────────────────────────────────────────
        for category, severity, pattern, description in self._patterns:
            try:
                for match in pattern.finditer(text):
                    span = match.span()


                    # Use group(1) when the pattern wraps the secret in a capture
                    # group; fall back to the full match (group 0) otherwise.
                    if match.lastindex and len(match.group(1)) >= len(match.group(0)) // 2:
                        raw_value = match.group(1)
                    else:
                        raw_value = match.group(0)
                    masked = _mask_value(raw_value)

                    risk = Risk(
                        category=category,
                        severity=severity,
                        masked_value=masked,
                        description=description,
                        start=span[0],
                        end=span[1],
                    )
                    result.risks.append(risk)
                    logger.debug(
                        "Risk detected: category=%s severity=%s",
                        category,
                        severity.value,
                    )
            except re.error as exc:
                logger.error("Regex error in pattern '%s': %s", category, exc)
        # ── Step 1.5: Smart Deduplication ────────────────────────────────
        if result.risks:
            deduped_risks = []
            by_masked = {}
            for risk in result.risks:
                by_masked.setdefault(risk.masked_value, []).append(risk)
                
            for masked_val, risks_list in by_masked.items():
                if len(risks_list) == 1:
                    deduped_risks.append(risks_list[0])
                else:
                    categories = []
                    descriptions = []
                    for r in risks_list:
                        if r.category not in categories:
                            categories.append(r.category)
                        if r.description not in descriptions:
                            descriptions.append(r.description)
                    
                    merged_category = " + ".join(categories)
                    merged_description = " + ".join(descriptions)
                    
                    # Highest severity among duplicates
                    priority = {Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1}
                    highest_sev = max(risks_list, key=lambda r: priority[r.severity]).severity
                    
                    merged_risk = Risk(
                        category=merged_category,
                        severity=highest_sev,
                        masked_value=masked_val,
                        description=merged_description,
                        start=risks_list[0].start,
                        end=risks_list[-1].end,
                    )
                    deduped_risks.append(merged_risk)
            
            result.risks = deduped_risks
        # ── Step 2 & 3: MCP/Gemini fallback ────────────────────
        if not result.has_risks:
            has_keyword = bool(_CRED_KEYWORDS.search(text))
            has_high_entropy = any(_is_high_entropy_secret(t) for t in text.split())
            if has_keyword or has_high_entropy:
                if analyze_text(text):
                    risk = Risk(
                        category="semantic_secret",
                        severity=Severity.HIGH,
                        masked_value="[AI detected]",
                        description="AI-Detected Credential / Secret",
                        start=0,
                        end=len(text),
                    )
                    result.risks.append(risk)
                    logger.info(
                        "MCP server detected semantic secret in message (len=%d)", len(text)
                    )
            else:
                logger.debug("Message has no keywords or high entropy. Skipping Gemini.")

        return result

    def analyse_batch(self, messages: list[str]) -> list[AnalysisResult]:
        """
        Analyse a list of messages in sequence.

        Args:
            messages: List of raw message texts.

        Returns:
            List of AnalysisResult objects, one per message.
        """
        return [self.analyse(msg) for msg in messages]


# ---------------------------------------------------------------------------
# Block Kit alert builder — 3-button actions (Feature 2)
# ---------------------------------------------------------------------------

def build_alert_blocks(
    result: AnalysisResult,
    channel_id: str,
    username: str,
    message_ts: str = "",
    original_text: str = "",
) -> list[dict]:
    """
    Build Slack Block Kit blocks for an ephemeral compliance alert.

    Includes three action buttons:
    - 🗑️ Delete Message (danger)
    - ✏️ I'll Edit It
    - ✋ Dismiss

    Args:
        result:     The analysis result containing detected risks.
        channel_id: The channel where the message was posted.
        username:   The Slack display name of the sender.
        message_ts: The timestamp of the original message (used for action values).

    Returns:
        List of Block Kit block dicts ready to pass to Slack API.
    """
    severity_emoji = {
        Severity.HIGH: "🛡️",
        Severity.MEDIUM: "👁️",
        Severity.LOW: "📝",
    }

    primary_risk = result.risks[0].description if result.risks else "sensitive data"
    
    blocks: list[dict] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🛡️ Security Assistant: A Note About Your Recent Message",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"To help keep your information safe, we noticed a potential *{primary_risk}* in your message in <#{channel_id}>. "
                    "For your privacy, this alert is visible only to you. No one else in the channel can see it."
                ),
            },
        },
        {"type": "divider"},
    ]

    for risk in result.risks:
        emoji = severity_emoji.get(risk.severity, "⚪")
        blocks.append(
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Type:*\n{risk.description}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{emoji} {risk.severity.value}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Masked Value:*\n`{risk.masked_value}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Category:*\n`{risk.category}`",
                    },
                ],
            }
        )

    # ── Actions block ─────────────────────────────────────────
    safe_value = original_text[:2000] if original_text else "masked_by_user"
    blocks.append(
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✅ Mark as Safe", "emoji": True},
                    "action_id": "mark_safe_pattern",
                    "value": safe_value,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✋ Dismiss", "emoji": True},
                    "action_id": "dismiss_alert",
                    "value": "dismiss",
                },
            ],
        }
    )

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": (
                        "🔒 Agent Zero — Compliance Guardian | "
                        "This message is only visible to you.\n"
                        "💡 To secure your data, please manually click 'More actions' (⋮) on your message and select 'Delete message' or 'Edit message'."
                    ),
                }
            ],
        }
    )

    return blocks


def build_scan_summary_blocks(
    results: list[tuple[str, AnalysisResult]],
    channel_id: str,
    message_count: int,
) -> list[dict]:
    """
    Build Block Kit blocks summarising an /audit-scan result.

    Args:
        results:       List of (message_preview, analysis_result) tuples.
        channel_id:    Channel that was scanned.
        message_count: Total messages scanned.

    Returns:
        List of Block Kit block dicts.
    """
    risky = [(preview, r) for preview, r in results if r.has_risks]
    high = sum(1 for _, r in risky if r.highest_severity == Severity.HIGH)
    medium = sum(1 for _, r in risky if r.highest_severity == Severity.MEDIUM)
    low = sum(1 for _, r in risky if r.highest_severity == Severity.LOW)

    blocks: list[dict] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🔍 Audit Scan — <#{channel_id}>",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Messages Scanned:*\n{message_count}"},
                {"type": "mrkdwn", "text": f"*Risky Messages:*\n{len(risky)}"},
                {"type": "mrkdwn", "text": f"*🔴 High:*\n{high}"},
                {"type": "mrkdwn", "text": f"*🟡 Medium:*\n{medium}"},
                {"type": "mrkdwn", "text": f"*🟢 Low:*\n{low}"},
            ],
        },
        {"type": "divider"},
    ]

    if not risky:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "✅ No sensitive data found in this channel.",
                },
            }
        )
    else:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{len(risky)} message(s) contained sensitive data:*",
                },
            }
        )
        for preview, r in risky[:10]:  # cap display at 10
            categories = ", ".join({risk.category for risk in r.risks})
            emoji = (
                "🔴"
                if r.highest_severity == Severity.HIGH
                else "🟡" if r.highest_severity == Severity.MEDIUM else "🟢"
            )
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"{emoji} *{r.highest_severity.value}* | "
                            f"{len(r.risks)} risk(s): `{categories}`\n"
                            f"> _{preview}_"
                        ),
                    },
                }
            )
            
        if len(risky) > 10:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"... and {len(risky) - 10} more messages not shown. Use /audit-report for the full report.",
                    },
                }
            )

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "🔒 Agent Zero — Compliance Guardian",
                }
            ],
        }
    )
    return blocks
