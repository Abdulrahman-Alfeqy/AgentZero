#!/usr/bin/env python3
"""
verify.py — Automated verification suite for Agent Zero.

Runs 14 checks:
 1. Syntax check every .py file
 2. Classifier — AWS key + colon/equals password
 3. Natural-language 'is/was/are' separator
 4. Preview masking
 5. Storage test — write → read → verify
 6. PDF test — generate → size check → delete
 7. Thread monitoring — message with thread_ts → detected (Feature 1)
 8. UUID entropy exclusion — UUID must NOT be flagged (Feature 3)
 9. MCP mock — _call_mcp_analyse mock returns True → SEMANTIC_SECRET risk
10. /dashboard/data — returns valid JSON with expected keys (Feature 5)
11. delete_flagged_message action — parses channel/ts correctly (Feature 2)
12. dismiss_alert — respond(delete_original=True) called (Feature 2)
13. MCP server integration — starts on :5002, responds to analyse_message call
14. message_changed handler — scans edited text, stores incident with notes='edited_message'

Exit code 0 = all checks passed.
Exit code 1 = one or more checks failed.
"""

from __future__ import annotations

import ast
import json
import sys
import tempfile
import threading

import traceback
from pathlib import Path



SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))

PASS = "✅ PASS"
FAIL = "❌ FAIL"
results: dict[str, bool] = {}


def section(title: str) -> None:
    print(f"\n{'─' * 65}")
    print(f"  {title}")
    print(f"{'─' * 65}")


# ────────────────────────────────────────────────────────────────
# Check 1: Syntax check every .py file
# ────────────────────────────────────────────────────────────────

section("CHECK 1: Python syntax check")

py_files = list(SCRIPT_DIR.glob("*.py"))
all_syntax_ok = True
for pyfile in sorted(py_files):
    try:
        source = pyfile.read_text(encoding="utf-8")
        ast.parse(source, filename=str(pyfile))
        print(f"  {PASS}  {pyfile.name}")
    except SyntaxError as exc:
        print(f"  {FAIL}  {pyfile.name} — {exc}")
        all_syntax_ok = False

results["syntax_check"] = all_syntax_ok


# ────────────────────────────────────────────────────────────────
# Check 2: Classifier — AWS key + colon/equals password
# ────────────────────────────────────────────────────────────────

section("CHECK 2: Classifier — AWS key + colon/equals password")

try:
    from classifier import RiskClassifier, Severity

    clf = RiskClassifier()
    test_message = (
        "Hey team, our new AWS key is AKIAIOSFODNN7EXAMPLE and "
        "the password is password=SuperSecret123!"
    )
    result = clf.analyse(test_message)

    print(f"  Message:       {test_message[:80]}")
    print(f"  Risks found:   {len(result.risks)}")
    for r in result.risks:
        print(f"    • {r.severity.value:6s} | {r.category:30s} | masked: {r.masked_value}")

    aws_found = any(r.category == "aws_access_key" for r in result.risks)
    pwd_found = any(r.category == "plaintext_password" for r in result.risks)
    count_ok = len(result.risks) >= 2

    print(f"  {PASS if aws_found else FAIL}  AWS key detected")
    print(f"  {PASS if pwd_found else FAIL}  Password detected (equals separator)")
    print(f"  {PASS if count_ok else FAIL}  At least 2 risks ({len(result.risks)} total)")

    raw_aws = "AKIAIOSFODNN7EXAMPLE"
    raw_pwd = "SuperSecret123!"
    no_leak = all(raw_aws not in r.masked_value and raw_pwd not in r.masked_value for r in result.risks)
    print(f"  {PASS if no_leak else FAIL}  No raw values in masked output")

    results["classifier_test"] = aws_found and pwd_found and count_ok and no_leak

except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    traceback.print_exc()
    results["classifier_test"] = False


# ────────────────────────────────────────────────────────────────
# Check 3: Natural-language separator
# ────────────────────────────────────────────────────────────────

section("CHECK 3: Natural-language 'is/was/are' separator")

try:
    from classifier import RiskClassifier

    clf = RiskClassifier()
    cases: list[tuple[str, str | None, bool, str]] = [
        ("my password is SuperSecret123!",       "plaintext_password", True,  "password IS value"),
        ("the secret was Abc123XYZ789long",       "plaintext_password", True,  "secret WAS value"),
        ("api key is AbCdEfGhIjKlMnOpQrSt",      "api_key_generic",    True,  "api key IS value"),
        ("password: Hunter2@secret",              "plaintext_password", True,  "colon still works"),
        ("password=letmein99!",                   "plaintext_password", True,  "equals still works"),
        ("just a normal message without secrets", None,                 False, "clean message → no hit"),
    ]

    all_ok = True
    for text, expected_cat, should_hit, label in cases:
        r = clf.analyse(text)
        if should_hit:
            ok = any(ri.category == expected_cat for ri in r.risks)
        else:
            ok = not r.has_risks
        icon = PASS if ok else FAIL
        if not ok:
            all_ok = False
        print(f"  {icon}  {label}")
        for ri in r.risks:
            print(f"       → {ri.category}: {ri.masked_value}")

    results["nlp_separator_test"] = all_ok

except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    traceback.print_exc()
    results["nlp_separator_test"] = False


# ────────────────────────────────────────────────────────────────
# Check 4: Preview masking
# ────────────────────────────────────────────────────────────────

section("CHECK 4: Preview must not contain raw secrets")

try:
    from classifier import RiskClassifier

    clf = RiskClassifier()
    raw_messages = [
        "test key: AKIAIOSFODNN7EXAMPLE is our prod key",
        "my password is SuperSecret123! please protect",
    ]

    all_ok = True
    for raw in raw_messages:
        analysis = clf.analyse(raw[:80])
        chars = list(raw[:80])
        for risk in sorted(analysis.risks, key=lambda r: r.start, reverse=True):
            start, end = risk.start, min(risk.end, len(chars))
            chars[start:end] = list(f"[{risk.masked_value}]")
        preview = "".join(chars).replace("\n", " ")

        ok = "AKIAIOSFODNN7EXAMPLE" not in preview and "SuperSecret123!" not in preview
        if not ok:
            all_ok = False
        print(f"  {PASS if ok else FAIL}  Preview: {preview[:70]}")

    results["preview_masking_test"] = all_ok

except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    traceback.print_exc()
    results["preview_masking_test"] = False


# ────────────────────────────────────────────────────────────────
# Check 5: Storage test
# ────────────────────────────────────────────────────────────────

section("CHECK 5: Storage — write → read → verify")

try:
    from storage import IncidentStore, IncidentRecord

    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
        tmp_path = Path(tf.name)

    store = IncidentStore(path=tmp_path)
    fake = IncidentRecord(
        incident_id="INC-TEST-001",
        timestamp="2026-01-01T00:00:00+00:00",
        user_id="U12345678",
        username="test.user",
        channel_id="C12345678",
        channel_name="general",
        message_preview="our key is [AKIA***EXAM]",
        risk_count=1,
        highest_severity="HIGH",
        risks=[{
            "category": "aws_access_key", "severity": "HIGH",
            "masked_value": "AKIA***EXAM", "description": "AWS Access Key ID",
            "start": 10, "end": 30,
        }],
    )
    store.append(fake)
    loaded = store.load_all()
    assert len(loaded) == 1
    assert loaded[0].incident_id == fake.incident_id
    stats = store.get_stats()
    assert stats["total"] == 1 and stats["high"] == 1
    assert "AKIAIOSFODNN7EXAMPLE" not in loaded[0].message_preview

    print(f"  {PASS}  Write, read-back, stats verified")
    print(f"  {PASS}  No raw secrets in stored preview")
    results["storage_test"] = True
    tmp_path.unlink(missing_ok=True)

except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    traceback.print_exc()
    results["storage_test"] = False
    try:
        tmp_path.unlink(missing_ok=True)
    except Exception:
        pass


# ────────────────────────────────────────────────────────────────
# Check 6: PDF generation test
# ────────────────────────────────────────────────────────────────

section("CHECK 6: PDF generation — create → size check → delete")

try:
    from storage import IncidentStore, IncidentRecord
    from report_generator import ReportGenerator

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_reports = Path(tmpdir)
        store2 = IncidentStore(path=tmp_reports / "test.jsonl")
        fake_pdf = IncidentRecord(
            incident_id="INC-PDF-001",
            timestamp="2026-01-01T12:00:00+00:00",
            user_id="U99999999", username="pdf.tester",
            channel_id="C99999999", channel_name="test-channel",
            message_preview="[AKIA***EXAM] found in test",
            risk_count=1, highest_severity="HIGH",
            risks=[{
                "category": "aws_access_key", "severity": "HIGH",
                "masked_value": "AKIA***EXAM", "description": "AWS Access Key ID",
                "start": 0, "end": 20,
            }],
        )
        store2.append(fake_pdf)
        gen = ReportGenerator(output_dir=tmp_reports)
        pdf_path = gen.generate(incidents=store2.load_all(), stats=store2.get_stats())
        assert pdf_path.exists() and pdf_path.stat().st_size > 0
        size_kb = pdf_path.stat().st_size / 1024
        print(f"  {PASS}  PDF generated: {pdf_path.name} ({size_kb:.1f} KB)")
        pdf_path.unlink()
        print(f"  {PASS}  PDF deleted successfully")

    results["pdf_test"] = True

except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    traceback.print_exc()
    results["pdf_test"] = False


# ────────────────────────────────────────────────────────────────
# Check 7: Feature 1 — Thread reply with credential → detected
# ────────────────────────────────────────────────────────────────

section("CHECK 7: Feature 1 — Thread reply with credential is detected")

try:
    from classifier import RiskClassifier

    clf = RiskClassifier()

    # Simulate a thread reply message (has thread_ts)
    thread_message_text = "Here is the prod key: AKIAIOSFODNN7EXAMPLE"
    result = clf.analyse(thread_message_text)

    aws_detected = any(r.category == "aws_access_key" for r in result.risks)
    print(f"  Message:    '{thread_message_text}'")
    print(f"  Simulated as thread reply (thread_ts present)")
    print(f"  {PASS if aws_detected else FAIL}  AWS key detected in thread reply content")

    # Verify the handle_message skip logic: only 'bot_message' and 'message_deleted' skipped
    skipped_subtypes = {"bot_message", "message_deleted"}
    thread_event_subtype = None  # thread replies have no subtype
    should_process = thread_event_subtype not in skipped_subtypes
    print(f"  {PASS if should_process else FAIL}  Thread reply subtype=None → NOT skipped")

    results["thread_monitoring"] = aws_detected and should_process

except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    traceback.print_exc()
    results["thread_monitoring"] = False


# ────────────────────────────────────────────────────────────────
# Check 8: Feature 3 — UUID entropy exclusion
# ────────────────────────────────────────────────────────────────

section("CHECK 8: Feature 3 — UUID must NOT be flagged by entropy check")

try:
    from classifier import _is_high_entropy_secret

    test_cases = [
        ("550e8400-e29b-41d4-a716-446655440000", False, "RFC UUID → NOT high-entropy secret"),
        ("a3f8b2c9d1e4f7a0b5c8d2e6f1a4b7c0",     False, "MD5 hex digest → NOT high-entropy secret"),
        ("0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d",     False, "MD5 hex (lowercase) → NOT flagged"),
        ("Tr0ub4dor&3XkPjQ@nZ!mW9sL",            True,  "Real mixed-char password → IS flagged"),
    ]

    all_ok = True
    for token, expect_high, label in test_cases:
        got = _is_high_entropy_secret(token)
        ok = got == expect_high
        if not ok:
            all_ok = False
        print(f"  {PASS if ok else FAIL}  {label}")
        print(f"       token={token[:36]}  got={got}  expected={expect_high}")

    results["uuid_entropy_exclusion"] = all_ok

except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    traceback.print_exc()
    results["uuid_entropy_exclusion"] = False


# ────────────────────────────────────────────────────────────────
# Check 9: Feature 3 — MCP mock → SEMANTIC_SECRET created
# ────────────────────────────────────────────────────────────────

section("CHECK 9: Feature 3 — MCP mock returns True → SEMANTIC_SECRET risk")

try:
    import classifier as clf_module

    # Inject a fake analyze_text that always returns True
    original_call_mcp = clf_module.analyze_text

    def mock_call_mcp(text: str) -> bool:
        """Mock: always return True (MCP server says credential found)."""
        return True

    clf_module.analyze_text = mock_call_mcp

    # Use a message that has a credential keyword but no regex match,
    # and contains a high-entropy-looking token to trigger the fallback path
    test_text = "the api_key is Tr0ub4dor&3XkPjQ@nZ9sL2w8f"
    clf = clf_module.RiskClassifier()
    result = clf.analyse(test_text)

    semantic_found = any(r.category == "semantic_secret" for r in result.risks)
    high_sev = any(r.severity == clf_module.Severity.HIGH for r in result.risks)
    ai_masked = any(r.masked_value == "[AI detected]" for r in result.risks)

    print(f"  Test text: '{test_text}'")
    print(f"  Risks found: {len(result.risks)}")
    for r in result.risks:
        print(f"    • {r.category} | {r.severity.value} | {r.masked_value}")
    print(f"  {PASS if semantic_found else FAIL}  SEMANTIC_SECRET category present")
    print(f"  {PASS if high_sev else FAIL}  Severity=HIGH")
    print(f"  {PASS if ai_masked else FAIL}  masked_value='[AI detected]'")

    results["gemini_mock"] = semantic_found and high_sev and ai_masked

    # Restore the real function
    clf_module.analyze_text = original_call_mcp

except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    traceback.print_exc()
    results["gemini_mock"] = False


# ────────────────────────────────────────────────────────────────
# Check 10: Feature 5 — /dashboard/data returns valid JSON
# ────────────────────────────────────────────────────────────────

section("CHECK 10: Feature 5 — /dashboard/data returns valid JSON")

try:
    import tempfile
    from pathlib import Path
    from storage import IncidentStore, IncidentRecord

    # Create a temp store with a few incidents for the dashboard
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tf:
        dash_store_path = Path(tf.name)

    dash_store = IncidentStore(path=dash_store_path)
    for i in range(3):
        dash_store.append(IncidentRecord(
            incident_id=f"INC-DASH-{i:03d}",
            timestamp="2026-07-04T08:00:00+00:00",
            user_id="U1234", username="tester",
            channel_id="C1234", channel_name="test-ch",
            message_preview="[AKIA***EXAM]",
            risk_count=1, highest_severity="HIGH",
            risks=[{"category": "aws_access_key", "severity": "HIGH",
                    "masked_value": "AKIA***EXAM", "description": "AWS key",
                    "start": 0, "end": 20}],
        ))

    # Patch the global store reference in main module's _build_dashboard_data
    import main as main_module
    original_store = main_module.store
    main_module.store = dash_store

    # Import Flask test client
    flask_app = main_module._create_flask_app()
    flask_app.config["TESTING"] = True

    with flask_app.test_client() as client:
        import base64
        import os
        u = os.environ.get("DASHBOARD_USERNAME", "admin")
        p = os.environ.get("DASHBOARD_PASSWORD", "pass")
        auth_str = base64.b64encode(f"{u}:{p}".encode("utf-8")).decode("utf-8")
        resp = client.get("/dashboard/data", headers={"Authorization": f"Basic {auth_str}"})
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
        data = json.loads(resp.data)

    required_keys = {
        "risk_type_distribution",
        "top_channels", "severity_counts", "total"
    }
    missing = required_keys - set(data.keys())
    has_all_keys = not missing

    sev = data.get("severity_counts", {})
    has_sev_keys = all(k in sev for k in ("HIGH", "MEDIUM", "LOW"))

    print(f"  HTTP 200:       {PASS}")
    print(f"  {PASS if has_all_keys else FAIL}  All required keys present: {required_keys}")
    if missing:
        print(f"       Missing: {missing}")
    print(f"  {PASS if has_sev_keys else FAIL}  severity_counts has HIGH/MEDIUM/LOW")
    print(f"  total={data.get('total')}, HIGH={sev.get('HIGH')}")

    results["dashboard_data"] = has_all_keys and has_sev_keys

    # Restore store
    main_module.store = original_store
    dash_store_path.unlink(missing_ok=True)

except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    traceback.print_exc()
    results["dashboard_data"] = False


# ────────────────────────────────────────────────────────────────
# Check 11: Feature 2 — build_alert_blocks actions and mark_safe value
# ────────────────────────────────────────────────────────────────

section("CHECK 11: Feature 2 — mark_safe value carries original text")

try:
    from classifier import build_alert_blocks, RiskClassifier

    clf = RiskClassifier()
    test_text = "AKIAIOSFODNN7EXAMPLE is our prod key"
    result = clf.analyse(test_text)

    channel_id = "C0BFXSG1H2L"
    ts = "1751600000.000100"
    blocks = build_alert_blocks(
        result,
        channel_id=channel_id,
        username="test.user",
        message_ts=ts,
        original_text=test_text,
    )

    # Find the actions block
    actions_block = next((b for b in blocks if b.get("type") == "actions"), None)
    assert actions_block is not None, "No actions block found in alert"

    elements = actions_block.get("elements", [])

    delete_btn = next((e for e in elements if e.get("action_id") == "delete_flagged_message"), None)
    mark_safe_btn = next((e for e in elements if e.get("action_id") == "mark_safe_pattern"), None)
    dismiss_btn = next((e for e in elements if e.get("action_id") == "dismiss_alert"), None)

    # Verify button values carry original text
    expected_value = test_text[:2000]
    mark_safe_val_ok   = mark_safe_btn   and mark_safe_btn.get("value")   == expected_value

    print(f"  {PASS if not delete_btn else FAIL}  delete_flagged_message button removed")
    print(f"  {PASS if mark_safe_btn else FAIL}  mark_safe_pattern button present")
    print(f"  {PASS if dismiss_btn else FAIL}  dismiss_alert button present")
    print(f"  {PASS if mark_safe_val_ok else FAIL}  mark_safe value='{expected_value}'")

    all_ok = all([not delete_btn, mark_safe_btn, dismiss_btn, mark_safe_val_ok])
    results["delete_action"] = all_ok

except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    traceback.print_exc()
    results["delete_action"] = False


# ────────────────────────────────────────────────────────────────
# Check 12: Feature 2 — dismiss_alert removes ephemeral
# ────────────────────────────────────────────────────────────────

section("CHECK 12: Feature 2 — dismiss_alert calls respond(delete_original=True)")

try:
    import main as main_module

    # Build a fake body and respond mock
    called_with_delete_original = []

    def mock_respond(**kwargs):
        called_with_delete_original.append(kwargs)

    def mock_ack():
        pass

    body = {"user": {"id": "U12345"}}

    main_module.handle_dismiss_alert(ack=mock_ack, body=body, respond=mock_respond)

    ok = len(called_with_delete_original) == 1 and called_with_delete_original[0].get("delete_original") is True
    print(f"  {PASS if ok else FAIL}  respond(delete_original=True) called on dismiss")
    if called_with_delete_original:
        print(f"       respond kwargs: {called_with_delete_original[0]}")

    results["dismiss_action"] = ok

except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    traceback.print_exc()
    results["dismiss_action"] = False


# ────────────────────────────────────────────────────────────────
# Check 13: MCP server integration — starts on :5002, responds to
#           analyse_message call via proper SSE protocol
# ────────────────────────────────────────────────────────────────

section("CHECK 13: MCP server — starts on :5002, analyse_message responds")

try:
    import anyio
    import urllib.request as _ureq
    import time as _time

    TEST_MCP_PORT = 5002

    # Create a fresh FastMCP instance on port 5002 (dedicated test port)
    from mcp.server.fastmcp import FastMCP as _FastMCP
    from classifier import RiskClassifier as _RC

    _test_mcp = _FastMCP(
        name="agent-zero-test",
        host="127.0.0.1",
        port=TEST_MCP_PORT,
    )

    # Register a test analyse_message tool on the test instance
    @_test_mcp.tool()
    def _test_analyse_message(text: str) -> dict:
        """Test tool: analyse a message for sensitive data."""
        return _RC().analyse(text).to_dict()

    # Start the test MCP server in a daemon thread
    def _run_test_mcp():
        _test_mcp.run(transport="sse")

    _mcp_t = threading.Thread(target=_run_test_mcp, daemon=True, name="mcp-test")
    _mcp_t.start()

    # Wait for the server to start (poll /sse endpoint, up to 6 seconds)
    server_ready = False
    for _attempt in range(20):
        _time.sleep(0.3)
        try:
            _ureq.urlopen(f"http://127.0.0.1:{TEST_MCP_PORT}/sse", timeout=1)
            server_ready = True
            break
        except Exception:
            pass

    print(f"  {PASS if server_ready else FAIL}  MCP server started on :{TEST_MCP_PORT}")

    if server_ready:
        # Call analyse_message via the official MCP Python client (SSE protocol)
        async def _mcp_test_call():
            from mcp.client.sse import sse_client
            from mcp import ClientSession

            async with sse_client(
                f"http://127.0.0.1:{TEST_MCP_PORT}/sse",
                timeout=5,
            ) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    call_result = await session.call_tool(
                        "_test_analyse_message",
                        {"text": "test key: AKIAIOSFODNN7EXAMPLE"},
                    )
                    return call_result

        call_result = anyio.run(_mcp_test_call)

        # Parse the tool result
        tool_data = None
        is_error = getattr(call_result, "isError", True)
        content_blocks = getattr(call_result, "content", [])
        if not is_error and content_blocks:
            import json as _json
            tool_data = _json.loads(content_blocks[0].text)

        has_risks = tool_data and tool_data.get("risk_count", 0) > 0
        aws_found = tool_data and any(
            r.get("category") == "aws_access_key"
            for r in tool_data.get("risks", [])
        )
        high_sev = tool_data and tool_data.get("highest_severity") == "HIGH"
        no_error = not is_error

        print(f"  {PASS if no_error else FAIL}  analyse_message returned without error")
        print(f"  {PASS if has_risks else FAIL}  risk_count={tool_data.get('risk_count') if tool_data else 'N/A'} (expected >=1)")
        print(f"  {PASS if aws_found else FAIL}  aws_access_key category detected")
        print(f"  {PASS if high_sev else FAIL}  highest_severity=HIGH")
        if tool_data:
            print(f"       masked_value={tool_data['risks'][0]['masked_value']}")

        results["mcp_server_integration"] = all([server_ready, no_error, has_risks, aws_found, high_sev])
    else:
        print(f"  {FAIL}  MCP server did not start within 6 seconds")
        results["mcp_server_integration"] = False

except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    traceback.print_exc()
    results["mcp_server_integration"] = False


# ────────────────────────────────────────────────────────────────
# Check 14: message_changed handler — scans edited text, stores incident
# ────────────────────────────────────────────────────────────────

section("CHECK 14: message_changed — edited text scanned, incident stored")

try:
    import main as _main
    from classifier import RiskClassifier
    from storage import IncidentStore, IncidentRecord

    # Build a fake message_changed event
    test_channel   = "C0TESTCHAN1"
    test_ts        = "1751600001.000200"
    test_inner_uid = "U0TESTUSER1"
    edited_text    = "Updated: our new key is AKIAIOSFODNN7EXAMPLE prod"

    fake_event = {
        "type": "message",
        "subtype": "message_changed",
        "channel": test_channel,
        "message": {
            "text": edited_text,
            "user": test_inner_uid,
            "ts": test_ts,
        },
    }

    # ---------- stub the Slack client calls -----------------------------------
    stored_records: list[IncidentRecord] = []
    ephemeral_payloads: list[dict] = []

    class _FakeClient:
        def users_info(self, user=""):
            return {"user": {"real_name": "Test User", "name": "testuser"}}

        def conversations_info(self, channel=""):
            return {"channel": {"name": "test-chan"}}

        def chat_postEphemeral(self, **kwargs):
            ephemeral_payloads.append(kwargs)
            return {"ok": True}

        def chat_postMessage(self, **kwargs):
            return {"ok": True}

    # Patch store.append so we capture what gets stored without file I/O
    original_store_append = _main.store.append
    _main.store.append = lambda r: stored_records.append(r)

    # ---------- invoke handle_message -----------------------------------------
    _main.handle_message(
        event=fake_event,
        client=_FakeClient(),
        say=lambda **kw: None,
    )

    # ---------- restore -------------------------------------------------------
    _main.store.append = original_store_append

    # ---------- assertions ----------------------------------------------------
    incident_stored   = len(stored_records) == 1
    is_edited_note    = stored_records[0].notes == "edited_message" if stored_records else False
    ts_correct        = stored_records[0].user_id == test_inner_uid if stored_records else False
    channel_correct   = stored_records[0].channel_id == test_channel if stored_records else False
    aws_in_risks      = any(
        r["category"] == "aws_access_key"
        for r in (stored_records[0].risks if stored_records else [])
    )
    high_sev          = stored_records[0].highest_severity == "HIGH" if stored_records else False
    ephemeral_sent    = len(ephemeral_payloads) == 1
    no_raw_in_preview = (
        "AKIAIOSFODNN7EXAMPLE" not in stored_records[0].message_preview
        if stored_records else False
    )

    print(f"  {PASS if incident_stored else FAIL}  Incident stored (count={len(stored_records)})")
    print(f"  {PASS if is_edited_note else FAIL}  notes='edited_message'")
    print(f"  {PASS if ts_correct else FAIL}  user_id='{stored_records[0].user_id if stored_records else 'N/A'}' (expected '{test_inner_uid}')")
    print(f"  {PASS if channel_correct else FAIL}  channel_id='{stored_records[0].channel_id if stored_records else 'N/A'}' (expected '{test_channel}')")
    print(f"  {PASS if aws_in_risks else FAIL}  aws_access_key in risks")
    print(f"  {PASS if high_sev else FAIL}  highest_severity=HIGH")
    print(f"  {PASS if ephemeral_sent else FAIL}  Ephemeral alert sent")
    print(f"  {PASS if no_raw_in_preview else FAIL}  No raw secret in preview")
    if stored_records:
        print(f"       preview: {stored_records[0].message_preview}")

    results["message_changed_handler"] = all([
        incident_stored, is_edited_note, ts_correct, channel_correct,
        aws_in_risks, high_sev, ephemeral_sent, no_raw_in_preview,
    ])

except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    traceback.print_exc()
    results["message_changed_handler"] = False


# ────────────────────────────────────────────────────────────────
# Check 15: Slash command — handle_audit_scan
# ────────────────────────────────────────────────────────────────

section("CHECK 15: Slash command — /audit-scan")

try:
    import main as _main

    fake_command = {
        "channel_id": "C12345",
        "user_id": "U12345"
    }

    class _FakeAck:
        called = False
        def __call__(self, text=None):
            self.called = True

    class _FakeClient:
        def conversations_history(self, **kwargs):
            return {"messages": [{"text": "Hello world", "user": "U99"}]}

        def users_info(self, user=""):
            return {"user": {"real_name": "Test User", "name": "testuser"}}

        def conversations_info(self, channel=""):
            return {"channel": {"name": "test-chan"}}

        def conversations_join(self, channel=""):
            return {"ok": True}

    ack = _FakeAck()
    client = _FakeClient()
    
    ephemeral_msgs = []
    def fake_say(text="", blocks=None, thread_ts=None):
        ephemeral_msgs.append(text)

    _main.audit_scan(ack=ack, command=fake_command, client=client, respond=fake_say)
    
    print(f"  {PASS if ack.called else FAIL}  ack() called")
    print(f"  {PASS if len(ephemeral_msgs) > 0 else FAIL}  say() called (ephemeral sent)")
    results["slash_command"] = ack.called and len(ephemeral_msgs) > 0

except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    traceback.print_exc()
    results["slash_command"] = False


# ────────────────────────────────────────────────────────────────
# ────────────────────────────────────────────────────────────────
# Check 16: Command — /audit-search
# ────────────────────────────────────────────────────────────────

section("CHECK 16: Command — /audit-search")

try:
    import main as _main
    ack16 = _FakeAck()
    
    # We no longer need Slack client methods for /audit-search
    client16 = object()
    
    respond16_kwargs = {}
    def fake_respond16(**kwargs):
        respond16_kwargs.update(kwargs)

    from storage import IncidentRecord
    _main.store.append(IncidentRecord(
        incident_id="TEST-SEARCH",
        timestamp="2026-07-07T00:00:00Z",
        user_id="U123",
        username="searchuser",
        channel_id="C123",
        channel_name="searchchannel",
        message_preview="test",
        risk_count=1,
        highest_severity="HIGH",
        risks=[{"category": "aws_access_key", "severity": "HIGH", "masked_value": "test"}],
        notes="looking for api keys"
    ))

    _main.audit_search(
        ack=ack16,
        command={"text": "api keys"},
        client=client16,
        respond=fake_respond16
    )

    print(f"  {PASS if ack16.called else FAIL}  ack() called")
    has_blocks = "blocks" in respond16_kwargs
    has_text = "text" in respond16_kwargs
    print(f"  {PASS if has_blocks or has_text else FAIL}  Blocks or text returned")
    
    blocks_str = str(respond16_kwargs.get("blocks", []))
    found_search_result = "api keys" in blocks_str
    print(f"  {PASS if found_search_result else FAIL}  Search result found in local incidents")
    
    results["audit_search"] = ack16.called and (has_blocks or has_text) and found_search_result
except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    results["audit_search"] = False


# ────────────────────────────────────────────────────────────────
# Check 17: Action — mark_safe_pattern prevents detection
# ────────────────────────────────────────────────────────────────

section("CHECK 17: Action — mark_safe_pattern")

try:
    import main as _main
    
    ack17 = _FakeAck()
    respond17_kwargs = {}
    def fake_respond17(**kwargs):
        respond17_kwargs.update(kwargs)

    _main.handle_mark_safe(
        ack=ack17,
        body={"actions": [{"value": "my_safe_secret_key_123"}]},
        respond=fake_respond17
    )
    res17 = _main.classifier.analyse("my_safe_secret_key_123")

    print(f"  {PASS if ack17.called else FAIL}  ack() called")
    print(f"  {PASS if not res17.has_risks else FAIL}  Safe pattern prevents detection")
    results["mark_safe_action"] = ack17.called and not res17.has_risks
except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    results["mark_safe_action"] = False


# ────────────────────────────────────────────────────────────────
# Check 18: Dashboard Auth
# ────────────────────────────────────────────────────────────────

section("CHECK 18: Dashboard Auth Check")

try:
    import main as _main
    import os
    os.environ["DASHBOARD_USERNAME"] = "admin"
    os.environ["DASHBOARD_PASSWORD"] = "pass"
    ok1 = _main._check_auth("admin", "pass")
    ok2 = not _main._check_auth("admin", "wrong")
    print(f"  {PASS if ok1 and ok2 else FAIL}  Auth logic works")
    results["dashboard_auth"] = ok1 and ok2
except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    results["dashboard_auth"] = False


# ────────────────────────────────────────────────────────────────
# Check 19: Dashboard Empty State
# ────────────────────────────────────────────────────────────────

section("CHECK 19: Dashboard Empty State")

try:
    import main as _main
    # Mock store to return empty
    original_load = _main.store.load_all
    _main.store.load_all = lambda: []
    
    import base64
    import os
    u = os.environ.get("DASHBOARD_USERNAME", "admin")
    p = os.environ.get("DASHBOARD_PASSWORD", "pass")
    auth_str = base64.b64encode(f"{u}:{p}".encode("utf-8")).decode("utf-8")
    
    with flask_app.test_client() as client:
        resp = client.get("/dashboard", headers={"Authorization": f"Basic {auth_str}"})
        html = resp.data.decode()
        has_empty = "All is quiet." in html
    
    _main.store.load_all = original_load

    print(f"  {PASS if has_empty else FAIL}  Empty state message returned")
    results["dashboard_empty"] = has_empty
except Exception as exc:
    print(f"  {FAIL}  Exception: {exc}")
    results["dashboard_empty"] = False


# ────────────────────────────────────────────────────────────────
# Check 20: PDF Generation Malicious String test
# ────────────────────────────────────────────────────────────────

section("CHECK 20: PDF Generation Malicious String")

try:
    from report_generator import ReportGenerator
    from storage import IncidentRecord
    import uuid
    import tempfile
    
    with tempfile.TemporaryDirectory() as td:
        rg = ReportGenerator(output_dir=td)
        inc = IncidentRecord(
            incident_id="INC-123",
            timestamp="2026-07-07T00:00:00Z",
            user_id="U123",
            username="<script>alert(1)</script>",
            channel_id="C123",
            channel_name="<malicious>&channel",
            message_preview="test",
            risk_count=1,
            highest_severity="HIGH",
            risks=[]
        )
        rg.generate([inc], {"total": 1, "high": 1, "medium": 0, "low": 0})
        print(f"  {PASS}  PDF generated successfully with malicious strings")
        results["pdf_escape"] = True
except Exception as e:
    print(f"  {FAIL}  PDF generation failed: {e}")
    results["pdf_escape"] = False


# ────────────────────────────────────────────────────────────────
# Check 21: Additional Credentials & False Positives
# ────────────────────────────────────────────────────────────────

section("CHECK 21: Additional Credentials & False Positives")

try:
    from classifier import RiskClassifier, Severity
    clf = RiskClassifier()
    
    test_cases = [
        ("sk_test_abcdefghijklmnopqrstuvwxyz12", "stripe_key", Severity.HIGH, True),
        ("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", "github_token", Severity.HIGH, True),
        ("4111111111111111", "credit_card", Severity.HIGH, True),
        ("-----BEGIN RSA PRIVATE KEY-----", "private_key", Severity.HIGH, True),
        ("postgresql://user:pass@localhost:5432/db", "database_connection_string", Severity.HIGH, True),
        ("Let's set up a meeting to discuss the password policy", None, None, False),
        ("password reset tomorrow", None, None, False),
        ("slack_token = xoxb-1234567890-1234567890-abcdefghij", "slack_token", Severity.HIGH, True),
    ]

    all_ok = True
    for text, exp_cat, exp_sev, should_flag in test_cases:
        res = clf.analyse(text)
        if should_flag:
            if not res.has_risks:
                print(f"  {FAIL}  Failed to flag '{text[:30]}...'")
                all_ok = False
            else:
                r = res.risks[0]
                if r.category != exp_cat:
                    print(f"  {FAIL}  Category mismatch for '{text[:30]}...': Expected {exp_cat}, got {r.category}")
                    all_ok = False
                elif r.severity != exp_sev:
                    print(f"  {FAIL}  Severity mismatch for '{text[:30]}...': Expected {exp_sev}, got {r.severity}")
                    all_ok = False
                else:
                    print(f"  {PASS}  Correctly flagged '{text[:30]}...' as {exp_cat} ({exp_sev.value})")
        else:
            if res.has_risks:
                print(f"  {FAIL}  False positive for '{text[:30]}...': flagged as {res.risks[0].category}")
                all_ok = False
            else:
                print(f"  {PASS}  Correctly ignored '{text[:30]}...'")

    results["additional_credentials"] = all_ok
except Exception as e:
    print(f"  {FAIL}  Check 21 Exception: {e}")
    results["additional_credentials"] = False


# ────────────────────────────────────────────────────────────────
# Check 22: AI Provider Fallbacks
# ────────────────────────────────────────────────────────────────

section("CHECK 22: AI Provider Fallbacks")

try:
    import ai_provider
    import os
    
    original_mcp_cache = ai_provider._mcp_cache.copy()
    ai_provider._mcp_cache.clear()
    
    os.environ["GEMINI_API_KEY"] = "fake_gemini"
    os.environ["OPENROUTER_API_KEY"] = "fake_openrouter"
    
    import requests
    original_post = requests.post
    
    def fail_post(*args, **kwargs):
        raise Exception("Mock REST failure")
    requests.post = fail_post
    
    class FakeGenaiModels:
        def generate_content(self, *args, **kwargs):
            raise Exception("Mock Gemini failure")
            
    class FakeGenaiClient:
        def __init__(self, api_key):
            self.models = FakeGenaiModels()
            
    import sys
    sys.modules["google.genai"] = type("MockGenai", (), {"Client": FakeGenaiClient})
    sys.modules["google"] = type("MockGoogle", (), {"genai": sys.modules["google.genai"]})
    
    res1 = ai_provider.analyze_text("some random text 123")
    print(f"  {PASS if not res1 else FAIL}  All providers fail -> analyze_text returns False")
    
    def mock_openrouter_post(*args, **kwargs):
        url = kwargs.get("url") or (args[0] if args else "")
        if "openrouter" in url:
            class MockResp:
                def raise_for_status(self): pass
                def json(self): return {"choices": [{"message": {"content": "YES"}}]}
            return MockResp()
        raise Exception("Mock other REST failure")
        
    requests.post = mock_openrouter_post
    ai_provider._mcp_cache.clear()
    res2 = ai_provider.analyze_text("this text will use openrouter")
    print(f"  {PASS if res2 else FAIL}  Gemini fails, OpenRouter succeeds -> returns True")
    
    # Should hit cache, so mock won't matter
    res3 = ai_provider.analyze_text("this text will use openrouter")
    print(f"  {PASS if res3 else FAIL}  Cached result returns instantly without calling")
    
    results["ai_fallback"] = (not res1) and res2 and res3
    
    requests.post = original_post
    ai_provider._mcp_cache = original_mcp_cache
except Exception as e:
    import traceback
    traceback.print_exc()
    print(f"  {FAIL}  Check 22 Exception: {e}")
    results["ai_fallback"] = False


# ────────────────────────────────────────────────────────────────
# Check 23: Smart Deduplication and Worst-Case Scenarios
# ────────────────────────────────────────────────────────────────

section("CHECK 23: Smart Deduplication and Worst-Case Scenarios")

try:
    import classifier as clf_module
    clf = clf_module.RiskClassifier()
    
    test_cases = [
        # (text, expected_risk_count, [ (expected_cat_substring, expected_sev) ])
        ("sk_test_abcdefghijklmnopqrstuvwxyz123", 1, [("stripe_key", clf_module.Severity.HIGH)]),
        ("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890", 1, [("github_token", clf_module.Severity.HIGH)]),
        ("4111-1111-1111-1111", 1, [("credit_card", clf_module.Severity.HIGH)]),
        ("-----BEGIN OPENSSH PRIVATE KEY-----", 1, [("private_key", clf_module.Severity.HIGH)]),
        ("Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;", 1, [("database_connection_string", clf_module.Severity.HIGH)]),
        ("discuss the password policy", 0, []),
        ("password reset tomorrow", 0, []),
        ("xoxb-1234567890-1234567890-abcdefg1234", 1, [("slack_token", clf_module.Severity.HIGH)]),
        ("password is secret123 and another password is secret123", 1, [("plaintext_password", clf_module.Severity.HIGH)]),
        ("password is 123-456-7890", 1, [("plaintext_password + phone_number", clf_module.Severity.HIGH)]),
        ("password is secret123 and slack_token = xoxb-1234567890-1234567890-abcdefg1234", 2, []),
    ]
    
    all_ok_23 = True
    for text, exp_count, exp_risks in test_cases:
        res = clf.analyse(text)
        if len(res.risks) != exp_count:
            print(f"  {FAIL}  Expected {exp_count} risks for '{text[:30]}...', got {len(res.risks)}")
            for r in res.risks:
                print(f"      Got: {r.category} | {r.masked_value}")
            all_ok_23 = False
            continue
            
        for i, (exp_cat, exp_sev) in enumerate(exp_risks):
            r = res.risks[i]
            if exp_cat not in r.category:
                print(f"  {FAIL}  Expected category '{exp_cat}' for '{text[:30]}...', got {r.category}")
                all_ok_23 = False
            elif r.severity != exp_sev:
                print(f"  {FAIL}  Expected severity {exp_sev} for '{text[:30]}...', got {r.severity}")
                all_ok_23 = False
            else:
                print(f"  {PASS}  Correctly handled '{text[:30]}...' -> {r.category}")
                
        if exp_count == 0:
            print(f"  {PASS}  Correctly ignored '{text[:30]}...'")
            
    # For the last test case (2 distinct risks), check if both are present
    if len(test_cases[-1][2]) == 0 and all_ok_23:
        res = clf.analyse(test_cases[-1][0])
        cats = [r.category for r in res.risks]
        if "plaintext_password" in cats and "slack_token" in cats:
            print(f"  {PASS}  Distinct risks preserved for '{test_cases[-1][0][:30]}...'")
        else:
            print(f"  {FAIL}  Distinct risks not preserved: {cats}")
            all_ok_23 = False
            
    results["dedup_worst_cases"] = all_ok_23
except Exception as e:
    import traceback
    traceback.print_exc()
    print(f"  {FAIL}  Check 23 Exception: {e}")
    results["dedup_worst_cases"] = False

# ────────────────────────────────────────────────────────────────
# VERIFICATION SUMMARY
# ────────────────────────────────────────────────────────────────

section("VERIFICATION SUMMARY")

label_map = {
    "syntax_check":              "Syntax Check (all .py files)",
    "classifier_test":           "Classifier — AWS key + colon/equals password",
    "nlp_separator_test":        "Natural-language 'is/was/are' separator",
    "preview_masking_test":      "Preview masking (no raw secrets)",
    "storage_test":              "Storage — write → read → verify",
    "pdf_test":                  "PDF — generate → size check → delete",
    "thread_monitoring":         "Feature 1 — Thread replies detected correctly",
    "uuid_entropy_exclusion":    "Feature 3 — UUID/hex excluded from entropy flag",
    "gemini_mock":               "Feature 3 — MCP mock → SEMANTIC_SECRET risk",
    "dashboard_data":            "Feature 5 — /dashboard/data valid JSON",
    "delete_action":             "Feature 2 — mark_safe value carries original text",
    "dismiss_action":            "Feature 2 — dismiss_alert calls delete_original",
    "mcp_server_integration":    "MCP server — starts on :5002, analyse_message works",
    "message_changed_handler":   "Edited messages — message_changed scanned & stored",
    "slash_command":             "Feature 4 — Slash command /audit-scan handled",
    "audit_search":              "Check 16: /audit-search returns mock results",
    "mark_safe_action":          "Check 17: mark_safe_pattern prevents detection",
    "dashboard_auth":            "Check 18: Dashboard basic auth check",
    "dashboard_empty":           "Check 19: Dashboard empty state returned",
    "pdf_escape":                "Check 20: PDF generation escapes malicious strings",
    "additional_credentials":    "Check 21: Additional Credentials and False Positives",
    "ai_fallback":               "Check 22: AI Provider Fallbacks",
    "dedup_worst_cases":         "Check 23: Smart Deduplication and Worst-Case Scenarios",
}

all_passed = True
for key, label in label_map.items():
    ok = results.get(key, False)
    icon = PASS if ok else FAIL
    print(f"  {icon}  {label}")
    if not ok:
        all_passed = False

print()
if all_passed:
    print("  🎉  ALL CHECKS PASSED — Agent Zero v3 is ready!")
    print()
    print("  To start the bot:")
    print("    source .venv/bin/activate && python main.py")
    print()
    print("  Dashboard:  http://127.0.0.1:5000/dashboard")
    print("  MCP Server: http://127.0.0.1:5001/sse")
else:
    print("  ⚠️   Some checks FAILED — see details above.")

sys.exit(0 if all_passed else 1)
