from __future__ import annotations

from joltprobe.injection.detector import (
    check_error_leak,
    check_error_strings,
    check_template_reflection,
    is_timing_anomaly,
    responses_differ,
)


# ── check_error_strings ──────────────────────────────────────────────────────
#
# The most dangerous failure mode here is a false positive: a clean OCPP
# response triggers a finding. We pin those cases explicitly. We also pin
# structural edge cases (nested payload, CALLERROR description) since those
# are the real attack surface.

class TestCheckErrorStrings:
    # --- false positive prevention -------------------------------------------

    def test_clean_boot_notification_response(self):
        resp = [3, "abc", {"status": "Accepted", "currentTime": "2024-01-01T00:00:00Z", "interval": 300}]
        assert check_error_strings(resp) is None

    def test_clean_authorize_rejected(self):
        resp = [3, "abc", {"idTagInfo": {"status": "Rejected", "expiryDate": "2025-01-01T00:00:00Z"}}]
        assert check_error_strings(resp) is None

    def test_clean_heartbeat_response(self):
        assert check_error_strings([3, "abc", {"currentTime": "2024-01-01T00:00:00Z"}]) is None

    def test_formation_violation_callerror_is_clean(self):
        # A CSMS returning a generic FormationViolation should not look like DB injection.
        resp = [4, "abc", "FormationViolation", "Required field missing in payload", {}]
        assert check_error_strings(resp) is None

    def test_not_implemented_callerror_is_clean(self):
        resp = [4, "abc", "NotImplemented", "This action is not supported", {}]
        assert check_error_strings(resp) is None

    # --- known ambiguity: "syntax error" in generic signatures ---------------
    #
    # A CSMS that echoes back "JSON syntax error" for a malformed payload will
    # match the "syntax error" generic signature. This is a false positive risk.
    # The test pins the current behaviour so any future change is deliberate.
    def test_json_syntax_error_in_callerror_matches_generic(self):
        resp = [4, "abc", "FormationViolation", "JSON syntax error in payload", {}]
        assert check_error_strings(resp) == "generic"

    # --- structural coverage -------------------------------------------------

    def test_error_buried_in_nested_payload(self):
        # json.dumps flattens the whole envelope; errors inside nested objects
        # must still be caught.
        resp = [3, "abc", {"result": {"detail": "You have an error in your SQL syntax near 'x'"}}]
        assert check_error_strings(resp) == "mysql"

    def test_error_in_callerror_description_field(self):
        # The description field of a CALLERROR is where a CSMS most commonly
        # leaks DB error strings.
        resp = [4, "abc", "InternalError", "PSQLException: ERROR: syntax error at or near", {}]
        assert check_error_strings(resp) == "postgresql"

    def test_none_response(self):
        assert check_error_strings(None) is None

    def test_empty_string(self):
        assert check_error_strings("") is None


# ── check_error_leak ─────────────────────────────────────────────────────────

class TestCheckErrorLeak:
    # --- false positive: short numeric PostgreSQL codes ----------------------
    #
    # "22001" is a PostgreSQL character-data-too-long code, but it is also a
    # plausible meter reading in Wh. The current implementation will fire on it.
    # This test pins the behaviour so the trade-off is visible.
    def test_meter_reading_matching_postgresql_code_is_false_positive(self):
        resp = [3, "abc", {"meterValue": [{"sampledValue": [{"value": "22001"}]}]}]
        # "22001" appears verbatim in the JSON; the function returns "postgresql".
        # This is a known limitation of substring matching on short numeric codes.
        assert check_error_leak(resp) == "postgresql"

    # --- false positive prevention for common clean responses ----------------

    def test_clean_callresult_is_clean(self):
        resp = [3, "abc", {"status": "Accepted", "currentTime": "2024-01-01T00:00:00Z"}]
        assert check_error_leak(resp) is None

    def test_not_implemented_callerror_is_clean(self):
        resp = [4, "abc", "NotImplemented", "This action is not supported by this CSMS", {}]
        assert check_error_leak(resp) is None

    def test_security_error_callerror_is_clean(self):
        resp = [4, "abc", "SecurityError", "Certificate verification failed", {}]
        assert check_error_leak(resp) is None

    # --- structural coverage -------------------------------------------------

    def test_orm_error_in_callerror_description(self):
        # The most likely surface: ORM stack trace leaking into CALLERROR description.
        resp = [4, "abc", "InternalError", "SequelizeDatabaseError: value too long for type character varying(20)", {}]
        assert check_error_leak(resp) == "orm"

    def test_orm_error_buried_in_nested_payload(self):
        resp = [3, "abc", {"error": {"message": "TypeORMError: Duplicate entry for key 'PRIMARY'"}}]
        assert check_error_leak(resp) == "orm"

    def test_none_response(self):
        assert check_error_leak(None) is None


# ── check_template_reflection ─────────────────────────────────────────────────

class TestCheckTemplateReflection:
    def test_reflection_detected(self):
        response = [3, "abc", {"status": "Accepted", "info": "7777777"}]
        found, _ = check_template_reflection(response, "7777777", None, "{{7*1111111}}")
        assert found is True

    def test_callerror_not_a_finding(self):
        response = [4, "abc", "InternalError", "error detail", ""]
        found, _ = check_template_reflection(response, "7777777", None, "{{7*1111111}}")
        assert found is False

    def test_rejected_auth_not_a_finding(self):
        response = [3, "abc", {"idTagInfo": {"status": "Rejected"}}]
        found, _ = check_template_reflection(response, "7777777", None, "{{7*1111111}}")
        assert found is False

    def test_invalid_auth_not_a_finding(self):
        response = [3, "abc", {"idTagInfo": {"status": "Invalid"}}]
        found, _ = check_template_reflection(response, "7777777", None, "{{7*1111111}}")
        assert found is False

    def test_expected_absent_from_response(self):
        response = [3, "abc", {"status": "Accepted"}]
        found, _ = check_template_reflection(response, "7777777", None, "{{7*1111111}}")
        assert found is False

    def test_expected_present_in_baseline_suppresses_finding(self):
        baseline = [3, "abc", {"status": "Accepted", "info": "7777777"}]
        response = [3, "xyz", {"status": "Accepted", "info": "7777777"}]
        found, _ = check_template_reflection(response, "7777777", baseline, "{{7*1111111}}")
        assert found is False

    def test_raw_payload_echoed_back_suppresses_finding(self):
        payload = "{{7*1111111}}"
        response = [3, "abc", {"status": "Accepted", "info": f"{payload} and 7777777"}]
        found, _ = check_template_reflection(response, "7777777", None, payload)
        assert found is False

    def test_none_baseline_is_allowed(self):
        response = [3, "abc", {"status": "Accepted", "calc": "49"}]
        found, _ = check_template_reflection(response, "49", None, "{{7*7}}")
        assert found is True

    # --- false positive: short expected string as substring of larger value --
    #
    # "49" (the result of 7*7) appears naturally inside transaction ID 1490 or
    # any number containing "49". The function uses substring matching with no
    # word boundary, so this fires as a finding even though nothing was evaluated.
    def test_short_expected_string_inside_larger_number_is_false_positive(self):
        baseline = [3, "abc", {"status": "Accepted", "currentTime": "2024-01-01T00:00:00Z"}]
        response = [3, "xyz", {"status": "Accepted", "transactionId": 1490}]
        found, _ = check_template_reflection(response, "49", baseline, "{{7*7}}")
        # "49" is present inside "1490" — current implementation fires.
        # Prefer expected values that are unlikely to appear as substrings (e.g. 7777777).
        assert found is True


# ── responses_differ ──────────────────────────────────────────────────────────

class TestResponsesDiffer:
    def test_same_payload_different_msg_id(self):
        # The core contract: message ID is stripped before comparison.
        a = [3, "id-aaa", {"status": "Accepted"}]
        b = [3, "id-bbb", {"status": "Accepted"}]
        assert responses_differ(a, b) is False

    def test_different_status(self):
        a = [3, "id-aaa", {"status": "Accepted"}]
        b = [3, "id-bbb", {"status": "Rejected"}]
        assert responses_differ(a, b) is True

    def test_none_vs_callresult(self):
        assert responses_differ(None, [3, "id", {"status": "Accepted"}]) is True

    def test_both_none(self):
        assert responses_differ(None, None) is False

    def test_callerror_vs_callresult(self):
        a = [3, "id-a", {"status": "Accepted"}]
        b = [4, "id-b", "InternalError", "details", ""]
        assert responses_differ(a, b) is True

    def test_key_order_independent(self):
        # sort_keys=True means payload field order does not affect comparison.
        a = [3, "id-a", {"status": "Accepted", "currentTime": "2024-01-01T00:00:00Z"}]
        b = [3, "id-b", {"currentTime": "2024-01-01T00:00:00Z", "status": "Accepted"}]
        assert responses_differ(a, b) is False

    # --- false positive: time-varying fields in responses --------------------
    #
    # BootNotification responses include currentTime. If the CSMS returns
    # otherwise-identical payloads with different timestamps (which it will,
    # since time passes between the true-payload and false-payload calls), the
    # boolean injection check will always report a finding — a false positive.
    # This test pins the behaviour; the injection check compensates for it by
    # using a clean baseline before each pair rather than relying on time-stable
    # responses.
    def test_time_varying_field_reports_as_differing(self):
        a = [3, "id-a", {"status": "Accepted", "currentTime": "2024-01-01T00:00:00Z", "interval": 300}]
        b = [3, "id-b", {"status": "Accepted", "currentTime": "2024-01-01T00:00:01Z", "interval": 300}]
        assert responses_differ(a, b) is True

    def test_extra_key_in_one_response_reports_as_differing(self):
        a = [3, "id-a", {"status": "Accepted"}]
        b = [3, "id-b", {"status": "Accepted", "interval": 300}]
        assert responses_differ(a, b) is True


# ── is_timing_anomaly ─────────────────────────────────────────────────────────

class TestIsTimingAnomaly:
    def test_clear_timing_injection(self):
        # 5s sleep payload, 5.5s observed vs 100ms baseline
        assert is_timing_anomaly(100.0, 5500.0, 5.0) is True

    def test_normal_fast_response(self):
        assert is_timing_anomaly(100.0, 150.0, 5.0) is False

    def test_multiplier_met_but_under_absolute_threshold(self):
        # 300ms > 100ms * 2.0 (multiplier satisfied) but < 2500ms (absolute min)
        assert is_timing_anomaly(100.0, 300.0, 5.0) is False

    def test_high_baseline_triggers_on_large_delay(self):
        # baseline 2000ms, response 4100ms — exceeds both multiplier and absolute min
        assert is_timing_anomaly(2000.0, 4100.0, 5.0) is True

    def test_above_absolute_threshold_but_not_multiplier(self):
        # 2600ms > 2500ms absolute, but 2600 / 2000 = 1.3 < 2.0 multiplier
        assert is_timing_anomaly(2000.0, 2600.0, 5.0) is False

    def test_just_below_absolute_threshold(self):
        assert is_timing_anomaly(100.0, 2400.0, 5.0) is False
