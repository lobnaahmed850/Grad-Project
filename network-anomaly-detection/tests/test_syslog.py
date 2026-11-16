import json

import pytest

import logic
from netguard.syslog import normalize

NOW = "2026-01-01T00:00:00+00:00"


@pytest.mark.parametrize("date,expected", [
    ("Mar  1 00:01:02.123", "2026-03-01T00:01:02.123Z"),
    ("Mar 1 00:01:02", "2026-03-01T00:01:02.000Z"),
    ("Dec 31 23:59:59", "2025-12-31T23:59:59.000Z"),
])
def test_cisco_padding_optional_fraction_and_year_rollover(date, expected):
    event = logic.parse_gns3_event(f"<189>12: R1: *{date}: %LINEPROTO-5-UPDOWN: Interface changed", "127.0.0.1", NOW)
    assert event["@timestamp"] == expected
    assert event["parser"]["version"] == "2.0.0"


def test_device_timezone_is_explicit(monkeypatch):
    monkeypatch.setenv("NETGUARD_DEVICE_TIMEZONE", "America/New_York")
    event = normalize("<38>Jan  2 03:04:05 ubuntu sshd[9]: Accepted publickey for root", "127.0.0.1", NOW)
    assert event["@timestamp"] == "2026-01-02T08:04:05.000Z"
    assert event["parser"]["timezone"] == "America/New_York"


@pytest.mark.parametrize("message", ["Failed password for sudo_admin", "Accepted publickey for sudo_user", "sudo command failed"])
def test_sudo_substrings_never_change_sshd_process(message):
    event = normalize(f"<38>Jan  2 03:04:05 ubuntu sshd[9]: {message}", "127.0.0.1", NOW)
    assert event["process"]["name"] == "sshd"
    assert event["event"]["dataset"] == "linux.sshd"


def test_real_nested_logger_tag_is_recognized():
    event = normalize("<85>Jan  2 03:04:05 ubuntu alice: sudo[12]: alice : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls", "127.0.0.1", NOW)
    assert event["process"]["name"] == "sudo"
    assert event["process"]["command_line"] == "/bin/ls"


@pytest.mark.parametrize("payload", [
    "<14>2026-01-02 03:04:05 computer=WIN10 event_id=4625 user=bob message='An account failed to log on'",
    json.dumps({"EventTime": "2026-01-02T03:04:05Z", "Hostname": "WIN10", "EventID": 4625,
                "TargetUserName": "bob", "Message": "An account failed to log on"}),
    "<14>Jan  2 03:04:05 WIN10 MSWinEventLog\t1\tSecurity\t37\tFri Jan  2 03:04:05 2026\t4625\tMicrosoft-Windows-Security-Auditing\tN/A\tFailure Audit\tAn account failed",
])
def test_windows_text_json_and_nxlog_formats(payload):
    event = normalize(payload, "127.0.0.1", NOW)
    assert event is not None
    assert event["@timestamp"] == "2026-01-02T03:04:05.000Z"
    assert event["event"]["code"] == "4625"
    assert event["event"]["outcome"] == "failure"


def test_rfc5424_timestamp_with_offset():
    event = normalize("<38>1 2026-01-02T03:04:05-05:00 ubuntu sshd 9 - - Accepted publickey", "127.0.0.1", NOW)
    assert event["@timestamp"] == "2026-01-02T08:04:05.000Z"


@pytest.mark.parametrize("payload", [
    "", "not syslog", "{}", "[]", '{"EventID":4625}', "<999>Jan  2 03:04:05 ubuntu sshd: failed",
    "<38>Foo 88 77:77:77 ubuntu sshd: failed", "<14>2026-13-02 03:04:05 computer=WIN event_id=4625 message=x",
    "<189>12: R1: *Foo 45 00:01:02: %LINEPROTO-5-UPDOWN: changed",
])
def test_invalid_events_are_quarantined_instead_of_using_current_time(payload):
    assert normalize(payload, "127.0.0.1", NOW) is None
