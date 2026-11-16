"""Conservative syslog normalization with explicit timestamp provenance."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

PARSER_VERSION = "2.0.0"
UTC = timezone.utc
CISCO_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>(?:(?P<seq>\d+):\s*)?(?:(?P<hostname>[\w.-]+):\s*)?"
    r"[*.]?(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)"
    r":\s*%(?P<facility>[A-Z0-9_]+)-(?P<severity>[0-7])-(?P<mnemonic>[A-Z0-9_]+):\s*(?P<message>.*)$",
    re.DOTALL,
)
WINDOWS_PATTERN = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<timestamp>\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?)"
    r"\s+computer=(?P<computer>\S+)\s+event_id=(?P<event_id>\d+)\s+(?:user=(?P<user>\S+)\s+)?"
    r"message=(?P<message>.*)$", re.DOTALL,
)
LINUX_PATTERN = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+"
    r"(?P<hostname>\S+)\s+(?P<process>[\w/.-]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$", re.DOTALL,
)
RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1 (?P<timestamp>\S+) (?P<hostname>\S+) (?P<process>\S+) (?P<pid>\S+) "
    r"(?P<msgid>\S+) - (?P<message>.*)$", re.DOTALL,
)
CISCO_EVENT_MAP = {
    "LINEPROTO-UPDOWN": (["network"], ["change"]),
    "SEC_LOGIN-LOGIN_FAILED": (["authentication"], ["denied"]),
}
WINDOWS_EVENT_MAP = {
    "4624": (["authentication"], ["start"]), "4625": (["authentication"], ["denied"]),
    "4634": (["authentication"], ["end"]), "4720": (["iam"], ["creation"]),
    "4722": (["iam"], ["change"]), "4728": (["iam"], ["group", "change"]),
    "4732": (["iam"], ["group", "change"]),
}
LINUX_EVENT_MAP = {
    "sudo": (["process"], ["change"]), "sshd": (["authentication"], ["info"]),
    "su": (["authentication"], ["change"]),
}


def iso(value):
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def map_severity(value):
    names = ("emergency", "alert", "critical", "error", "warning", "notice", "info", "debug")
    try:
        number = int(value)
    except (ValueError, TypeError):
        number = {"error": 3, "crit": 2, "failure": 3, "warn": 4, "warning": 4}.get(str(value).lower(), 6)
    number = number if 0 <= number <= 7 else 6
    return names[number], number


def parse_time(raw, received, yearless=False):
    reference = datetime.fromisoformat(received.replace("Z", "+00:00"))
    if reference.tzinfo is None:
        raise ValueError("Ingestion timestamp requires an offset")
    device_zone = ZoneInfo(os.environ.get("NETGUARD_DEVICE_TIMEZONE", "UTC"))
    if yearless:
        pattern = "%Y %b %d %H:%M:%S.%f" if "." in raw else "%Y %b %d %H:%M:%S"
        choices = []
        for year in (reference.year - 1, reference.year, reference.year + 1):
            try:
                choices.append(datetime.strptime(f"{year} {raw}", pattern).replace(tzinfo=device_zone))
            except ValueError:
                continue
        if not choices:
            raise ValueError("Invalid device timestamp")
        timestamp = min(choices, key=lambda candidate: abs((candidate - reference).total_seconds()))
    else:
        timestamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=device_zone)
    return iso(timestamp)


def normalize_cisco_timestamp(raw_ts):
    return parse_time(raw_ts, datetime.now(UTC).isoformat(), yearless=True)


def _base(raw, source, received, fields, parser, dataset, categories, types, severity):
    if not isinstance(raw, str) or not raw.strip() or len(raw) > 65507:
        raise ValueError("Empty or oversized syslog")
    ipaddress.ip_address(source)
    pri = int(fields.get("pri") or 14)
    if not 0 <= pri <= 191:
        raise ValueError("Invalid syslog PRI")
    timestamp = parse_time(fields["timestamp"], received, fields.get("yearless", False))
    level, severity = map_severity(severity)
    return {
        "@timestamp": timestamp, "ecs": {"version": "9.3.0"}, "log": {"level": level},
        "event": {"id": hashlib.sha256(raw.encode()).hexdigest()[:16], "kind": "event",
                  "category": categories, "type": types, "severity": severity, "created": timestamp,
                  "ingested": iso(datetime.fromisoformat(received.replace("Z", "+00:00"))),
                  "dataset": dataset, "module": "python-udp-collector", "original": raw},
        "host": {"name": fields.get("hostname") or fields.get("computer") or "unknown-device", "ip": source},
        "source": {"ip": source}, "message": fields["message"],
        "parser": {"version": PARSER_VERSION, "name": parser,
                   "timezone": os.environ.get("NETGUARD_DEVICE_TIMEZONE", "UTC"),
                   "year_inferred": fields.get("yearless", False)},
    }


def parse_gns3_event(raw_message, source_ip, iso_now):
    match = CISCO_PATTERN.fullmatch(raw_message)
    if not match:
        return None
    fields = match.groupdict()
    fields["yearless"] = True
    key = f"{fields['facility']}-{fields['mnemonic']}"
    categories, types = CISCO_EVENT_MAP.get(key, (["network"], ["info"]))
    try:
        event = _base(raw_message, source_ip, iso_now, fields, "cisco_ios", "gns3.syslog", categories, types, fields["severity"])
    except (ValueError, OverflowError):
        return None
    event["event"]["code"] = key
    if fields["seq"]:
        event["event"]["sequence"] = int(fields["seq"])
    if key == "SEC_LOGIN-LOGIN_FAILED":
        details = re.search(r"\[user:\s*([^\]]+)\]\s*\[Source:\s*([^\]]+)\]", fields["message"])
        event["event"].update(action="logon-failed", outcome="failure")
        if details:
            event["user"] = {"name": details[1]}
            try:
                event["source"]["ip"] = str(ipaddress.ip_address(details[2]))
            except ValueError:
                pass
    return event


def _windows_fields(raw):
    if raw.lstrip().startswith("{"):
        try:
            payload = json.loads(raw)
        except (ValueError, TypeError):
            return None
        if not isinstance(payload, dict):
            return None
        lowered = {key.lower(): value for key, value in payload.items()}
        code = lowered.get("eventid", lowered.get("event_id"))
        host = lowered.get("hostname", lowered.get("computer"))
        timestamp = lowered.get("eventtime", lowered.get("timecreated", lowered.get("timestamp")))
        message = lowered.get("message")
        if not str(code).isdigit() or not isinstance(host, str) or not isinstance(timestamp, str) or not isinstance(message, str):
            return None
        return dict(event_id=str(code), computer=host, timestamp=timestamp, message=message,
                    user=lowered.get("targetusername", lowered.get("accountname")), pri=14)
    match = WINDOWS_PATTERN.fullmatch(raw)
    if match:
        fields = match.groupdict()
        message = fields["message"]
        if len(message) >= 2 and message[0] == message[-1] and message[0] in "\"'":
            fields["message"] = message[1:-1]
        return fields
    match = re.match(r"^<(?P<pri>\d{1,3})>\w{3}\s+\d+\s+[\d:]+\s+(?P<computer>\S+)\s+MSWinEventLog\s+", raw)
    if not match:
        return None
    detail = re.search(r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(\w{3}\s+\d+\s+[\d:]+\s+\d{4})\s+(\d+)\s+Microsoft-Windows", raw)
    if not detail:
        return None
    try:
        timestamp = datetime.strptime(detail[1], "%b %d %H:%M:%S %Y").isoformat()
    except ValueError:
        return None
    return {**match.groupdict(), "timestamp": timestamp, "event_id": detail[2], "message": raw[detail.end():].strip()}


def parse_windows_event(raw_message, source_ip, iso_now):
    fields = _windows_fields(raw_message)
    if fields is None:
        return None
    code = fields["event_id"]
    categories, types = WINDOWS_EVENT_MAP.get(code, (["host"], ["info"]))
    try:
        severity = 4 if code == "4625" else int(fields.get("pri") or 14) % 8
        parser_name = "nxlog_json" if raw_message.lstrip().startswith("{") else "windows_powershell"
        event = _base(raw_message, source_ip, iso_now, fields, parser_name, "windows.security", categories, types, severity)
    except (ValueError, TypeError, OverflowError):
        return None
    event["host"]["os"] = {"family": "windows"}
    event["event"]["code"] = code
    if code in ("4624", "4625"):
        event["event"].update(action="logon-success" if code == "4624" else "logon-failed",
                              outcome="success" if code == "4624" else "failure")
    if isinstance(fields.get("user"), str) and fields["user"] not in ("-", "N/A", ""):
        event["user"] = {"name": fields["user"]}
    return event


def parse_linux_event(raw_message, source_ip, iso_now):
    match = LINUX_PATTERN.fullmatch(raw_message)
    yearless = match is not None
    if match is None:
        match = RFC5424.fullmatch(raw_message)
    if match is None or "MSWinEventLog" in raw_message:
        return None
    fields = match.groupdict()
    fields["yearless"] = yearless
    process = fields["process"]
    nested = re.match(r"^(sudo|sshd|su)(?:\[(\d+)\])?:\s*(.*)$", fields["message"], re.DOTALL)
    if nested and process not in LINUX_EVENT_MAP:
        process = fields["process"] = nested[1]
        fields["pid"], fields["message"] = nested[2], nested[3]
    categories, types = LINUX_EVENT_MAP.get(process, (["host"], ["info"]))
    try:
        event = _base(raw_message, source_ip, iso_now, fields, "linux_rsyslog", f"linux.{process}", categories, types, int(fields["pri"]) % 8)
    except (ValueError, OverflowError):
        return None
    event["host"]["os"] = {"family": "linux"}
    event["process"] = {"name": process}
    if str(fields.get("pid") or "").isdigit():
        event["process"]["pid"] = int(fields["pid"])
    if process == "sshd":
        failed = fields["message"].startswith(("Failed ", "Invalid user", "authentication failure"))
        accepted = fields["message"].startswith("Accepted ")
        if failed or accepted:
            event["event"].update(action="logon-failed" if failed else "logon-success",
                                  outcome="failure" if failed else "success", type=["denied"] if failed else ["start"])
    if process == "sudo":
        details = re.match(r"(\S+)\s+:.*?\bUSER=(\S+)\s*;\s*COMMAND=(.+)$", fields["message"])
        if details:
            event["user"] = {"name": details[1], "target": {"name": details[2]}}
            event["process"]["command_line"] = details[3]
            event["event"].update(action="privilege_elevation", outcome="success")
    return event


def normalize(raw_message, source_ip, iso_now):
    if not isinstance(raw_message, str) or not raw_message.strip() or len(raw_message) > 65507:
        return None
    for parser in (parse_gns3_event, parse_windows_event, parse_linux_event):
        event = parser(raw_message, source_ip, iso_now)
        if event is not None:
            return event
    return None
