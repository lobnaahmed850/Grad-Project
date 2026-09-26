import socket
import re
import json
import hashlib
from datetime import datetime, timezone


UDP_IP = "0.0.0.0" # listen on all interfaces
UDP_PORT = 514 # listen on standard syslog port
PARSER_VERSION = "1.3.0"   # track which logic version produced event

NORMALIZED_FILE = "normalized_events.jsonl" # successfully parsed 
RAW_LOGS_FILE = "raw_logs.json" # original messages
QUARANTINE_FILE = "quarantine.jsonl" # unparseable messages (didn't match any known regex patterns)


CISCO_PATTERN = re.compile(
    r"<(?P<pri>\d+)>(?P<seq>\d+): (?:(?P<hostname>\S+): )?\*?(?P<timestamp>[A-Za-z]+ \d+ \d+:\d+:\d+(?:\.\d+)?): "
    r"%(?P<facility>[A-Z0-9_]+)-(?P<severity>\d+)-(?P<mnemonic>[A-Z0-9_]+): (?P<message>.*)"
)

CISCO_DEBUG_PATTERN = re.compile(
    r"<(?P<pri>\d+)>(?P<seq>\d+):\s*(?:(?P<hostname>\S+):\s+)?\*?(?P<timestamp>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?):\s*(?P<message>RIP:.*)"
)

WINDOWS_PATTERN = re.compile(
    r"(?:<(?P<pri>\d+)>)?"
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"computer=(?P<computer>\S+)\s+"
    r"event_id=(?P<event_id>\d+)\s+"
    r"(?:user=(?P<user>\S+)\s+)?"
    r"message=['\"]?(?P<message>.*?)['\"]?$"
)

LOGIN_FAILED_DETAILS = re.compile(
    r"\[user: (?P<user>[^\]]+)\] \[Source: (?P<source_ip>[^\]]+)\]"
)


CISCO_EVENT_MAP = {
    "LINEPROTO-UPDOWN":            {"category": ["network"], "type": ["info"]},
    "SEC_LOGIN-LOGIN_FAILED":      {"category": ["authentication"], "type": ["denied"]},
    "SEC-IPACCESSLOGP":        {"category": ["intrusion_detection"], "type": ["alert"]},
    "SEC-IPACCESSLOGDP":       {"category": ["intrusion_detection"], "type": ["alert"]},
    "HSRP-STATECHANGE":            {"category": ["network", "routing"], "type": ["change"]}
}

WINDOWS_EVENT_MAP = {
    "4624": {"category": ["authentication"], "type": ["info"]},
    "4625": {"category": ["authentication"], "type": ["denied"]},
    "4634": {"category": ["authentication"], "type": ["info"]},
    "4720": {"category": ["iam"], "type": ["creation"]},
    "4722": {"category": ["iam"], "type": ["change"]},
    "4724": {"category": ["iam"], "type": ["change"]},
    "4728": {"category": ["iam"], "type": ["group", "change"]},
    "4732": {"category": ["iam"], "type": ["group", "change"]},
    "4738": {"category": ["iam"], "type": ["change"]}
}

LINUX_EVENT_MAP = {
    "sudo": {"category": ["process", "privilege"], "type": ["info"]},
    "sshd": {"category": ["authentication"], "type": ["info"]},
    "su":   {"category": ["authentication", "user"], "type": ["change"]}
}


def map_severity(sev_input):
    """
    Maps syslog numeric severity (0-7) or text tags to ECS log.level and event.severity.
    """
    mapping = {
        0: ("emergency", 0),
        1: ("alert", 1),
        2: ("critical", 2),
        3: ("error", 3),
        4: ("warning", 4),
        5: ("notice", 5),
        6: ("info", 6),
        7: ("debug", 7)
    }
    
    # If it's a Cisco/Syslog integer string or int
    try:
        sev_int = int(sev_input)
        return mapping.get(sev_int, ("info", 6))
    except (ValueError, TypeError):
        pass
        
    # Default fallback for Windows/Linux text-based levels
    if str(sev_input).lower() in ["error", "crit", "failure"]:
        return ("error", 3)
    elif str(sev_input).lower() in ["warn", "warning"]:
        return ("warning", 4)
    
    return ("info", 6) # Default info level


def normalize_cisco_timestamp(raw_ts):
    try:
        current_year = datetime.now().year
        dt = datetime.strptime(f"{current_year} {raw_ts}", "%Y %b %d %H:%M:%S.%f")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except Exception: # if parsing fails, fallback to current UTC
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def parse_gns3_event(raw_message, source_ip, iso_now):
    match = CISCO_PATTERN.match(raw_message)
    if not match: return None  

    fields = match.groupdict()
    event_key = f"{fields['facility']}-{fields['mnemonic']}"
    event_info = CISCO_EVENT_MAP.get(event_key, {"category": ["network"], "type": ["info"]})
    raw_hash = hashlib.sha256(raw_message.encode()).hexdigest()[:16]
    event_time = normalize_cisco_timestamp(fields["timestamp"])

    log_lvl, sev_num = map_severity(fields["severity"])

    normalized_event = {
        "@timestamp": event_time,
        "ecs": {"version": "9.3.0"},
        "log": {"level": log_lvl},
        "event": {
            "id": raw_hash,
            "kind": "event",
            "category": event_info["category"],
            "type": event_info["type"],
            "sequence": int(fields["seq"]),
            "severity": sev_num,
            "created": event_time,
            "ingested": iso_now,
            "dataset": "gns3.syslog",
            "module": "python-udp-collector",
            "original": raw_message
        },
        "host": {
            "name": fields.get("hostname") or "unknown-cisco-device", 
            "ip": source_ip
        },
        "source": {"ip": source_ip},
        "message": fields["message"],         
        "parser": {"version": PARSER_VERSION, "name": "cisco_ios"}
    }

    # Enrich access-log events with ACL connection details.
    if "IPACCESSLOG" in fields["mnemonic"]:
        acl_pattern = re.compile(
            r"permitted\s+(?P<proto>\S+)\s+(?P<src_ip>\S+).*?->\s+(?P<dst_ip>\S+)"
        )
        acl_match = acl_pattern.search(fields["message"])
        if acl_match:
            normalized_event["source"]["ip"] = acl_match.group("src_ip")
            normalized_event["destination"] = {"ip": acl_match.group("dst_ip")}
            normalized_event["network"] = {"transport": acl_match.group("proto")}

    if event_key == "SEC_LOGIN-LOGIN_FAILED":
        details = LOGIN_FAILED_DETAILS.search(fields["message"])
        if details:
            normalized_event["user"] = {"name": details.group("user")}
            normalized_event["source"]["ip"] = details.group("source_ip")

    if "ignored v2 packet" in fields["message"] and "invalid authentication" in fields["message"]:
        normalized_event["event"]["category"] = ["network", "intrusion_detection"]
        normalized_event["event"]["type"] = ["denied"]
        normalized_event["event"]["action"] = "routing-auth-failure"

    return normalized_event

def parse_windows_event(raw_message, source_ip, iso_now):
    nxlog_regex = r'<(?P<pri>\d+)>.*?\s+(?P<computer>\S+)\s+MSWinEventLog.*?(?P<timestamp>[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d+\s+[\d:]+\s+\d{4})\s+(?P<event_id>\d{4})\s+Microsoft-Windows-Security-Auditing.*?(?:Audit)\s+\S+\s+.*?\s+(?P<message>.*)'
    match = re.search(nxlog_regex, raw_message)
    if not match:
        match = WINDOWS_PATTERN.search(raw_message)
        if not match:
            return None
    
    fields = match.groupdict()
    if not fields.get("user") or fields.get("user") == "N/A":
        user_match = re.search(r'(?:Target Account|New Account).*?Account Name:\s+([A-Za-z0-9_-]+)', raw_message, re.DOTALL)
        if user_match and user_match.group(1) != "-":
            fields["user"] = user_match.group(1)

    raw_hash = hashlib.sha256(raw_message.encode()).hexdigest()[:16]
    
    event_id = fields["event_id"]
    event_info = WINDOWS_EVENT_MAP.get(event_id, {"category": ["authentication"], "type": ["info"]})

    if event_id == "4625":
        log_lvl, sev_num = map_severity("warning")
    elif fields.get("pri"):
        log_lvl, sev_num = map_severity(int(fields["pri"]) % 8)
    else:
        log_lvl, sev_num = map_severity("info")
    
    # ISO-8601 UTC timestamp conversion
    try:
        dt = datetime.strptime(fields["timestamp"], "%Y-%m-%d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        iso_ts = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except Exception:
        iso_ts = iso_now

    normalized_event = {
        "@timestamp": iso_ts,
        "ecs": {"version": "9.3.0"},
        "log": {"level": log_lvl},
        "event": {
            "id": raw_hash,
            "kind": "event",
            "category": event_info["category"],
            "type": event_info["type"],
            "code": event_id,
            "severity": sev_num,
            "created": iso_ts,
            "ingested": iso_now,
            "dataset": "windows.security",
            "module": "python-udp-collector",
            "original": raw_message
        },
        "host": {
            "name": fields["computer"],
            "ip": source_ip,
            "os": {"family": "windows"}
        },
        "source": {"ip": source_ip},
        "message": fields["message"],
        "parser": {"version": PARSER_VERSION, "name": "windows_powershell"}
    }

    # Contextual actions based on Event ID
    if event_id == "4625":
        normalized_event["event"]["action"] = "logon-failed"
        normalized_event["event"]["outcome"] = "failure"
    elif event_id == "4624":
        normalized_event["event"]["action"] = "logon-success"
        normalized_event["event"]["outcome"] = "success"
    elif event_id == "4720":
        normalized_event["event"]["action"] = "user-account-created"
    elif event_id == "4722":
        normalized_event["event"]["action"] = "user-account-enabled"
    elif event_id in ["4732", "4728"]:
        normalized_event["event"]["action"] = "member-added-to-local-group"
        group_match = re.search(r'Group Name:\s+([A-Za-z0-9_-]+)', raw_message)
        if group_match:
            normalized_event["group"] = {"name": group_match.group(1)}

    # User entity mapping
    if fields.get("user") and fields["user"] != "N/A":
        normalized_event["user"] = {"name": fields["user"]}

    return normalized_event

def parse_linux_event(raw_message, source_ip, iso_now):
    # Regex designed to capture PRI, timestamp, hostname, optional logger tags, process name, PID, and the message body
    linux_pattern = (
        r"<(?P<pri>\d+)>"
        r"(?P<timestamp>[A-Za-z]{3}\s+\d+\s+[\d:]+)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?:(?P<tag>\S+):\s+)?(?P<process>[a-zA-Z0-9_\-\/\.]+)(?:\[(?P<pid>\d+)\])?:\s*"
        r"(?P<msg>.*)"
    )
    
    match = re.search(linux_pattern, raw_message)
    if not match:
        return None

    fields = match.groupdict()
    process_name = fields["process"]
    msg_body = fields["msg"]
    hostname = fields["hostname"]

    # Handle cases where tools like logger inject an extra username tag preceding sudo
    if "sudo" in msg_body and process_name != "sudo":
        process_name = "sudo"

    # Resolve event taxonomy from predefined mapping or fallback to generic system/info
    event_info = LINUX_EVENT_MAP.get(process_name, {"category": ["system"], "type": ["info"]})
    raw_hash = hashlib.sha256(raw_message.encode()).hexdigest()[:16]

    # Normalize timestamp to UTC ISO 8601
    try:
        current_year = datetime.now().year
        dt = datetime.strptime(f"{current_year} {fields['timestamp']}", "%Y %b %d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        iso_ts = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except Exception:
        iso_ts = iso_now

    # Calculate severity from syslog PRI value (PRI % 8 yields severity level)
    log_lvl, sev_num = map_severity(int(fields["pri"]) % 8 if fields.get("pri") else "info")

    ecs_event = {
        "@timestamp": iso_ts,
        "ecs": {"version": "9.3.0"},
        "log": {"level": log_lvl},
        "event": {
            "id": raw_hash,
            "kind": "event",
            "category": event_info["category"],
            "type": event_info["type"],
            "severity": sev_num,
            "created": iso_ts,
            "ingested": iso_now,
            "dataset": f"linux.{process_name.lower()}",
            "module": "rsyslog",
            "original": raw_message
        },
        "host": {"name": hostname, "ip": source_ip, "os": {"family": "linux"}},
        "source": {"ip": source_ip},
        "process": {"name": process_name},
        "message": msg_body,
        "parser": {"version": PARSER_VERSION, "name": "linux_rsyslog"}
    }

    # Extract fine-grained sudo execution details if present
    if "sudo" in process_name or "COMMAND=" in msg_body:
        sudo_pattern = r"(\S+)\s+:.*?USER=(\S+)\s+;\s+COMMAND=(.+)$"
        sudo_match = re.search(sudo_pattern, msg_body)
        if sudo_match:
            user, target_user, command = sudo_match.groups()
            ecs_event["user"] = {"name": user, "target": {"name": target_user}}
            ecs_event["process"]["command_line"] = command.strip()
            ecs_event["event"]["category"] = ["process", "privilege"]
            ecs_event["event"]["action"] = "privilege_elevation"
            ecs_event["event"]["outcome"] = "success"

    return ecs_event

def parse_cisco_debug(raw_message, source_ip, iso_now):
    match = CISCO_DEBUG_PATTERN.search(raw_message)
    if not match:
        return None
        
    fields = match.groupdict()
    raw_hash = hashlib.sha256(raw_message.encode()).hexdigest()[:16]
    event_time = normalize_cisco_timestamp(fields["timestamp"])
    
    # Differentiate between routing attacks and standard debug noise
    if "ignored v2 packet" in fields["message"] and "invalid authentication" in fields["message"]:
        category = ["network", "intrusion_detection"]
        event_type = ["denied"]
        action = "routing-auth-failure"
        log_lvl, sev_num = map_severity("warning")
    else:
        category = ["network", "routing"]
        event_type = ["info"]
        action = "routing-update"
        log_lvl, sev_num = map_severity("info")
        
    normalized_event = {
        "@timestamp": event_time,
        "ecs": {"version": "9.3.0"},
        "log": {"level": log_lvl},
        "event": {
            "id": raw_hash,
            "kind": "event",
            "category": category,
            "type": event_type,
            "action": action,
            "severity": sev_num,
            "created": event_time,
            "ingested": iso_now,
            "dataset": "gns3.debug",
            "module": "python-udp-collector",
            "original": raw_message
        },
        "host": {"name": "unknown-cisco-device", "ip": source_ip},
        "source": {"ip": source_ip},
        "message": fields["message"],
        "parser": {"version": PARSER_VERSION, "name": "cisco_debug"}
    }
    
    # Isolate the rogue attacker's IP from the message string
    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', fields["message"])
    if ip_match:
        normalized_event["source"]["ip"] = ip_match.group(1)
        
    return normalized_event

def save_event(event_dict, filepath):
    with open(filepath, "a") as f:
        f.write(json.dumps(event_dict) + "\n")


if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    print(f"Listening for Syslog messages on UDP port {UDP_PORT}...")

    while True:
        data, addr = sock.recvfrom(4096)
        raw_message = data.decode(errors="replace").strip()
        source_ip = addr[0]
        iso_now = datetime.now(timezone.utc).isoformat()

        print(f"\nReceived from {addr}: {raw_message}")

        raw_hash = hashlib.sha256(raw_message.encode()).hexdigest()[:16]

        raw_entry = {
            "event_id": raw_hash,
            "received_at": iso_now,
            "source_ip": source_ip,
            "raw_payload": raw_message
        }
        save_event(raw_entry, RAW_LOGS_FILE)

        # parsing cscade logic
        normalized = parse_gns3_event(raw_message, source_ip, iso_now)

        if not normalized:
            normalized = parse_cisco_debug(raw_message, source_ip, iso_now)
            
        if not normalized:
            normalized = parse_windows_event(raw_message, source_ip, iso_now)
            
        if not normalized:
            normalized = parse_linux_event(raw_message, source_ip, iso_now)

        if normalized:
            print(f"Normalized ({normalized['parser']['name']}) ->", json.dumps(normalized, indent=2))
            save_event(normalized, NORMALIZED_FILE)
        else:
            print("Could NOT parse this event - sent to quarantine.")
            quarantine_entry = {
                "raw": raw_message,
                "source_ip": source_ip,
                "reason": "did not match any known regex patterns (Cisco, Windows, or Linux)",
                "received_at": iso_now
            }
            save_event(quarantine_entry, QUARANTINE_FILE)