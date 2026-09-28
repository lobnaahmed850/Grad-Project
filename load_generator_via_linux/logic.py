import socket
import re
import json
import hashlib
from datetime import datetime, timezone
import queue
import threading

UDP_IP = "0.0.0.0" # listen on all interfaces
UDP_PORT = 514 # listen on standard syslog port
PARSER_VERSION = "1.4.0-multithreaded"   # track which logic version produced event

NORMALIZED_FILE = "load_generator_via_linux/normalized_events.jsonl" # successfully parsed 
RAW_LOGS_FILE = "load_generator_via_linux/raw_logs.json" # original messages
QUARANTINE_FILE = "load_generator_via_linux/quarantine.jsonl" # unparseable messages (didn't match any known regex patterns)


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

SECURITY_SEVERITY_OVERRIDE = {
    ("cisco", "SEC-IPACCESSLOGP"):  ("high", 2),
    ("cisco", "SEC-IPACCESSLOGDP"): ("high", 2),
    ("windows", "4732"):            ("high", 2),  # member added to local group
    ("windows", "4728"):            ("high", 2),  # member added to global group
    ("windows", "4720"):            ("medium", 3),  # new account created
}

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

IGNORED_EVENT_KEYS = {
    "SYS-NOBLOCK",   # Cisco IOU hypervisor artifact - not a real network/security event
}

IP_TO_HOSTNAME = {
    "192.168.100.44": "IOU1",   # IOU1's Ethernet0/2 
    "192.168.177.1":  "IOU1",   # IOU1's Ethernet0/1
    "10.0.0.2":       "IOU1",   # IOU1's Ethernet0/0
    "10.0.0.1":       "R1",     # R1's FastEthernet1/0
    "192.168.141.1":  "R1",     # R1's FastEthernet0/0
}

def map_severity(sev_input):
    mapping = {
        0: ("emergency", 0), 1: ("alert", 1), 2: ("critical", 2),
        3: ("error", 3), 4: ("warning", 4), 5: ("notice", 5),
        6: ("info", 6), 7: ("debug", 7)
    }
    
    try:
        sev_int = int(sev_input)
        return mapping.get(sev_int, ("info", 6))
    except (ValueError, TypeError):
        pass
        
    if str(sev_input).lower() in ["error", "crit", "failure"]: return ("error", 3)
    elif str(sev_input).lower() in ["warn", "warning"]: return ("warning", 4)
    return ("info", 6)

def sanitize_message(msg):
    if not msg:
        return msg
    return msg.replace("\t", " ").replace('"', "").strip()

def normalize_cisco_timestamp(raw_ts):
    try:
        current_year = datetime.now().year
        dt = datetime.strptime(f"{current_year} {raw_ts}", "%Y %b %d %H:%M:%S.%f")
        dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except Exception:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def parse_gns3_event(raw_message, source_ip, iso_now):
    match = CISCO_PATTERN.match(raw_message)
    if not match: return None  

    fields = match.groupdict()
    event_key = f"{fields['facility']}-{fields['mnemonic']}"
    if event_key in IGNORED_EVENT_KEYS:
        return "IGNORED"
        
    event_info = CISCO_EVENT_MAP.get(event_key, {"category": ["network"], "type": ["info"]})
    raw_hash = hashlib.sha256(raw_message.encode()).hexdigest()[:16]
    event_time = normalize_cisco_timestamp(fields["timestamp"])

    override = SECURITY_SEVERITY_OVERRIDE.get(("cisco", event_key))
    if override:
        log_lvl, sev_num = override
    elif event_key == "HSRP-STATECHANGE" and "-> Active" in fields["message"]:
        log_lvl, sev_num = ("warning", 3)    
    else:
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
            "name": IP_TO_HOSTNAME.get(source_ip) or fields.get("hostname") or "unknown-cisco-device", 
            "ip": source_ip
        },
        "source": {"ip": source_ip},
        "message": sanitize_message(fields["message"]),        
        "parser": {"version": PARSER_VERSION, "name": "cisco_ios"}
    }

    if "IPACCESSLOG" in fields["mnemonic"]:
        acl_pattern = re.compile(r"permitted\s+(?P<proto>\S+)\s+(?P<src_ip>\S+).*?->\s+(?P<dst_ip>\S+)")
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

    override = SECURITY_SEVERITY_OVERRIDE.get(("windows", event_id))
    if override: log_lvl, sev_num = override
    elif event_id == "4625": log_lvl, sev_num = map_severity("warning")
    elif fields.get("pri"): log_lvl, sev_num = map_severity(int(fields["pri"]) % 8)
    else: log_lvl, sev_num = map_severity("info")
    
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
        "host": {"name": fields["computer"], "ip": source_ip, "os": {"family": "windows"}},
        "source": {"ip": source_ip},
        "message": sanitize_message(fields["message"]),
        "parser": {"version": PARSER_VERSION, "name": "windows_powershell"}
    }

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

    if fields.get("user") and fields["user"] != "N/A":
        normalized_event["user"] = {"name": fields["user"]}

    return normalized_event

def parse_linux_event(raw_message, source_ip, iso_now):
    linux_pattern = (
        r"<(?P<pri>\d+)>"
        r"(?P<timestamp>[A-Za-z]{3}\s+\d+\s+[\d:]+)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?:(?P<tag>\S+):\s+)?(?P<process>[a-zA-Z0-9_\-\/\.]+)(?:\[(?P<pid>\d+)\])?:\s*"
        r"(?P<msg>.*)"
    )
    match = re.search(linux_pattern, raw_message)
    if not match: return None

    fields = match.groupdict()
    process_name = fields["process"]
    msg_body = fields["msg"]
    hostname = fields["hostname"]

    if "sudo" in msg_body and process_name != "sudo":
        process_name = "sudo"

    event_info = LINUX_EVENT_MAP.get(process_name, {"category": ["system"], "type": ["info"]})
    raw_hash = hashlib.sha256(raw_message.encode()).hexdigest()[:16]

    try:
        current_year = datetime.now().year
        dt = datetime.strptime(f"{current_year} {fields['timestamp']}", "%Y %b %d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
        iso_ts = dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except Exception:
        iso_ts = iso_now

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
        "message": sanitize_message(msg_body),
        "parser": {"version": PARSER_VERSION, "name": "linux_rsyslog"}
    }

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

        if "shadow" in command.lower() or "passwd" in command.lower():
            ecs_event["log"]["level"] = "high"
            ecs_event["event"]["severity"] = 2

    return ecs_event

def parse_cisco_debug(raw_message, source_ip, iso_now):
    match = CISCO_DEBUG_PATTERN.search(raw_message)
    if not match: return None
        
    fields = match.groupdict()
    raw_hash = hashlib.sha256(raw_message.encode()).hexdigest()[:16]
    event_time = normalize_cisco_timestamp(fields["timestamp"])
    
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
            "id": raw_hash, "kind": "event", "category": category,
            "type": event_type, "action": action, "severity": sev_num,
            "created": event_time, "ingested": iso_now, "dataset": "gns3.debug",
            "module": "python-udp-collector", "original": raw_message
        },
        "host": {"name": IP_TO_HOSTNAME.get(source_ip, "unknown-cisco-device"), "ip": source_ip},
        "source": {"ip": source_ip},
        "message": sanitize_message(fields["message"]),
        "parser": {"version": PARSER_VERSION, "name": "cisco_debug"}
    }
    
    ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', fields["message"])
    if ip_match:
        normalized_event["source"]["ip"] = ip_match.group(1)
        
    return normalized_event

# ---------------------------------------------------------
# THREAD 1: Parse logs asynchronously (Removes CPU block)
# ---------------------------------------------------------
def parser_worker(in_q, raw_q, norm_q, quar_q):
    while True:
        raw_message, source_ip, iso_now = in_q.get()
        
        raw_hash = hashlib.sha256(raw_message.encode()).hexdigest()[:16]
        raw_q.put({"event_id": raw_hash, "received_at": iso_now, "source_ip": source_ip, "raw_payload": raw_message})

        normalized = parse_gns3_event(raw_message, source_ip, iso_now)
        if normalized == "IGNORED":
            in_q.task_done()
            continue

        if not normalized: normalized = parse_cisco_debug(raw_message, source_ip, iso_now)
        if not normalized: normalized = parse_windows_event(raw_message, source_ip, iso_now)
        if not normalized: normalized = parse_linux_event(raw_message, source_ip, iso_now)

        if normalized:
            norm_q.put(normalized)
        else:
            quar_q.put({
                "raw": raw_message,
                "source_ip": source_ip,
                "reason": "did not match any known regex patterns (Cisco, Windows, or Linux)",
                "received_at": iso_now
            })
        
        in_q.task_done()

# ---------------------------------------------------------
# THREAD 2: Write to disk in batches (Removes I/O block)
# ---------------------------------------------------------
def disk_writer_worker(filepath, q):
    while True:
        batch = []
        while not q.empty() and len(batch) < 500:
            batch.append(q.get())
            q.task_done()
            
        if batch:
            with open(filepath, "a", encoding="utf-8") as f:
                f.writelines([json.dumps(item) + "\n" if isinstance(item, dict) else item + "\n" for item in batch])
        else:
            threading.Event().wait(0.01)

# ---------------------------------------------------------
# MAIN THREAD: Network ingestion ONLY
# ---------------------------------------------------------
if __name__ == "__main__":
    ingest_queue = queue.Queue(maxsize=100000)
    raw_queue = queue.Queue()
    normalized_queue = queue.Queue()
    quarantine_queue = queue.Queue()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024 * 16)
    sock.bind((UDP_IP, UDP_PORT))

    print(f"Listening on UDP {UDP_PORT} with 16MB OS buffer (True Multithreaded Mode)...")

    threading.Thread(target=parser_worker, args=(ingest_queue, raw_queue, normalized_queue, quarantine_queue), daemon=True).start()
    threading.Thread(target=disk_writer_worker, args=(RAW_LOGS_FILE, raw_queue), daemon=True).start()
    threading.Thread(target=disk_writer_worker, args=(NORMALIZED_FILE, normalized_queue), daemon=True).start()
    threading.Thread(target=disk_writer_worker, args=(QUARANTINE_FILE, quarantine_queue), daemon=True).start()

    while True:
        data, addr = sock.recvfrom(65535)
        ingest_queue.put((data.decode(errors="replace").strip(), addr[0], datetime.now(timezone.utc).isoformat()))