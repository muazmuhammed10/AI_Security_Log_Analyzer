import re


def parse_log(content: str):
    events = []

    for line in content.splitlines():
        line = line.strip()

        if not line:
            continue

        ip_match = re.search(
            r"(?:\d{1,3}\.){3}\d{1,3}",
            line
        )

        ip = ip_match.group() if ip_match else None

        lower_line = line.lower()

        if "failed login" in lower_line or "failed password" in lower_line:
            event_type = "failed_login"

        elif "successful login" in lower_line or "accepted password" in lower_line:
            event_type = "successful_login"

        elif "port scan" in lower_line:
            event_type = "port_scan"

        else:
            event_type = "unknown"

        events.append({
            "raw": line,
            "ip": ip,
            "event_type": event_type
        })

    return events