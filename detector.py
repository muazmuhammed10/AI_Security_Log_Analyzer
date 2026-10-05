from collections import Counter


def detect_threats(events):
    threats = []

    # --------------------------------------------------
    # Count events by IP
    # --------------------------------------------------

    failed_logins = Counter(
        event["ip"]
        for event in events
        if event["event_type"] == "failed_login"
        and event["ip"]
    )

    successful_logins = Counter(
        event["ip"]
        for event in events
        if event["event_type"] == "successful_login"
        and event["ip"]
    )

    port_scans = Counter(
        event["ip"]
        for event in events
        if event["event_type"] == "port_scan"
        and event["ip"]
    )

    # --------------------------------------------------
    # 1. Brute Force Detection
    # --------------------------------------------------

    for ip, count in failed_logins.items():

        if count >= 5:

            threats.append({
                "type": "Brute Force Attack",
                "ip": ip,
                "attempts": count,
                "severity": "High",
                "description": (
                    "Multiple failed login attempts from "
                    "the same IP indicate possible credential "
                    "brute-force activity."
                )
            })

        elif count >= 3:

            threats.append({
                "type": "Suspicious Login Activity",
                "ip": ip,
                "attempts": count,
                "severity": "Medium",
                "description": (
                    "Several failed login attempts were "
                    "detected from the same IP address."
                )
            })

    # --------------------------------------------------
    # 2. Successful Login After Failed Attempts
    # --------------------------------------------------

    for ip in failed_logins:

        if ip in successful_logins and failed_logins[ip] >= 3:

            threats.append({
                "type": "Possible Account Compromise",
                "ip": ip,
                "attempts": failed_logins[ip],
                "severity": "High",
                "description": (
                    "A successful login occurred after "
                    "multiple failed login attempts from "
                    "the same IP."
                )
            })

    # --------------------------------------------------
    # 3. Port Scan Detection
    # --------------------------------------------------

    for ip, count in port_scans.items():

        threats.append({
            "type": "Port Scan",
            "ip": ip,
            "attempts": count,
            "severity": "High",
            "description": (
                "Possible network reconnaissance or "
                "port scanning activity was detected."
            )
        })

    # --------------------------------------------------
    # 4. Multiple Attack Types From Same IP
    # --------------------------------------------------

    ip_attack_types = {}

    for event in events:

        ip = event.get("ip")
        event_type = event.get("event_type")

        if not ip:
            continue

        if event_type in {
            "failed_login",
            "port_scan"
        }:

            if ip not in ip_attack_types:
                ip_attack_types[ip] = set()

            ip_attack_types[ip].add(event_type)

    for ip, attack_types in ip_attack_types.items():

        if len(attack_types) >= 2:

            threats.append({
                "type": "Multiple Attack Activities",
                "ip": ip,
                "attempts": len(attack_types),
                "severity": "High",
                "description": (
                    "Multiple suspicious activity types "
                    "were detected from the same IP address."
                )
            })

    return threats