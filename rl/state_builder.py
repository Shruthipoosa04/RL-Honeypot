def build_state(log):
    attack_type = 0
    if "select" in log.get("payload", "").lower():
        attack_type = 1
    if "drop" in log.get("payload", "").lower():
        attack_type = 2

    frequency = log.get("request_count", 1)
    frequency_level = 0 if frequency < 3 else 1 if frequency < 6 else 2

    privilege = 1 if log.get("is_admin_attempt") else 0

    file_risk = log.get("file_risk", 0)

    return (attack_type, frequency_level, privilege, file_risk)
