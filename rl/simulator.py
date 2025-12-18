import random

def fake_attacker():
    return {
        "payload": random.choice(["SELECT", "DROP", "normal"]),
        "request_count": random.randint(1,10),
        "is_admin_attempt": random.choice([True, False]),
        "file_risk": random.randint(0,3),
        "session_time": random.randint(1,20),
        "is_malicious": random.choice([True, False])
    }
