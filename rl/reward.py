def calculate_reward(log):
    reward = 0

    # Engagement
    reward += log.get("session_time", 1) * 0.1

    # Attack depth
    reward += log.get("request_count", 1)

    # Detection
    if log.get("is_malicious"):
        reward += 20

    # Early exit penalty
    if log.get("request_count", 1) == 1:
        reward -= 5

    return reward
