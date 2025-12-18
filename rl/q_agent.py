import random
from collections import defaultdict
import pickle

ACTIONS = 5
Q = defaultdict(lambda: [0]*ACTIONS)

ALPHA = 0.1
GAMMA = 0.9
EPSILON = 0.2

def choose_action(state):
    if random.random() < EPSILON:
        return random.randint(0, ACTIONS-1)
    return max(range(ACTIONS), key=lambda a: Q[state][a])

def update_q(state, action, reward, next_state):
    best_next = max(Q[next_state])
    Q[state][action] += ALPHA * (reward + GAMMA * best_next - Q[state][action])

def save_model():
    with open("data/qtable.pkl", "wb") as f:
        pickle.dump(dict(Q), f)

def load_model():
    global Q
    try:
        with open("data/qtable.pkl", "rb") as f:
            Q = defaultdict(lambda: [0]*ACTIONS, pickle.load(f))
    except:
        pass
