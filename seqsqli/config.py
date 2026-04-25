"""
seqsqli/config.py
=================
All constants, hyperparameters, and runtime globals.
Change values here — nowhere else needs to be touched.
"""

# ---------------------------------------------------------------------------
# Target / HTTP
# ---------------------------------------------------------------------------
DEFAULT_BASE_URL = "https://lab.0xffsec.co"
TIMEOUT          = 8
REQUEST_DELAY    = 0.05
MAX_RETRIES      = 2

# ---------------------------------------------------------------------------
# Q-Learning hyperparameters
# ---------------------------------------------------------------------------
ALPHA         = 0.15    # learning rate
GAMMA         = 0.9     # discount factor
EPSILON       = 0.4     # initial exploration rate
EPSILON_DECAY = 0.993
EPSILON_MIN   = 0.05

# ---------------------------------------------------------------------------
# Episode limits
# ---------------------------------------------------------------------------
MAX_STEPS    = 15
MAX_EPISODES = 300
STEP_PENALTY = 0.08

# ---------------------------------------------------------------------------
# Persistence paths
# ---------------------------------------------------------------------------
QTABLE_PATH  = "q_table.json"
RESULTS_PATH = "results.json"
