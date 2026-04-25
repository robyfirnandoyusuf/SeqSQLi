"""
seqsqli/rl/state.py
===================
State encoder: maps (last_result, last_action, step, payload) -> hashable tuple.
This is the ϕ(pt, ht) function described in the paper.
"""

from typing import Tuple


def extract_features(payload: str) -> Tuple:
    """Extract binary feature vector from payload.

    Each bit captures whether a mutation family has been applied,
    representing the mutation history implicitly via payload content.
    """
    p = payload.lower()
    return (
        1 if "/**/" in p else 0,                    # inline comment
        1 if ("%55" in p or "%53" in p) else 0,     # url-encoded keywords
        1 if "%0a" in p else 0,                     # newline
        1 if "/*!" in p else 0,                     # versioned comment
        1 if ("%09" in p or "%0b" in p or "%0c" in p) else 0,  # tab/vtab/ff
        1 if ("||" in p or "&&" in p) else 0,       # operator substitution
        1 if "0x" in p else 0,                      # hex encoding
        1 if "%bf" in p else 0,                     # GBK bypass
        1 if ("select" in p and "(" in p.split("select", 1)[-1][:20]) else 0,  # paren wrap
        1 if "%a0" in p else 0,                     # non-breaking space
        1 if "%23" in p else 0,                     # hash-comment bypass
        1 if ("uniunion" in p or "selselecte" in p
              or "UNIunion" in p or "SELselect" in p) else 0,  # nested double-write
        1 if "/*&" in p else 0,                     # param pollution comment
        1 if ("distinct" in p or "DISTINCT" in p) else 0,     # distinct inject
    )


def encode_state(last_result: str, last_action: str,
                 step: int, payload: str) -> Tuple:
    """Encode current environment state for Q-table lookup.

    st = (last_result, last_action, step_bucket, *payload_features)
    Step is bucketed into [0,4] to keep state space manageable.
    """
    return (last_result, last_action, min(step // 3, 4), *extract_features(payload))
