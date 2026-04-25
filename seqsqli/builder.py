"""
seqsqli/builder.py
==================
Factory functions for TargetProfile + legacy compatibility shims
for baseline.py which was written against the old monolithic agent.py.
"""

from typing import Optional

from seqsqli.config import DEFAULT_BASE_URL
from seqsqli.core.profile import TargetProfile, LESS_PRESETS
from seqsqli.core.http import send_request
from seqsqli.core.response import classify_response


# ---------------------------------------------------------------------------
# Public factories
# ---------------------------------------------------------------------------

def build_target_from_preset(less_id: float,
                              base_url: str = DEFAULT_BASE_URL) -> TargetProfile:
    """Create TargetProfile from a sqli-labs Less preset."""
    preset = LESS_PRESETS[less_id]
    return TargetProfile(
        url=f"{base_url}/{preset['path']}",
        param=preset["param"],
        method=preset["method"],
        quote=preset["quote"],
        closure=preset["closure"],
        filter_type=preset["filter"],
        extra_params=preset.get("extra_params", {}),
    )


def build_target_from_args(url: str, param: str,
                            method: str = "GET",
                            extra_params: str = None) -> TargetProfile:
    """Create TargetProfile from CLI arguments."""
    t = TargetProfile(url=url, param=param, method=method.upper())
    if extra_params:
        for pair in extra_params.split("&"):
            k, v = pair.split("=", 1)
            t.extra_params[k] = v
    return t


# ---------------------------------------------------------------------------
# Legacy compat — these names are imported by the old baseline.py
# ---------------------------------------------------------------------------

LESS_TARGETS = {
    lid: {
        "path":        preset["path"],
        "param":       preset["param"],
        "method":      preset["method"],
        "quote":       preset["quote"],
        "filter":      preset["filter"],
        "extra_params": preset.get("extra_params", {}),
    }
    for lid, preset in LESS_PRESETS.items()
}


def send_payload(target_dict: dict, payload: str):
    """Legacy compat wrapper: dict-based target → send_request."""
    t = TargetProfile(
        url=f"{DEFAULT_BASE_URL}/{target_dict['path']}",
        param=target_dict["param"],
        method=target_dict["method"],
        extra_params=target_dict.get("extra_params", {}),
    )
    return send_request(t, payload)


def analyze_response(resp_text: str, status_code: int) -> str:
    """Legacy compat alias for classify_response."""
    return classify_response(resp_text, status_code)
