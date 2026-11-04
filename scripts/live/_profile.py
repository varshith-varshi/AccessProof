"""Optional per-organization overrides for the live evidence collectors.

    AP_PROFILE_FILE=/path/profile.json  {"<module>": {"CONSTANT": value, ...}, ...}

No file = the reference lab organization (defaults unchanged). Used to collect
REAL evidence against another organization's own Guard/Gateway/RAG stack
(e.g. a fresh pilot), never to relabel existing evidence.
"""
import json
import os


def apply(module_name: str, namespace: dict) -> dict:
    path = os.environ.get("AP_PROFILE_FILE")
    if not path:
        return {}
    overrides = json.load(open(path)).get(module_name, {})
    for key, value in overrides.items():
        if key not in namespace:
            raise SystemExit(f"PROFILE_UNKNOWN_SETTING:{module_name}.{key}")
        namespace[key] = value
    return overrides
