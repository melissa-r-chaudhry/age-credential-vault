#!/usr/bin/env python3
"""
audit_unwrap.py — find and fix vault entries that were accidentally stored
as a wrapped JSON object (e.g. {"value": "...", "created": ..., ...})
instead of the raw secret value.

This happens if a migration script extracts the wrong field, or passes a
whole metadata record through to `vault.sh set` instead of just the value.
It's a silent failure: `vault.sh get` round-trips correctly either way,
so nothing *looks* broken until something tries to actually use the
secret (e.g. authenticate with it) and fails.

Usage:
    python3 audit_unwrap.py --list-only          # report only, no changes
    python3 audit_unwrap.py --fix                # extract .value and re-set

Requires: vault.sh on PATH (or VAULT_SH env var), vault already unlocked.
"""
import json
import os
import subprocess
import sys

VAULT_SH = os.environ.get("VAULT_SH", "./vault.sh")


def vault(*args: str) -> str:
    result = subprocess.run(
        [VAULT_SH, *args], capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def list_keys() -> list[str]:
    return [k for k in vault("list").splitlines() if k and not k.startswith("_")]


def is_wrapped(raw: str) -> dict | None:
    """Return the parsed dict if `raw` looks like a {"value": ...} wrapper, else None."""
    if not raw.startswith("{") and not raw.startswith("["):
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if isinstance(parsed, dict) and "value" in parsed:
        return parsed
    return None


def main() -> None:
    fix = "--fix" in sys.argv
    keys = list_keys()
    wrapped_found = []

    for key in keys:
        raw = vault("get", key)
        wrapper = is_wrapped(raw)
        if wrapper is not None:
            wrapped_found.append(key)
            print(f"WRAPPED: {key}")
            if fix:
                extracted = wrapper["value"]
                # Pass the extracted value as an actual subprocess argument,
                # never interpolated into a shell/Python string — avoids a
                # real quote-collision failure mode seen during the first
                # version of this script.
                subprocess.run([VAULT_SH, "set", key, extracted], check=True)
                round_trip = vault("get", key)
                status = "OK" if round_trip == extracted else "MISMATCH — INVESTIGATE"
                print(f"  -> fixed, round-trip check: {status}")
        else:
            print(f"raw_ok:  {key}")

    print()
    print(f"{len(keys)} keys checked, {len(wrapped_found)} wrapped.")
    if wrapped_found and not fix:
        print("Re-run with --fix to extract and re-set the wrapped keys.")


if __name__ == "__main__":
    main()
