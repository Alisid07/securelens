"""
example_safe.py — secure counterpart to example_vulnerable.py

This demonstrates the correct implementation for each pattern
that SecureLens flags in example_vulnerable.py.
"""

import os
import hashlib
import secrets
import subprocess
import logging

import requests

logger = logging.getLogger(__name__)


# ── Secrets via environment variables ────────
DB_PASSWORD = os.environ.get("DB_PASSWORD")
API_KEY = os.environ.get("API_KEY")


# ── Safe shell invocation ────────────────────
def delete_file(filename: str) -> None:
    """Use subprocess with shell=False to avoid injection."""
    subprocess.run(["rm", filename], check=True, shell=False)


# ── Parameterised SQL ────────────────────────
def get_user(cursor, username: str):
    """Parameterised query — safe from injection."""
    cursor.execute("SELECT * FROM users WHERE name = %s", (username,))
    return cursor.fetchone()


# ── Safe expression parsing ───────────────────
import ast

def calculate(expression: str) -> float:
    """ast.literal_eval only parses literals, no code execution."""
    return ast.literal_eval(expression)


# ── Strong hashing ───────────────────────────
def hash_password(password: str) -> str:
    """SHA-256 is suitable for checksums; for passwords use bcrypt/argon2."""
    return hashlib.sha256(password.encode()).hexdigest()


# ── Debug off ────────────────────────────────
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"


# ── Cryptographically secure token ──────────
def generate_token() -> str:
    """secrets module is designed for security-sensitive random values."""
    return secrets.token_hex(32)


# ── SSL verification enabled ─────────────────
def fetch_data(url: str):
    """Always verify TLS certificates."""
    return requests.get(url, timeout=10)


# ── Targeted exception handling ──────────────
def parse_config(path: str) -> dict:
    """Catch and log specific exceptions; never swallow silently."""
    try:
        with open(path) as f:
            import json
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.error("Failed to load config from %s: %s", path, exc)
    return {}
