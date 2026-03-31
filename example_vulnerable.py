"""
example_vulnerable.py — intentionally insecure code for SecureLens demo

DO NOT use this code in production. It exists purely to demonstrate
what SecureLens detects.

Run:  python -m securelens scan examples/example_vulnerable.py
"""

import os
import hashlib
import pickle
import random

# ── PY001: Hardcoded secret ──────────────────
DB_PASSWORD = "admin1234!"
API_KEY = "sk-live-abc987xyz"

# ── PY003: Shell injection risk ──────────────
def delete_file(filename: str) -> None:
    os.system("rm " + filename)  # unsafe: user input injected into shell

# ── PY002: SQL injection risk ────────────────
def get_user(cursor, username: str):
    query = "SELECT * FROM users WHERE name = '%s'" % username
    cursor.execute(query)  # unsafe string interpolation
    return cursor.fetchone()

# ── PY005: eval() misuse ─────────────────────
def calculate(expression: str) -> float:
    return eval(expression)  # arbitrary code execution

# ── PY004: Unsafe pickle ─────────────────────
def load_session(data: bytes):
    return pickle.loads(data)  # arbitrary code execution from untrusted bytes

# ── PY006: Weak hash ─────────────────────────
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()  # MD5 is broken

# ── PY007: Debug mode ────────────────────────
DEBUG = True  # should never be True in production

# ── PY009: Insecure randomness ───────────────
def generate_token() -> str:
    return str(random.randint(100000, 999999))  # not cryptographically secure

# ── PY010: SSL verification disabled ────────
import requests

def fetch_data(url: str):
    return requests.get(url, verify=False)  # MITM vulnerability

# ── PY008: Broad exception suppression ───────
def parse_config(path: str) -> dict:
    try:
        with open(path) as f:
            import json
            return json.load(f)
    except Exception:
        pass  # silently swallowing all errors
    return {}
