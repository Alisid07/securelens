"""
SecureLens — Test suite

Run with:  pytest tests/ -v
"""

import pytest
from securelens.scanner import Scanner, Severity, MockLLMClient


# ─────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────

@pytest.fixture
def scanner():
    return Scanner(llm_client=MockLLMClient())


# ─────────────────────────────────────────────
# Detection tests
# ─────────────────────────────────────────────

class TestHardcodedSecret:
    def test_detects_password(self, scanner):
        code = 'password = "supersecret123"'
        result = scanner.scan_code(code, use_llm=False)
        assert any(v.rule_id == "PY001" for v in result.vulnerabilities)

    def test_detects_api_key(self, scanner):
        code = 'api_key = "sk-abc1234567890"'
        result = scanner.scan_code(code, use_llm=False)
        assert any(v.rule_id == "PY001" for v in result.vulnerabilities)

    def test_ignores_short_values(self, scanner):
        code = 'token = "ok"'   # too short to match threshold
        result = scanner.scan_code(code, use_llm=False)
        assert not any(v.rule_id == "PY001" for v in result.vulnerabilities)


class TestSQLInjection:
    def test_detects_format_string(self, scanner):
        code = 'cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)'
        result = scanner.scan_code(code, use_llm=False)
        assert any(v.rule_id == "PY002" for v in result.vulnerabilities)

    def test_detects_fstring(self, scanner):
        code = f'cursor.execute(f"SELECT * FROM t WHERE name = {{name}}")'
        result = scanner.scan_code(code, use_llm=False)
        assert any(v.rule_id == "PY002" for v in result.vulnerabilities)


class TestOsSystem:
    def test_detects_os_system(self, scanner):
        code = 'import os\nos.system("rm -rf " + user_input)'
        result = scanner.scan_code(code, use_llm=False)
        assert any(v.rule_id == "PY003" for v in result.vulnerabilities)


class TestEval:
    def test_detects_eval(self, scanner):
        code = "result = eval(user_expression)"
        result = scanner.scan_code(code, use_llm=False)
        assert any(v.rule_id == "PY005" for v in result.vulnerabilities)


class TestInsecureHash:
    def test_detects_md5(self, scanner):
        code = "h = hashlib.md5(data).hexdigest()"
        result = scanner.scan_code(code, use_llm=False)
        assert any(v.rule_id == "PY006" for v in result.vulnerabilities)

    def test_detects_sha1(self, scanner):
        code = "h = hashlib.sha1(data).hexdigest()"
        result = scanner.scan_code(code, use_llm=False)
        assert any(v.rule_id == "PY006" for v in result.vulnerabilities)

    def test_allows_sha256(self, scanner):
        code = "h = hashlib.sha256(data).hexdigest()"
        result = scanner.scan_code(code, use_llm=False)
        assert not any(v.rule_id == "PY006" for v in result.vulnerabilities)


class TestSSLVerification:
    def test_detects_verify_false(self, scanner):
        code = 'requests.get(url, verify=False)'
        result = scanner.scan_code(code, use_llm=False)
        assert any(v.rule_id == "PY010" for v in result.vulnerabilities)


# ─────────────────────────────────────────────
# Risk scoring
# ─────────────────────────────────────────────

class TestRiskScoring:
    def test_clean_code_scores_zero(self, scanner):
        code = "def add(a, b):\n    return a + b\n"
        result = scanner.scan_code(code, use_llm=False)
        assert result.risk_score == 0
        assert result.passed is True

    def test_critical_finding_fails(self, scanner):
        code = 'password = "hardcoded_secret_123"'
        result = scanner.scan_code(code, use_llm=False)
        assert result.passed is False
        assert result.risk_score >= 10

    def test_severity_ordering(self, scanner):
        code = (
            'password = "hardcoded_secret_123"\n'  # CRITICAL
            'result = eval(user_input)\n'            # HIGH
            'h = hashlib.md5(data)\n'               # MEDIUM
        )
        result = scanner.scan_code(code, use_llm=False)
        severities = [v.severity for v in result.vulnerabilities]
        # Should be sorted most severe first
        scores = [v.severity for v in result.vulnerabilities]
        from securelens.scanner import SEVERITY_SCORE
        score_values = [SEVERITY_SCORE[s] for s in scores]
        assert score_values == sorted(score_values, reverse=True)


# ─────────────────────────────────────────────
# LLM stub
# ─────────────────────────────────────────────

class TestMockLLM:
    def test_mock_returns_string(self, scanner):
        code = 'password = "secret123"'
        result = scanner.scan_code(code, use_llm=True)
        assert isinstance(result.llm_summary, str)
        assert len(result.llm_summary) > 0

    def test_mock_deterministic(self):
        llm = MockLLMClient()
        code = 'api_key = "abc12345"'
        r1 = llm.review(code, [])
        r2 = llm.review(code, [])
        assert r1 == r2


# ─────────────────────────────────────────────
# Report generation
# ─────────────────────────────────────────────

class TestReporter:
    def test_json_report_valid(self, scanner):
        import json
        code = 'os.system("cmd")'
        result = scanner.scan_code(code, use_llm=False)
        from securelens.reporter import generate_json
        report = json.loads(generate_json([result]))
        assert "results" in report
        assert report["summary"]["total_vulnerabilities"] >= 1

    def test_markdown_report_contains_heading(self, scanner):
        code = 'eval(x)'
        result = scanner.scan_code(code, use_llm=False)
        from securelens.reporter import generate_markdown
        md = generate_markdown([result])
        assert "# 🔍 SecureLens" in md

    def test_sarif_report_schema(self, scanner):
        import json
        code = 'eval(x)'
        result = scanner.scan_code(code, use_llm=False)
        from securelens.reporter import generate_sarif
        sarif = json.loads(generate_sarif([result]))
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
