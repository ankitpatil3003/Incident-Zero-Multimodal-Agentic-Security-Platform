"""
Tests for secret masking in MCP tool outputs.
"""

from backend.mcps.common.types import mask_secrets, build_evidence, _mask_value


class TestMaskValue:
    def test_long_value_keeps_ends(self):
        result = _mask_value("SuperSecret123!")
        assert result.startswith("Sup")
        assert result.endswith("23!")
        assert "***" in result
        assert "SuperSecret" not in result

    def test_short_value_fully_masked(self):
        result = _mask_value("abc")
        assert result == "***"

    def test_borderline_length(self):
        # _MASK_VISIBLE_CHARS=3, threshold = 3*2+3 = 9
        result = _mask_value("123456789")
        assert result == "***"  # exactly threshold, fully masked

        result = _mask_value("1234567890")
        assert result.startswith("123")
        assert result.endswith("890")
        assert "***" in result


class TestMaskSecrets:
    def test_password_assignment(self):
        text = 'password = "SuperSecret123!"'
        result = mask_secrets(text)
        assert "SuperSecret123!" not in result
        assert "password" in result
        assert "***" in result

    def test_api_key_assignment(self):
        text = "api_key = 'sk-1234567890abcdef'"
        result = mask_secrets(text)
        assert "1234567890abcdef" not in result
        assert "***" in result

    def test_aws_key(self):
        text = "AKIAIOSFODNN7EXAMPLE12"
        result = mask_secrets(text)
        assert "AKIAIOSFODNN7EXAMPLE12" not in result
        assert "AKIA" in result
        assert "***" in result

    def test_github_token(self):
        text = "token = ghp_ABCDEFGHIJKLMNOPqrstuvwxyz123456"
        result = mask_secrets(text)
        assert "ABCDEFGHIJKLMNOPqrstuvwxyz123456" not in result
        assert "ghp_" in result

    def test_bearer_token(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        result = mask_secrets(text)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result
        assert "Bearer" in result

    def test_stripe_key(self):
        text = "sk_live_FAKE0TEST0KEY0only"
        result = mask_secrets(text)
        assert "FAKE0TEST0KEY0only" not in result
        assert "sk_live_" in result

    def test_no_secrets_unchanged(self):
        text = "This is a normal log line with no secrets."
        assert mask_secrets(text) == text

    def test_empty_string(self):
        assert mask_secrets("") == ""

    def test_case_insensitive(self):
        text = 'PASSWORD = "MySecretValue123"'
        result = mask_secrets(text)
        assert "MySecretValue123" not in result

    def test_colon_separator(self):
        text = 'secret: "LongSecretValueHere123"'
        result = mask_secrets(text)
        assert "LongSecretValueHere123" not in result

    def test_multiple_secrets(self):
        text = '''password = "Secret1ForTesting"\napi_key = "Secret2ForTesting"'''
        result = mask_secrets(text)
        assert "Secret1ForTesting" not in result
        assert "Secret2ForTesting" not in result


class TestBuildEvidenceMasking:
    def test_snippet_masked(self):
        ev = build_evidence(
            "e1", "code",
            snippet='password = "SuperSecretPassword123"',
        )
        assert "SuperSecretPassword123" not in ev["snippet"]
        assert "***" in ev["snippet"]

    def test_note_masked(self):
        ev = build_evidence(
            "e1", "code",
            note='Found token: ghp_ABCDEFGHIJKLMNOPqrstuvwxyz123456',
        )
        assert "ABCDEFGHIJKLMNOPqrstuvwxyz123456" not in ev["note"]

    def test_clean_snippet_unchanged(self):
        ev = build_evidence(
            "e1", "code",
            snippet="result = calculate(x, y)",
        )
        assert ev["snippet"] == "result = calculate(x, y)"

    def test_file_path_not_masked(self):
        """File paths should not be masked even if they contain 'secret'."""
        ev = build_evidence(
            "e1", "code",
            file_path="/app/secrets/config.py",
            snippet="import os",
        )
        assert ev["file_path"] == "/app/secrets/config.py"
