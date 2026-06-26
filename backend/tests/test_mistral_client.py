"""
Tests for the Mistral client wrapper — all API calls are mocked.
No MISTRAL_API_KEY needed.
"""

from backend.mcps.common.mistral_client import (
    _extract_content,
    _extract_first_json_object,
    _extract_ocr_text,
    _parse_json,
    _validate_schema,
)


class TestParseJson:
    def test_direct_json(self):
        result = _parse_json('{"key": "value"}')
        assert result == {"key": "value"}

    def test_fenced_code_block(self):
        text = 'Some text\n```json\n{"key": "value"}\n```\nMore text'
        result = _parse_json(text)
        assert result == {"key": "value"}

    def test_embedded_json_object(self):
        text = 'The result is {"key": "value"} as expected.'
        result = _parse_json(text)
        assert result == {"key": "value"}

    def test_returns_none_for_non_json(self):
        assert _parse_json("just plain text") is None
        assert _parse_json("") is None
        assert _parse_json(None) is None  # type: ignore[arg-type]

    def test_nested_json(self):
        text = '{"outer": {"inner": [1, 2, 3]}, "flag": true}'
        result = _parse_json(text)
        assert result["outer"]["inner"] == [1, 2, 3]
        assert result["flag"] is True


class TestExtractFirstJsonObject:
    def test_finds_first_object(self):
        text = 'prefix {"a": 1} suffix {"b": 2}'
        result = _extract_first_json_object(text)
        assert result == '{"a": 1}'

    def test_handles_nested_braces(self):
        text = '{"a": {"b": {"c": 1}}}'
        result = _extract_first_json_object(text)
        assert result == text

    def test_handles_strings_with_braces(self):
        text = '{"key": "value with {braces}"}'
        result = _extract_first_json_object(text)
        assert result == text

    def test_returns_none_when_no_object(self):
        assert _extract_first_json_object("no json here") is None


class TestExtractContent:
    def test_string_content(self):
        raw = {"choices": [{"message": {"content": "hello"}}]}
        assert _extract_content(raw) == "hello"

    def test_list_content(self):
        raw = {"choices": [{"message": {"content": [{"text": "a"}, {"text": "b"}]}}]}
        assert _extract_content(raw) == "a\nb"

    def test_missing_content(self):
        assert _extract_content({}) == ""
        assert _extract_content({"choices": []}) == ""


class TestExtractOcrText:
    def test_text_field(self):
        assert _extract_ocr_text({"text": "hello"}) == ["hello"]

    def test_pages_with_markdown(self):
        raw = {"pages": [{"markdown": "# Title"}, {"text": "body"}]}
        result = _extract_ocr_text(raw)
        assert "# Title" in result
        assert "body" in result

    def test_empty_response(self):
        assert _extract_ocr_text({}) == []
        assert _extract_ocr_text(None) == []  # type: ignore[arg-type]


class TestValidateSchema:
    def test_passes_with_required_keys(self):
        schema = {"required": ["a", "b"]}
        payload = {"a": 1, "b": 2, "c": 3}
        assert _validate_schema(payload, schema) is True

    def test_fails_with_missing_keys(self):
        schema = {"required": ["a", "b"]}
        payload = {"a": 1}
        assert _validate_schema(payload, schema) is False

    def test_empty_required(self):
        schema = {"required": []}
        assert _validate_schema({}, schema) is True
