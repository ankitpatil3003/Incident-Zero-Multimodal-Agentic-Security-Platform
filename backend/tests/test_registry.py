"""
Tests for the MCP tool registry and shared types.
"""

import json
import pytest
from pathlib import Path

from backend.app.registry import ToolRegistry, _type_matches
from backend.mcps.common.types import build_tool_result, build_evidence, build_error_result
from backend.mcps.common.local_extract import local_first


# --- ToolRegistry tests ---


class TestToolRegistry:
    def _make_registry(self) -> ToolRegistry:
        return ToolRegistry()

    def _dummy_handler(self, **kwargs):
        return build_tool_result(
            tool_name="TestTool",
            artifacts={"result": "ok"},
            evidence=[],
            signals={},
        )

    def test_register_and_get(self):
        reg = self._make_registry()
        spec = reg.register(
            name="TestTool",
            description="A test tool",
            input_schema={"required": ["path"], "properties": {"path": {"type": "string"}}},
            output_signals=["test_signal"],
            handler=self._dummy_handler,
        )
        assert reg.get("TestTool") is spec
        assert reg.get("NonExistent") is None

    def test_duplicate_name_raises(self):
        reg = self._make_registry()
        reg.register(
            name="Dup",
            description="first",
            input_schema={"required": [], "properties": {}},
            output_signals=[],
            handler=self._dummy_handler,
        )
        with pytest.raises(ValueError, match="already registered"):
            reg.register(
                name="Dup",
                description="second",
                input_schema={"required": [], "properties": {}},
                output_signals=[],
                handler=self._dummy_handler,
            )

    def test_list_tools(self):
        reg = self._make_registry()
        reg.register("A", "tool A", {"required": [], "properties": {}}, [], self._dummy_handler)
        reg.register("B", "tool B", {"required": [], "properties": {}}, [], self._dummy_handler)
        names = [t.name for t in reg.list_tools()]
        assert "A" in names
        assert "B" in names

    def test_invoke_validates_input(self):
        reg = self._make_registry()
        reg.register(
            name="Strict",
            description="needs path",
            input_schema={"required": ["path"], "properties": {"path": {"type": "string"}}},
            output_signals=[],
            handler=self._dummy_handler,
        )
        with pytest.raises(ValueError, match="Missing required input"):
            reg.invoke("Strict", {})

    def test_invoke_calls_handler(self):
        reg = self._make_registry()
        reg.register(
            name="TestTool",
            description="test",
            input_schema={"required": [], "properties": {}},
            output_signals=[],
            handler=self._dummy_handler,
        )
        result = reg.invoke("TestTool", {})
        assert result["tool_name"] == "TestTool"
        assert result["artifacts"]["result"] == "ok"

    def test_invoke_unknown_tool_raises(self):
        reg = self._make_registry()
        with pytest.raises(ValueError, match="Unknown tool"):
            reg.invoke("Ghost", {})

    def test_to_function_call_schema(self):
        reg = self._make_registry()
        reg.register(
            name="CodeScan",
            description="Scan code",
            input_schema={
                "required": ["repo_path"],
                "properties": {"repo_path": {"type": "string"}},
            },
            output_signals=["finding_type"],
            handler=self._dummy_handler,
        )
        schemas = reg.to_function_call_schema()
        assert len(schemas) == 1
        assert schemas[0]["type"] == "function"
        assert schemas[0]["function"]["name"] == "CodeScan"

    def test_input_type_validation(self):
        reg = self._make_registry()
        spec = reg.register(
            name="Typed",
            description="typed inputs",
            input_schema={
                "required": ["count"],
                "properties": {"count": {"type": "integer"}},
            },
            output_signals=[],
            handler=self._dummy_handler,
        )
        errors = spec.validate_input({"count": "not_a_number"})
        assert any("expected type" in e for e in errors)

        errors = spec.validate_input({"count": 5})
        assert errors == []


class TestTypeMatches:
    def test_string(self):
        assert _type_matches("hello", "string") is True
        assert _type_matches(123, "string") is False

    def test_integer(self):
        assert _type_matches(42, "integer") is True
        assert _type_matches(3.14, "integer") is False

    def test_number(self):
        assert _type_matches(42, "number") is True
        assert _type_matches(3.14, "number") is True

    def test_unknown_type_passes(self):
        assert _type_matches("anything", "custom_type") is True


# --- Shared types tests ---


class TestBuildToolResult:
    def test_basic_result(self):
        result = build_tool_result("TestTool", {"k": "v"}, [], {})
        assert result["tool_name"] == "TestTool"
        assert result["artifacts"] == {"k": "v"}
        assert result["evidence"] == []
        assert result["signals"] == {}
        assert result["errors"] is None

    def test_with_errors(self):
        result = build_tool_result("T", {}, [], {}, errors=[{"error": "boom"}])
        assert result["errors"] == [{"error": "boom"}]


class TestBuildEvidence:
    def test_valid_kind(self):
        e = build_evidence("e1", "log", snippet="error line")
        assert e["kind"] == "log"

    def test_invalid_kind_defaults_to_other(self):
        e = build_evidence("e1", "invalid_kind")
        assert e["kind"] == "other"


class TestBuildErrorResult:
    def test_error_only(self):
        result = build_error_result("T", "file_not_found")
        assert result["errors"] == [{"error": "file_not_found"}]
        assert result["artifacts"] == {}

    def test_error_with_detail(self):
        result = build_error_result("T", "fail", detail="bad path")
        assert result["errors"] == [{"error": "fail", "detail": "bad path"}]


# --- Local-first pattern tests ---


class TestLocalFirst:
    def test_local_only_when_no_llm_needed(self):
        def local_fn():
            return {
                "artifacts": {"parsed": True},
                "evidence": [{"id": "e1", "kind": "code"}],
                "signals": {"found": True},
                "needs_llm": False,
            }

        def llm_fn(local_result):
            raise AssertionError("Should not be called")

        result = local_first(local_fn, llm_fn)
        assert result["artifacts"]["parsed"] is True
        assert len(result["evidence"]) == 1

    def test_llm_augments_local(self):
        def local_fn():
            return {
                "artifacts": {"local_key": "local_val"},
                "evidence": [{"id": "e1", "kind": "code"}],
                "signals": {"local_signal": True},
                "needs_llm": True,
            }

        def llm_fn(local_result):
            return {
                "artifacts": {"llm_key": "llm_val"},
                "evidence": [{"id": "e2", "kind": "log"}],
                "signals": {"llm_signal": True},
            }

        result = local_first(local_fn, llm_fn)
        assert result["artifacts"]["local_key"] == "local_val"
        assert result["artifacts"]["llm_key"] == "llm_val"
        assert len(result["evidence"]) == 2
        assert result["signals"]["local_signal"] is True
        assert result["signals"]["llm_signal"] is True

    def test_llm_failure_falls_back_to_local(self):
        def local_fn():
            return {
                "artifacts": {"ok": True},
                "evidence": [],
                "signals": {},
                "needs_llm": True,
            }

        def llm_fn(local_result):
            raise RuntimeError("API down")

        result = local_first(local_fn, llm_fn)
        assert result["artifacts"]["ok"] is True
        assert any("llm_extraction_failed" in str(e) for e in result.get("errors", []))

    def test_evidence_dedup_by_id(self):
        def local_fn():
            return {
                "artifacts": {},
                "evidence": [{"id": "e1", "kind": "code"}],
                "signals": {},
                "needs_llm": True,
            }

        def llm_fn(local_result):
            return {
                "artifacts": {},
                "evidence": [{"id": "e1", "kind": "code"}, {"id": "e2", "kind": "log"}],
                "signals": {},
            }

        result = local_first(local_fn, llm_fn)
        ids = [e["id"] for e in result["evidence"]]
        assert ids == ["e1", "e2"]  # e1 not duplicated


# --- Schema file validation ---


class TestSchemaFile:
    def test_tool_registry_schema_is_valid_json(self):
        schema_path = Path(__file__).resolve().parent.parent.parent / "schemas" / "tool_registry.json"
        with open(schema_path) as f:
            schema = json.load(f)
        assert "tools" in schema["properties"]
        assert "ToolResult" in schema["definitions"]
        assert "Evidence" in schema["definitions"]
