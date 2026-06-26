"""
Unified Mistral AI client wrapper with retry, JSON extraction, and schema validation.

Supports three call modes:
  - call_text(): text/chat completions (mistral-large-latest)
  - call_vision(): vision-capable models with image content
  - call_ocr(): dedicated OCR endpoint for text extraction from images

All functions return a consistent response envelope:
  {"ok": bool, "data": dict, "error": str|None, "raw": dict|None}
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 20
DEFAULT_RETRIES = 2


def call_text(
    model: str,
    messages: List[Dict[str, Any]],
    json_schema: Optional[Dict[str, Any]] = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    retries: int = DEFAULT_RETRIES,
) -> Dict[str, Any]:
    """Call Mistral text model. Returns parsed JSON from the response."""
    return _call_chat(
        model=model,
        messages=messages,
        json_schema=json_schema,
        timeout_seconds=timeout_seconds,
        retries=retries,
    )


def call_vision(
    model: str,
    messages_with_image: List[Dict[str, Any]],
    json_schema: Optional[Dict[str, Any]] = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    retries: int = DEFAULT_RETRIES,
) -> Dict[str, Any]:
    """Call Mistral vision model. Messages should include image_url content."""
    return _call_chat(
        model=model,
        messages=messages_with_image,
        json_schema=json_schema,
        timeout_seconds=timeout_seconds,
        retries=retries,
    )


def call_ocr(
    image_path: str,
    model: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    retries: int = DEFAULT_RETRIES,
) -> Dict[str, Any]:
    """Call Mistral OCR endpoint for text extraction from an image file."""
    client = _get_client()
    if client is None:
        return _error("MISTRAL_API_KEY not set")

    last_error: Optional[str] = None
    for attempt in range(retries + 1):
        try:
            with open(image_path, "rb") as f:
                image_data = base64.standard_b64encode(f.read()).decode("utf-8")

            data_url = f"data:image/png;base64,{image_data}"
            raw = client.ocr.process(
                model=model,
                document={
                    "type": "image_url",
                    "image_url": {"url": data_url},
                },
            )

            raw_dict = _to_dict(raw)
            text_blocks = _extract_ocr_text(raw_dict)
            return {
                "ok": True,
                "data": {"text_blocks": text_blocks, "raw": raw_dict},
                "error": None,
                "raw": raw_dict,
            }
        except Exception as exc:
            last_error = str(exc)
            logger.warning("Mistral OCR attempt %d failed: %s", attempt + 1, last_error)

        if attempt < retries:
            time.sleep(0.5 * (attempt + 1))

    return _error(last_error or "Unknown error")


# --- Internal helpers ---


def _call_chat(
    model: str,
    messages: List[Dict[str, Any]],
    json_schema: Optional[Dict[str, Any]],
    timeout_seconds: int,
    retries: int,
) -> Dict[str, Any]:
    client = _get_client()
    if client is None:
        return _error("MISTRAL_API_KEY not set")

    last_error: Optional[str] = None
    for attempt in range(retries + 1):
        try:
            raw = client.chat.complete(model=model, messages=messages)
            raw_dict = _to_dict(raw)
            content = _extract_content(raw_dict)
            parsed = _parse_json(content)

            if parsed is None:
                return _error("Model response is not valid JSON", raw=raw_dict)

            if json_schema and not _validate_schema(parsed, json_schema):
                return _error("Response failed schema validation", raw=raw_dict)

            return {"ok": True, "data": parsed, "error": None, "raw": raw_dict}
        except Exception as exc:
            last_error = str(exc)
            logger.warning("Mistral chat attempt %d failed: %s", attempt + 1, last_error)

        if attempt < retries:
            time.sleep(0.5 * (attempt + 1))

    return _error(last_error or "Unknown error")


def _get_client() -> Any:
    """Lazy-import and instantiate the Mistral client."""
    import os

    api_key = os.environ.get("MISTRAL_API_KEY", "").strip()
    if not api_key:
        return None

    from mistralai import Mistral

    return Mistral(api_key=api_key)


def _extract_content(raw: Dict[str, Any]) -> str:
    """Pull the text content from a chat completion response."""
    try:
        content = raw["choices"][0]["message"]["content"]
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict) and isinstance(item.get("text"), str):
                    parts.append(item["text"])
            return "\n".join(parts)
        return str(content)
    except (KeyError, IndexError, TypeError):
        return ""


def _extract_ocr_text(raw: Dict[str, Any]) -> List[str]:
    """Normalize OCR response into a flat list of text blocks."""
    if not raw:
        return []

    if isinstance(raw.get("text"), str):
        return [raw["text"]]

    blocks: List[str] = []
    for page in raw.get("pages", []) or raw.get("page_results", []) or []:
        if not isinstance(page, dict):
            continue
        if isinstance(page.get("text"), str):
            blocks.append(page["text"])
        if isinstance(page.get("markdown"), str):
            blocks.append(page["markdown"])
        for block in page.get("blocks", []):
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                blocks.append(block["text"])

    if not blocks and isinstance(raw.get("content"), str):
        blocks.append(raw["content"])

    return blocks


def _parse_json(content: str) -> Optional[Dict[str, Any]]:
    """
    Extract a JSON object from model output.
    Tries: raw parse → fenced code block → first { ... } substring.
    """
    if not content:
        return None

    text = content.strip()

    # Direct parse
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, ValueError):
        pass

    # Fenced code block
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        try:
            parsed = json.loads(fenced.group(1))
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, ValueError):
            pass

    # First JSON object substring
    candidate = _extract_first_json_object(text)
    if candidate:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, ValueError):
            pass

    return None


def _extract_first_json_object(text: str) -> Optional[str]:
    """Find the first balanced { ... } in text."""
    start = text.find("{")
    if start < 0:
        return None

    depth = 0
    in_string = False
    escape = False

    for idx in range(start, len(text)):
        ch = text[idx]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : idx + 1]

    return None


def _validate_schema(payload: Dict[str, Any], schema: Dict[str, Any]) -> bool:
    """Minimal validation: check that all required keys are present."""
    required = schema.get("required", [])
    return all(key in payload for key in required)


def _error(message: str, raw: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {"ok": False, "data": {}, "error": message, "raw": raw}


def _to_dict(value: Any) -> Dict[str, Any]:
    """Convert SDK response objects to plain dicts."""
    if isinstance(value, dict):
        return value
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "model_dump_json"):
        return json.loads(value.model_dump_json())
    if hasattr(value, "__dict__"):
        return dict(value.__dict__)
    return {"raw": value}
