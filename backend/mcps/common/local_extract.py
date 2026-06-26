"""
Local-first extraction pattern used by all MCP tools.

Strategy:
  1. Run local_fn() — fast, deterministic, no API calls (regex, heuristics, parsing)
  2. If local_fn() sets needs_llm=True, run llm_fn() for deeper analysis
  3. Merge local + LLM results into a single payload

This ensures the pipeline produces useful output even when:
  - Mistral API is rate-limited (free tier: 1 req/s)
  - Network is unavailable
  - API key is not configured

The local phase always runs. The LLM phase is optional augmentation.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List

logger = logging.getLogger(__name__)


def local_first(
    local_fn: Callable[[], Dict[str, Any]],
    llm_fn: Callable[[Dict[str, Any]], Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Execute the local-first pattern.

    local_fn must return:
      {
        "artifacts": dict,
        "evidence": list,
        "signals": dict,
        "needs_llm": bool,  # whether to invoke llm_fn
      }

    llm_fn receives the local result and must return:
      {
        "artifacts": dict,
        "evidence": list,
        "signals": dict,
        "errors": list (optional),
      }

    Returns merged result with combined artifacts, evidence, signals, errors.
    """
    local_result = local_fn()

    artifacts = local_result.get("artifacts", {})
    evidence = local_result.get("evidence", [])
    signals = local_result.get("signals", {})
    errors: List[Dict[str, Any]] = []

    needs_llm = local_result.get("needs_llm", False)

    if needs_llm:
        try:
            llm_result = llm_fn(local_result)
            llm_errors = llm_result.pop("errors", []) or []
            errors.extend(llm_errors)

            # Merge: LLM artifacts override local, evidence appends, signals merge
            llm_artifacts = llm_result.get("artifacts", {})
            if llm_artifacts:
                artifacts = _merge_artifacts(artifacts, llm_artifacts)

            llm_evidence = llm_result.get("evidence", [])
            if llm_evidence:
                evidence = _merge_evidence(evidence, llm_evidence)

            llm_signals = llm_result.get("signals", {})
            if llm_signals:
                signals = _merge_signals(signals, llm_signals)

        except Exception as exc:
            logger.warning("LLM extraction failed, using local-only results: %s", exc)
            errors.append({"error": "llm_extraction_failed", "detail": str(exc)})

    result: Dict[str, Any] = {
        "artifacts": artifacts,
        "evidence": evidence,
        "signals": signals,
    }
    if errors:
        result["errors"] = errors
    return result


def _merge_artifacts(
    local: Dict[str, Any], llm: Dict[str, Any]
) -> Dict[str, Any]:
    """LLM artifacts take precedence; local keys preserved if not in LLM."""
    merged = dict(local)
    for key, value in llm.items():
        if value is None or value == "" or value == []:
            continue  # don't overwrite local with empty LLM values
        merged[key] = value
    return merged


def _merge_evidence(
    local: List[Dict[str, Any]], llm: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Append LLM evidence, deduplicating by id."""
    seen_ids = {e.get("id") for e in local if e.get("id")}
    merged = list(local)
    for item in llm:
        eid = item.get("id")
        if eid and eid in seen_ids:
            continue
        merged.append(item)
        if eid:
            seen_ids.add(eid)
    return merged


def _merge_signals(
    local: Dict[str, Any], llm: Dict[str, Any]
) -> Dict[str, Any]:
    """Merge signal dicts. Lists concatenate, bools OR, dicts shallow-merge."""
    merged = dict(local)
    for key, value in llm.items():
        if key not in merged:
            merged[key] = value
            continue

        current = merged[key]
        if isinstance(current, list) and isinstance(value, list):
            merged[key] = current + [v for v in value if v not in current]
        elif isinstance(current, bool) and isinstance(value, bool):
            merged[key] = current or value
        elif isinstance(current, dict) and isinstance(value, dict):
            merged[key] = {**current, **value}
        else:
            merged[key] = value
    return merged
