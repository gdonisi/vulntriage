"""Shared helpers for parsing structured JSON out of LLM responses.

LLM calls in this project ask the model to respond with a JSON object only.
Small models sometimes wrap the output in code fences or add stray prose, so
we make a best-effort attempt to locate and parse the JSON before falling back
to regex field extraction.
"""

from __future__ import annotations

import json
import re


def parse_json_object(text: str) -> dict | None:
    """Best-effort parse of a JSON object from an LLM response.

    Strips Markdown code fences and tolerates leading/trailing prose. Returns
    ``None`` if no JSON object can be parsed.
    """
    cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.MULTILINE)
    try:
        obj = json.loads(cleaned)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    # Fallback: grab the first {...} block in the text.
    match = re.search(r"\{.*\}", cleaned, flags=re.DOTALL)
    if match:
        try:
            obj = json.loads(match.group(0))
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            pass
    return None


def extract_field(text: str, field: str) -> str | None:
    """Extract a single string field from an LLM JSON response.

    Tries ``parse_json_object`` first, then a regex fallback. Useful for
    modules that only need one field and want to stay tolerant of malformed
    JSON.
    """
    obj = parse_json_object(text)
    if obj is not None:
        val = obj.get(field)
        if isinstance(val, str):
            return val
    pattern = r'"' + field + r'"\s*:\s*"((?:[^"\\]|\\.)*)"'
    match = re.search(pattern, text)
    if match:
        return match.group(1).encode().decode("unicode_escape", errors="replace")
    return None
