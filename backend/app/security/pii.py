"""PII redaction applied to every piece of user text before it can reach an LLM.

Regex-based and deliberately conservative: emails, phone numbers, street
addresses, URLs (profile links identify people) and, heuristically, the
candidate's name on the first line of a resume. Names elsewhere in free text
are not detected; that would need an NER model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_URL = re.compile(r"\b(?:https?://|www\.)\S+|\b(?:linkedin\.com|github\.com|gitlab\.com)/\S+", re.I)
# Requires 9+ digits overall so years ("2019-2023") and version numbers survive.
_PHONE = re.compile(r"(?<![\w])(?:\+?\d[\d\s().-]{7,}\d)(?![\w])")
_STREET = re.compile(
    r"\b\d{1,5}\s+(?:[A-Z][a-zA-Z]*\s){1,4}"
    r"(?:Street|St|Avenue|Ave|Road|Rd|Lane|Ln|Boulevard|Blvd|Drive|Dr|Court|Ct|Way|Place|Pl|Marg|Nagar)\b\.?"
    r"(?:,?\s*(?:Apt|Suite|Unit|Flat)\s*\w+)?",
)
_POSTCODE = re.compile(r"\b(?:\d{5}(?:-\d{4})?|\d{3}\s?\d{3}|[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2})\b")
_NAME_LINE = re.compile(r"^[A-Z][a-zA-Z'’-]+(?:\s+[A-Z][a-zA-Z'’.-]*){1,3}$")


@dataclass
class RedactionResult:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def _count_digits(s: str) -> int:
    return sum(ch.isdigit() for ch in s)


def redact(text: str, *, first_line_is_name: bool = False) -> RedactionResult:
    counts: dict[str, int] = {}

    def sub(pattern: re.Pattern[str], label: str, s: str, guard=None) -> str:
        def repl(m: re.Match[str]) -> str:
            if guard and not guard(m.group(0)):
                return m.group(0)
            counts[label] = counts.get(label, 0) + 1
            return f"[{label}]"

        return pattern.sub(repl, s)

    out = text
    if first_line_is_name:
        lines = out.split("\n")
        for i, line in enumerate(lines):
            if line.strip():
                if _NAME_LINE.match(line.strip()):
                    lines[i] = "[NAME]"
                    counts["NAME"] = 1
                break
        out = "\n".join(lines)
    out = sub(_EMAIL, "EMAIL", out)
    out = sub(_URL, "URL", out)
    out = sub(_PHONE, "PHONE", out, guard=lambda s: _count_digits(s) >= 9)
    out = sub(_STREET, "ADDRESS", out)
    # Postcodes only count as PII next to an address we already removed.
    out = re.sub(
        r"(\[ADDRESS\][^\n]{0,40}?)" + _POSTCODE.pattern,
        lambda m: m.group(1) + "[POSTCODE]",
        out,
    )
    return RedactionResult(out, counts)


def contains_pii(text: str) -> bool:
    return bool(_EMAIL.search(text)) or any(
        _count_digits(m.group(0)) >= 9 for m in _PHONE.finditer(text)
    )
