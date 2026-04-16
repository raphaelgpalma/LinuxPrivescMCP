"""
LinPEAS ANSI SGR filter — parses compound sequences correctly.

The classic bug: a regex like r'\\x1b\\[1;31m' requires 'm' literal right
after '31'. LinPEAS's top-priority markers use compound parameters:

  $G  = \\e[1;31m       RED          — important
  $F  = \\e[1;33m       YELLOW       — interesting
  $C  = \\e[1;31;103m   RED_ON_YEL   — 95% PE vector (most valuable)
  $Y  = \\e[1;33;43m    YEL_ON_YEL   — strong PE vector

A naive `1;31m` regex misses $C entirely (after 31 comes ';103m', not 'm').
This filter parses every SGR sequence and checks the parameter set.

Priority ranking (highest to lowest):
  CRITICAL : 103 in params (bright-yellow background → $C)
  STRONG   :  43 in params (yellow background → $Y)
  IMPORTANT: 31 or 91 in params (red foreground → $G / bright red)
  INTEREST : 33 or 93 in params (yellow foreground → $F / bright yellow)
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

SGR_RE = re.compile(r"\x1b\[([0-9;]*)m")
STRIP_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
SECTION_RE = re.compile(r"^[╔═╚║╗╝]+")

CRITICAL_PARAMS = {103}
STRONG_PARAMS = {43}
IMPORTANT_PARAMS = {31, 91}
INTEREST_PARAMS = {33, 93}

PRIORITY_ORDER = ("CRITICAL", "STRONG", "IMPORTANT", "INTEREST")
PRIORITY_LABEL = {
    "CRITICAL": "[C] 95% PE",
    "STRONG": "[Y] strong PE",
    "IMPORTANT": "[R] important",
    "INTEREST": "[F] interesting",
}


@dataclass
class Finding:
    priority: str
    section: str
    text: str

    def formatted(self) -> str:
        tag = PRIORITY_LABEL[self.priority]
        return f"{tag}  {self.text}"


@dataclass
class FilterResult:
    findings: List[Finding] = field(default_factory=list)
    total_lines: int = 0

    def by_priority(self) -> dict[str, List[Finding]]:
        groups: dict[str, List[Finding]] = {p: [] for p in PRIORITY_ORDER}
        for f in self.findings:
            groups[f.priority].append(f)
        return groups

    def render(self, max_per_priority: int = 0) -> str:
        if not self.findings:
            return "No high-priority findings detected."
        out: List[str] = []
        groups = self.by_priority()
        counts = {p: len(v) for p, v in groups.items()}
        header = (
            f"=== LinPEAS findings ({len(self.findings)}/{self.total_lines} lines) "
            f"| C={counts['CRITICAL']} Y={counts['STRONG']} "
            f"R={counts['IMPORTANT']} F={counts['INTEREST']} ==="
        )
        out.append(header)
        current_section: Optional[str] = None
        for priority in PRIORITY_ORDER:
            items = groups[priority]
            if not items:
                continue
            out.append(f"\n--- {PRIORITY_LABEL[priority]} ({len(items)}) ---")
            shown = items if max_per_priority <= 0 else items[:max_per_priority]
            for f in shown:
                if f.section != current_section:
                    out.append(f"[{f.section or 'misc'}]")
                    current_section = f.section
                out.append(f"  {f.text}")
            if max_per_priority > 0 and len(items) > max_per_priority:
                out.append(f"  ... +{len(items) - max_per_priority} more")
        return "\n".join(out)


def _classify(params: Iterable[int]) -> Optional[str]:
    """Return the HIGHEST priority bucket these SGR params hit, if any."""
    pset = set(params)
    if pset & CRITICAL_PARAMS:
        return "CRITICAL"
    if pset & STRONG_PARAMS:
        return "STRONG"
    if pset & IMPORTANT_PARAMS:
        return "IMPORTANT"
    if pset & INTEREST_PARAMS:
        return "INTEREST"
    return None


def _line_priority(line: str) -> Optional[str]:
    """Pick highest-priority SGR in the line; None if none found."""
    best: Optional[str] = None
    for m in SGR_RE.finditer(line):
        raw = m.group(1)
        if not raw:
            continue
        try:
            params = [int(p) for p in raw.split(";") if p != ""]
        except ValueError:
            continue
        hit = _classify(params)
        if hit is None:
            continue
        if best is None or PRIORITY_ORDER.index(hit) < PRIORITY_ORDER.index(best):
            best = hit
    return best


def _clean(line: str) -> str:
    return STRIP_ANSI.sub("", line).rstrip()


def _is_section_header(stripped: str) -> bool:
    # LinPEAS section headers use box-drawing chars
    return bool(SECTION_RE.match(stripped)) or stripped.startswith("═")


def filter_linpeas(raw: str) -> FilterResult:
    """Parse LinPEAS raw output and return ranked findings."""
    result = FilterResult()
    current_section = ""
    for line in raw.splitlines():
        result.total_lines += 1
        stripped = _clean(line).strip()
        if not stripped:
            continue
        if _is_section_header(stripped):
            # Clean header text from box-drawing noise
            hdr = re.sub(r"[╔═╚║╗╝]+", " ", stripped).strip()
            if hdr:
                current_section = hdr
            continue
        priority = _line_priority(line)
        if priority is None:
            continue
        # Dedupe trailing whitespace; keep inner text, no color codes
        text = _clean(line).strip()
        if not text:
            continue
        result.findings.append(
            Finding(priority=priority, section=current_section, text=text)
        )
    return result


def filter_file(path: str) -> FilterResult:
    with open(path, "r", errors="replace") as fh:
        return filter_linpeas(fh.read())


def summarize(path_or_text: str, max_per_priority: int = 0) -> str:
    """Convenience: accept a file path OR raw text, return rendered summary."""
    if os.path.isfile(path_or_text):
        res = filter_file(path_or_text)
    else:
        res = filter_linpeas(path_or_text)
    return res.render(max_per_priority=max_per_priority)
