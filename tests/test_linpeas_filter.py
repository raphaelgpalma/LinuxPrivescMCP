"""
Regression tests for the LinPEAS ANSI SGR filter.

The original filter used literal regexes like r'\\x1b\\[1;31m' that required
'm' right after '31'. That broke on compound SGR sequences used by LinPEAS
for its highest-priority findings:

  $C = \\e[1;31;103m  (RED_ON_YELLOW, 95% PE vector)
  $Y = \\e[1;33;43m   (YELLOW_ON_YELLOW, strong vector)

These tests exist specifically to prove the fix.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from linpeas_filter import filter_linpeas, _line_priority  # noqa: E402


# LinPEAS color escape codes
G = "\x1b[1;31m"        # RED (important)
F = "\x1b[1;33m"        # YELLOW (interesting)
C = "\x1b[1;31;103m"    # RED_ON_YELLOW (95% PE)
Y = "\x1b[1;33;43m"     # YELLOW_ON_YELLOW (strong PE)
E = "\x1b[1;32m"        # GREEN (informational — should be ignored)
B = "\x1b[1;34m"        # BLUE (informational — should be ignored)
RESET = "\x1b[0m"


def test_critical_sequence_is_captured():
    """$C (1;31;103m) is the most important marker; must not be missed."""
    line = f"{C}/usr/bin/pkexec  --> CVE-2021-4034 (PwnKit){RESET}"
    assert _line_priority(line) == "CRITICAL"


def test_strong_sequence_is_captured():
    """$Y (1;33;43m) marks strong vectors."""
    line = f"{Y}sudo: NOPASSWD on /usr/bin/vim{RESET}"
    assert _line_priority(line) == "STRONG"


def test_important_red_still_works():
    line = f"{G}SUID capability: /usr/bin/cp{RESET}"
    assert _line_priority(line) == "IMPORTANT"


def test_interesting_yellow_still_works():
    line = f"{F}Writable /etc/cron.d/monitor{RESET}"
    assert _line_priority(line) == "INTEREST"


def test_informational_colors_are_ignored():
    assert _line_priority(f"{E}Kernel: 5.15.0-56-generic{RESET}") is None
    assert _line_priority(f"{B}Hostname: victim{RESET}") is None


def test_critical_beats_lower_priorities_on_same_line():
    line = f"{F}yellow{RESET} and {C}red-on-yellow{RESET} mixed"
    assert _line_priority(line) == "CRITICAL"


def test_filter_aggregates_and_ranks():
    raw = "\n".join([
        "╔══════════╗ SUID ╔══════════╗",
        f"{G}/usr/bin/cp",
        f"{C}/usr/bin/pkexec (CVE-2021-4034)",
        f"{E}not a finding — green",
        "╔══════════╗ Sudo ╔══════════╗",
        f"{Y}user ALL=(root) NOPASSWD: /bin/less",
        f"{F}readable /etc/passwd",
        "plain line with no color",
    ])
    result = filter_linpeas(raw)
    priorities = [f.priority for f in result.findings]
    assert "CRITICAL" in priorities
    assert "STRONG" in priorities
    assert "IMPORTANT" in priorities
    assert "INTEREST" in priorities
    # Green/plain/section lines are not findings
    assert len(result.findings) == 4


def test_findings_retain_section_context():
    raw = "\n".join([
        "╔══════════╗ SUID - Check ╔══════════╗",
        f"{C}/usr/bin/pkexec",
    ])
    result = filter_linpeas(raw)
    assert len(result.findings) == 1
    assert "SUID" in result.findings[0].section


def test_render_groups_by_priority():
    raw = "\n".join([f"{C}crit", f"{G}imp", f"{F}interest"])
    out = filter_linpeas(raw).render()
    # Order should be C > R > F (Y is absent here)
    assert out.index("95% PE") < out.index("important") < out.index("interesting")


def test_old_naive_regex_would_miss_these():
    """Sanity check: a naive r'\\x1b\\[1;31m' regex (the old bug) would fail here."""
    import re as _re
    naive = _re.compile(r"\x1b\[1;31m")
    critical_line = f"{C}pkexec vulnerability"
    # The OLD bug: critical line does NOT match naive regex
    assert naive.search(critical_line) is None
    # The FIX: our parser does classify it as CRITICAL
    assert _line_priority(critical_line) == "CRITICAL"


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
        except Exception:
            failed += 1
            print(f"  FAIL  {t.__name__}")
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} tests passed")
    sys.exit(1 if failed else 0)
