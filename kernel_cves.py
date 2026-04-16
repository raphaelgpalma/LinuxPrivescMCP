"""
Kernel → privesc CVE mapping.

Short list of the CVEs that actually matter on HTB/real engagements.
Each entry ties version ranges to public exploits + quick triage hints.

Version comparison uses tuple semantics over (major, minor, patch).
"Affected" is expressed as (min_inclusive, max_inclusive).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class KernelCVE:
    cve: str
    name: str
    affected: List[Tuple[Tuple[int, int, int], Tuple[int, int, int]]]
    distros: str
    exploit: str
    notes: str


# Affected ranges are inclusive. Use (0,0,0) for unbounded low.
_CVES: List[KernelCVE] = [
    KernelCVE(
        cve="CVE-2021-4034",
        name="PwnKit (pkexec)",
        affected=[((0, 0, 0), (99, 99, 99))],  # userland, all kernels
        distros="Any distro with vulnerable polkit (pkexec < 0.120)",
        exploit="github.com/berdav/CVE-2021-4034 (C) — compile & run",
        notes=(
            "Not kernel-bound — check pkexec version: `dpkg -l policykit-1` or "
            "`rpm -q polkit`. If pkexec is SUID and polkit < patched → instant root."
        ),
    ),
    KernelCVE(
        cve="CVE-2022-0847",
        name="DirtyPipe",
        affected=[((5, 8, 0), (5, 16, 11)), ((5, 15, 0), (5, 15, 25)), ((5, 10, 0), (5, 10, 102))],
        distros="Ubuntu 20.04/21.10, Debian bullseye, Fedora 35, CentOS Stream",
        exploit="github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits",
        notes="Overwrites read-only files. Trivial to trigger; works on most 5.8-5.16.x.",
    ),
    KernelCVE(
        cve="CVE-2016-5195",
        name="DirtyCow",
        affected=[((2, 6, 22), (4, 8, 3))],
        distros="Older Ubuntu/CentOS/RHEL",
        exploit="github.com/FireFart/dirtycow (C) or `dirtycow` SearchSploit",
        notes="Classic. Still shows up on legacy HTB boxes.",
    ),
    KernelCVE(
        cve="CVE-2017-16995",
        name="eBPF sign-extension",
        affected=[((4, 4, 0), (4, 14, 8))],
        distros="Ubuntu 16.04/17.10",
        exploit="exploit-db.com/exploits/44298",
        notes="Check `uname -r`; boxes in 4.4.0-116 range are prime candidates.",
    ),
    KernelCVE(
        cve="CVE-2017-1000112",
        name="UDP fragmentation offload",
        affected=[((4, 8, 0), (4, 13, 0))],
        distros="Ubuntu 16.04 with HWE kernel 4.8-4.13",
        exploit="exploit-db.com/exploits/43418",
        notes="",
    ),
    KernelCVE(
        cve="CVE-2021-3493",
        name="OverlayFS (Ubuntu)",
        affected=[((5, 4, 0), (5, 11, 0))],
        distros="Ubuntu 20.04/20.10/21.04 — distro-specific patch missing",
        exploit="exploit-db.com/exploits/50233",
        notes="Only affects Ubuntu's OverlayFS patches. Check `lsb_release -a`.",
    ),
    KernelCVE(
        cve="CVE-2022-2588",
        name="cls_route UAF",
        affected=[((3, 0, 0), (5, 19, 0))],
        distros="Wide",
        exploit="github.com/Markakd/CVE-2022-2588",
        notes="Requires CAP_NET_ADMIN or unpriv user ns.",
    ),
    KernelCVE(
        cve="CVE-2022-32250",
        name="Netfilter UAF",
        affected=[((5, 8, 0), (5, 18, 1))],
        distros="",
        exploit="github.com/theori-io/CVE-2022-32250-exploit",
        notes="Requires user namespaces (`unprivileged_userns_clone=1`).",
    ),
    KernelCVE(
        cve="CVE-2023-32233",
        name="Netfilter nf_tables",
        affected=[((5, 1, 0), (6, 3, 1))],
        distros="Ubuntu 22.04/23.04, Debian 12",
        exploit="github.com/Liuk3r/CVE-2023-32233",
        notes="Works on 22.04 GA kernels. Needs unpriv user ns.",
    ),
    KernelCVE(
        cve="CVE-2023-0386",
        name="OverlayFS / SUID copy-up",
        affected=[((5, 11, 0), (6, 2, 0))],
        distros="Ubuntu 22.04, Fedora, Arch",
        exploit="github.com/xkaneiki/CVE-2023-0386",
        notes="Fast & reliable on vulnerable 22.04 kernels.",
    ),
    KernelCVE(
        cve="CVE-2024-1086",
        name="nf_tables double-free",
        affected=[((5, 14, 0), (6, 6, 15))],
        distros="Ubuntu 22.04/23.10, Debian 12",
        exploit="github.com/Notselwyn/CVE-2024-1086",
        notes="Ring-0 → root, public PoC, works on modern boxes.",
    ),
    KernelCVE(
        cve="CVE-2024-0582",
        name="io_uring UAF",
        affected=[((6, 4, 0), (6, 7, 0))],
        distros="Ubuntu 23.10 mainline",
        exploit="github.com/ysanatomic/io_uring_LPE-CVE-2023-0582",
        notes="",
    ),
    KernelCVE(
        cve="CVE-2022-2586",
        name="nf_tables cross-table UAF",
        affected=[((5, 12, 0), (5, 18, 18))],
        distros="",
        exploit="github.com/0range1337/CVE-2022-2586",
        notes="",
    ),
    KernelCVE(
        cve="CVE-2023-3269",
        name="StackRot",
        affected=[((6, 1, 0), (6, 4, 0))],
        distros="Debian 12, Fedora 38",
        exploit="github.com/lrh2000/StackRot",
        notes="",
    ),
    KernelCVE(
        cve="CVE-2021-22555",
        name="Netfilter heap OOB",
        affected=[((2, 6, 19), (5, 12, 0))],
        distros="Very wide — kCTF winning exploit",
        exploit="github.com/google/security-research/.../CVE-2021-22555",
        notes="Requires user namespaces.",
    ),
    KernelCVE(
        cve="CVE-2016-4557",
        name="eBPF ref-count",
        affected=[((4, 4, 0), (4, 5, 5))],
        distros="Ubuntu 16.04 (older kernels)",
        exploit="exploit-db.com/exploits/40759",
        notes="",
    ),
    KernelCVE(
        cve="CVE-2021-3156",
        name="Sudo Baron Samedit",
        affected=[((0, 0, 0), (99, 99, 99))],  # userland
        distros="Sudo < 1.9.5p2 — Ubuntu 20.04 vanilla, Debian 10, CentOS 7/8",
        exploit="github.com/blasty/CVE-2021-3156 (or SearchSploit 'baron samedit')",
        notes=(
            "Not kernel — sudo version. `sudo --version` or `sudoedit -s /`. "
            "If `sudoedit: invalid option` → segfault = vulnerable."
        ),
    ),
    KernelCVE(
        cve="CVE-2019-14287",
        name="Sudo runas UID bypass",
        affected=[((0, 0, 0), (99, 99, 99))],
        distros="Sudo < 1.8.28",
        exploit="`sudo -u#-1 /bin/bash` (if sudoers has `ALL, !root` or similar)",
        notes="Only if sudoers allows running as any user EXCEPT root.",
    ),
    KernelCVE(
        cve="CVE-2022-2602",
        name="io_uring UAF",
        affected=[((5, 4, 0), (5, 19, 16))],
        distros="",
        exploit="github.com/migraine-sudo/CVE-2022-2602",
        notes="",
    ),
]

_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def parse_version(s: str) -> Optional[Tuple[int, int, int]]:
    """
    Extract a (maj, min, patch) tuple from arbitrary uname -a / --version text.
    Returns None if no version looking thing is found.
    """
    if not s:
        return None
    m = _VERSION_RE.search(s)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def _in_range(v: Tuple[int, int, int], lo: Tuple[int, int, int], hi: Tuple[int, int, int]) -> bool:
    return lo <= v <= hi


def match_cves(uname_or_version: str) -> List[dict]:
    """
    Given raw `uname -a` output, a version like "5.15.0-56-generic", or just
    "5.15.0", return the CVEs that affect this kernel.

    Userland CVEs (PwnKit, Samedit) are always flagged as "verify manually"
    because they depend on the package version, not the kernel.
    """
    version = parse_version(uname_or_version)
    matches: List[dict] = []
    for cve in _CVES:
        # Userland (full range)
        if cve.affected == [((0, 0, 0), (99, 99, 99))]:
            matches.append({
                "cve": cve.cve,
                "name": cve.name,
                "kind": "userland",
                "distros": cve.distros,
                "exploit": cve.exploit,
                "notes": cve.notes,
                "confidence": "verify",
            })
            continue
        if version is None:
            continue
        if any(_in_range(version, lo, hi) for lo, hi in cve.affected):
            matches.append({
                "cve": cve.cve,
                "name": cve.name,
                "kind": "kernel",
                "distros": cve.distros,
                "exploit": cve.exploit,
                "notes": cve.notes,
                "confidence": "in-range",
            })
    return matches


def render(uname_or_version: str) -> str:
    cves = match_cves(uname_or_version)
    version = parse_version(uname_or_version)
    ver_str = ".".join(str(p) for p in version) if version else "unknown"
    if not cves:
        return f"No candidate CVEs for kernel {ver_str}."
    lines = [f"Candidate privesc CVEs for kernel {ver_str}:"]
    for c in cves:
        tag = "KERN" if c["kind"] == "kernel" else "USER"
        lines.append(f"  [{tag}] {c['cve']}  {c['name']}")
        lines.append(f"         exploit: {c['exploit']}")
        if c["distros"]:
            lines.append(f"         distros: {c['distros']}")
        if c["notes"]:
            lines.append(f"         notes:   {c['notes']}")
    return "\n".join(lines)
