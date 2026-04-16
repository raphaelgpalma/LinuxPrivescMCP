"""Tests covering all modules end-to-end."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import gtfobins
import kernel_cves
import recipes
from session_manager import SessionManager
from transport_ssh import SSHTransport
from transport_revshell import RevShellTransport
from server import (
    _analyze_sudo,
    _analyze_suid,
    _analyze_caps,
    _analyze_writable,
    _analyze_cron,
    _split_enum_sections,
    build_server,
)


# -------- gtfobins --------

def test_gtfobins_normalize():
    assert gtfobins.normalize("/usr/bin/vim.basic") == "vim"
    assert gtfobins.normalize("/bin/bash") == "bash"
    assert gtfobins.normalize("python3") == "python3"


def test_gtfobins_lookup_single():
    r = gtfobins.lookup("/usr/bin/vim")
    assert r["found"] is True
    assert "sudo" in r and "suid" in r


def test_gtfobins_lookup_unknown():
    r = gtfobins.lookup("not_a_real_binary_xyz")
    assert r["found"] is False


def test_gtfobins_bulk():
    r = gtfobins.bulk_lookup(["/usr/bin/vim", "/usr/bin/cat", "fakebin"])
    assert r["count"] == 2
    assert "fakebin" in r["unknown"]


# -------- kernel_cves --------

def test_kernel_parse():
    assert kernel_cves.parse_version("Linux victim 5.15.0-56-generic #62") == (5, 15, 0)
    assert kernel_cves.parse_version("6.2.0") == (6, 2, 0)


def test_kernel_matches_dirty_pipe():
    uname = "Linux x 5.15.0-24-generic"
    cves = kernel_cves.match_cves(uname)
    cve_ids = [c["cve"] for c in cves]
    assert "CVE-2022-0847" in cve_ids
    assert "CVE-2021-4034" in cve_ids


def test_kernel_no_match_for_modern():
    cves = kernel_cves.match_cves("7.0.0")
    cve_ids = [c["cve"] for c in cves]
    assert all(c["confidence"] == "verify" for c in cves)
    assert "CVE-2022-0847" not in cve_ids


# -------- recipes --------

def test_recipe_lookup():
    r = recipes.recipe("pwnkit")
    assert r["found"] is True
    assert "exploit" in r


def test_recipe_fuzzy():
    r = recipes.recipe("docker")
    assert r.get("found") or r.get("suggestions")


def test_enum_script_all():
    s = recipes.enum_script(None)
    assert "suid" in s and "sudo" in s


def test_enum_script_targeted():
    s = recipes.enum_script(["suid", "caps"])
    assert "-perm -4000" in s
    assert "getcap" in s
    assert "sudo -l" not in s


# -------- transport classes instantiate --------

def test_ssh_transport_init():
    t = SSHTransport()
    assert t.connected is False
    assert t.info["type"] == "ssh"


def test_revshell_transport_init():
    t = RevShellTransport()
    assert t.connected is False
    assert t.listening is False
    assert t.info["type"] == "revshell"


def test_ssh_execute_not_connected():
    t = SSHTransport()
    r = t.execute("id")
    assert r["success"] is False
    assert "not connected" in r["error"]


def test_revshell_execute_not_connected():
    t = RevShellTransport()
    r = t.execute("id")
    assert r["success"] is False
    assert "no shell connected" in r["error"]


# -------- session manager --------

def test_session_manager_init():
    mgr = SessionManager()
    listing = mgr.list_sessions()
    assert listing["active"] is None
    assert listing["sessions"] == {}


def test_session_manager_no_session_execute():
    mgr = SessionManager()
    r = mgr.execute("id")
    assert r["success"] is False
    assert "no active session" in r["error"]


# -------- section parser --------

def test_split_enum_sections():
    raw = (
        "=== sudo ===\n"
        "User x may run...\n"
        "(ALL) NOPASSWD: /bin/vim\n"
        "=== suid ===\n"
        "/usr/bin/vim\n"
        "/bin/sudo\n"
    )
    sections = _split_enum_sections(raw)
    assert "sudo" in sections
    assert "suid" in sections
    assert "/usr/bin/vim" in sections["suid"]
    assert "NOPASSWD" in sections["sudo"]


# -------- analyzers --------

def test_analyze_sudo():
    raw = (
        "User x may run the following commands:\n"
        "    (ALL : ALL) NOPASSWD: /usr/bin/vim\n"
        "    (root) NOPASSWD: /bin/cp, /bin/cat\n"
        "    env_keep+=\"LD_PRELOAD\"\n"
    )
    out = _analyze_sudo(raw)
    assert out["success"] is True
    assert out["hint_ld_preload"] is True
    binaries = [e["binary"] for e in out["entries"]]
    assert "/usr/bin/vim" in binaries and "/bin/cp" in binaries
    exploit_bins = [e["binary"] for e in out["exploitable"]]
    assert "vim" in exploit_bins and "cp" in exploit_bins


def test_analyze_suid():
    raw = "/usr/bin/vim\n/bin/sudo\n/tmp/weirdbin\n"
    out = _analyze_suid(raw)
    assert out["success"] is True
    exploit_bins = [e["binary"] for e in out["exploitable"]]
    assert "vim" in exploit_bins
    assert "/tmp/weirdbin" in out["unknown"]


def test_analyze_caps():
    raw = (
        "/usr/bin/python3 cap_setuid=ep\n"
        "/usr/bin/ping cap_net_raw+ep\n"
    )
    out = _analyze_caps(raw)
    assert out["success"] is True
    paths = [e["path"] for e in out["exploitable"]]
    assert "/usr/bin/python3" in paths


def test_analyze_writable():
    raw = "/etc/passwd\n/etc/cron.d/monitor\n/var/log/syslog\n"
    out = _analyze_writable(raw)
    vectors = [h["vector"] for h in out["high_value"]]
    assert "writable_passwd" in vectors
    assert any("cron" in v for v in vectors)


def test_analyze_cron():
    raw = (
        "* * * * * root /usr/local/bin/backup.sh\n"
        "*/5 * * * * root /bin/tar czf /tmp/b.tgz *\n"
    )
    out = _analyze_cron(raw)
    assert len(out["entries"]) == 2
    assert len(out["wildcard_candidates"]) == 1
    assert "/usr/local/bin/backup.sh" in out["script_paths_to_check"]


# -------- server wiring --------

def test_build_server():
    mcp = build_server()
    assert mcp is not None


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
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
