"""Unified session manager — SSH and reverse shell behind one interface."""
from __future__ import annotations

import time
from typing import Dict, Optional

from transport_ssh import SSHTransport
from transport_revshell import RevShellTransport


class Session:
    """Wraps either transport with metadata."""

    def __init__(self, sid: str, transport):
        self.sid = sid
        self.transport = transport
        self.created_at = time.time()
        self.last_used = time.time()
        self.shell_user: Optional[str] = None
        self.hostname: Optional[str] = None

    def touch(self):
        self.last_used = time.time()

    def probe(self) -> dict:
        """Detect current user and hostname on the target."""
        r = self.transport.execute("id && hostname", timeout=5.0)
        if r.get("success"):
            lines = r["stdout"].strip().splitlines()
            if lines:
                id_line = lines[0]
                if "uid=" in id_line:
                    import re
                    m = re.search(r"uid=\d+\(([^)]+)\)", id_line)
                    if m:
                        self.shell_user = m.group(1)
                if len(lines) > 1:
                    self.hostname = lines[-1].strip()
        return {
            "user": self.shell_user,
            "hostname": self.hostname,
            "is_root": self.shell_user == "root",
        }

    @property
    def info(self) -> dict:
        return {
            "sid": self.sid,
            "transport": self.transport.info,
            "shell_user": self.shell_user,
            "hostname": self.hostname,
            "is_root": self.shell_user == "root",
            "created_at": self.created_at,
            "last_used": self.last_used,
        }


class SessionManager:
    """Manage multiple sessions across different transports."""

    def __init__(self):
        self._sessions: Dict[str, Session] = {}
        self._active_sid: Optional[str] = None
        self._counter = 0

    def _next_sid(self, prefix: str = "s") -> str:
        self._counter += 1
        return f"{prefix}{self._counter}"

    @property
    def active(self) -> Optional[Session]:
        if self._active_sid and self._active_sid in self._sessions:
            s = self._sessions[self._active_sid]
            if s.transport.connected:
                return s
            self._active_sid = None
        return None

    def connect_ssh(
        self,
        host: str,
        port: int = 22,
        username: str = "root",
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        key_passphrase: Optional[str] = None,
        timeout: float = 10.0,
    ) -> dict:
        transport = SSHTransport()
        result = transport.connect(
            host=host,
            port=port,
            username=username,
            password=password,
            key_path=key_path,
            key_passphrase=key_passphrase,
            timeout=timeout,
        )
        if not result.get("success"):
            return result

        sid = self._next_sid("ssh")
        session = Session(sid, transport)
        probe = session.probe()
        self._sessions[sid] = session
        self._active_sid = sid

        return {
            "success": True,
            "session": session.info,
            "probe": probe,
        }

    def start_revshell_listener(
        self, host: str = "0.0.0.0", port: int = 4444
    ) -> dict:
        transport = RevShellTransport()
        result = transport.start_listener(host=host, port=port)
        if not result.get("success"):
            return result

        sid = self._next_sid("rev")
        session = Session(sid, transport)
        self._sessions[sid] = session
        self._active_sid = sid

        return {
            "success": True,
            "session": session.info,
            "note": "listener started — waiting for connection. Send your reverse shell to this port.",
        }

    def check_revshell(self, sid: Optional[str] = None) -> dict:
        """Check if a reverse shell has connected."""
        target_sid = sid or self._active_sid
        if not target_sid or target_sid not in self._sessions:
            return {"success": False, "error": "no such session"}
        session = self._sessions[target_sid]
        if not isinstance(session.transport, RevShellTransport):
            return {"success": False, "error": "not a revshell session"}
        if session.transport.connected:
            probe = session.probe()
            return {"success": True, "connected": True, "probe": probe, "session": session.info}
        return {"success": True, "connected": False, "message": "still waiting for connection"}

    def execute(self, command: str, sid: Optional[str] = None, timeout: float = 30.0) -> dict:
        session = self._resolve(sid)
        if not session:
            return {"success": False, "error": "no active session"}
        session.touch()
        return session.transport.execute(command, timeout=timeout)

    def upload(self, local_path: str, remote_path: str, sid: Optional[str] = None) -> dict:
        session = self._resolve(sid)
        if not session:
            return {"success": False, "error": "no active session"}
        session.touch()
        return session.transport.upload(local_path, remote_path)

    def download(self, remote_path: str, local_path: str, sid: Optional[str] = None) -> dict:
        session = self._resolve(sid)
        if not session:
            return {"success": False, "error": "no active session"}
        session.touch()
        if hasattr(session.transport, "download"):
            return session.transport.download(remote_path, local_path)
        return {"success": False, "error": "download not supported on this transport"}

    def disconnect(self, sid: Optional[str] = None) -> dict:
        target_sid = sid or self._active_sid
        if not target_sid or target_sid not in self._sessions:
            return {"success": False, "error": "no such session"}
        session = self._sessions.pop(target_sid)
        result = session.transport.disconnect()
        if self._active_sid == target_sid:
            self._active_sid = next(iter(self._sessions), None)
        return result

    def switch(self, sid: str) -> dict:
        if sid not in self._sessions:
            return {"success": False, "error": f"unknown session: {sid}"}
        self._active_sid = sid
        s = self._sessions[sid]
        return {"success": True, "session": s.info}

    def list_sessions(self) -> dict:
        return {
            "active": self._active_sid,
            "sessions": {sid: s.info for sid, s in self._sessions.items()},
        }

    def _resolve(self, sid: Optional[str] = None) -> Optional[Session]:
        target = sid or self._active_sid
        if target and target in self._sessions:
            s = self._sessions[target]
            if s.transport.connected:
                return s
        return None
