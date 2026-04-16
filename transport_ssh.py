"""SSH transport — persistent connection via paramiko."""
from __future__ import annotations

import io
import os
import socket
import threading
import time
from typing import Optional, Tuple

import paramiko


class SSHTransport:
    """Manage a single SSH session to a target."""

    def __init__(self):
        self._client: Optional[paramiko.SSHClient] = None
        self._host: Optional[str] = None
        self._port: int = 22
        self._user: Optional[str] = None
        self._connected = False
        self._lock = threading.Lock()

    @property
    def connected(self) -> bool:
        if not self._connected or not self._client:
            return False
        transport = self._client.get_transport()
        return transport is not None and transport.is_active()

    @property
    def info(self) -> dict:
        return {
            "type": "ssh",
            "host": self._host,
            "port": self._port,
            "user": self._user,
            "connected": self.connected,
        }

    def connect(
        self,
        host: str,
        port: int = 22,
        username: str = "root",
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        key_passphrase: Optional[str] = None,
        timeout: float = 10.0,
    ) -> dict:
        with self._lock:
            if self._client:
                try:
                    self._client.close()
                except Exception:
                    pass

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            connect_kwargs: dict = {
                "hostname": host,
                "port": port,
                "username": username,
                "timeout": timeout,
                "allow_agent": False,
                "look_for_keys": False,
            }

            if key_path:
                expanded = os.path.expanduser(key_path)
                pkey = paramiko.RSAKey.from_private_key_file(
                    expanded, password=key_passphrase
                )
                connect_kwargs["pkey"] = pkey
            elif password:
                connect_kwargs["password"] = password
            else:
                connect_kwargs["look_for_keys"] = True
                connect_kwargs["allow_agent"] = True

            client.connect(**connect_kwargs)
            self._client = client
            self._host = host
            self._port = port
            self._user = username
            self._connected = True

            return {"success": True, **self.info}

    def disconnect(self) -> dict:
        with self._lock:
            if self._client:
                try:
                    self._client.close()
                except Exception:
                    pass
                self._client = None
            self._connected = False
            return {"success": True, "message": "disconnected"}

    def execute(self, command: str, timeout: float = 30.0) -> dict:
        if not self.connected:
            return {"success": False, "error": "not connected"}
        with self._lock:
            try:
                stdin, stdout, stderr = self._client.exec_command(
                    command, timeout=timeout
                )
                out = stdout.read().decode("utf-8", errors="replace")
                err = stderr.read().decode("utf-8", errors="replace")
                exit_code = stdout.channel.recv_exit_status()
                return {
                    "success": True,
                    "stdout": out,
                    "stderr": err,
                    "exit_code": exit_code,
                }
            except socket.timeout:
                return {"success": False, "error": f"command timed out ({timeout}s)"}
            except Exception as e:
                self._connected = False
                return {"success": False, "error": str(e)}

    def upload(self, local_path: str, remote_path: str) -> dict:
        if not self.connected:
            return {"success": False, "error": "not connected"}
        with self._lock:
            try:
                sftp = self._client.open_sftp()
                sftp.put(local_path, remote_path)
                sftp.chmod(remote_path, 0o755)
                sftp.close()
                return {
                    "success": True,
                    "local": local_path,
                    "remote": remote_path,
                }
            except Exception as e:
                return {"success": False, "error": str(e)}

    def download(self, remote_path: str, local_path: str) -> dict:
        if not self.connected:
            return {"success": False, "error": "not connected"}
        with self._lock:
            try:
                sftp = self._client.open_sftp()
                sftp.get(remote_path, local_path)
                sftp.close()
                return {
                    "success": True,
                    "remote": remote_path,
                    "local": local_path,
                }
            except Exception as e:
                return {"success": False, "error": str(e)}

    def upload_bytes(self, data: bytes, remote_path: str, mode: int = 0o755) -> dict:
        """Upload raw bytes to target (for tools like linpeas that we fetch locally)."""
        if not self.connected:
            return {"success": False, "error": "not connected"}
        with self._lock:
            try:
                sftp = self._client.open_sftp()
                with sftp.open(remote_path, "wb") as f:
                    f.write(data)
                sftp.chmod(remote_path, mode)
                sftp.close()
                return {"success": True, "remote": remote_path, "size": len(data)}
            except Exception as e:
                return {"success": False, "error": str(e)}
