from __future__ import annotations

import asyncio
import base64
import json
import ssl
import uuid
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse

import websockets
import websockets.exceptions


@dataclass
class ScanConfig:
    target: str
    charger_id: str
    version: str
    username: Optional[str]
    password: Optional[str]
    timeout: float
    security_profile: Optional[int]
    enable_dos: bool
    credential_list: Optional[str]
    idtag_attempts: int = 20


class OCPPConnection:
    def __init__(
        self,
        base_url: str,
        charger_id: str,
        version: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: float = 10.0,
        ssl_context: Optional[ssl.SSLContext] = None,
    ) -> None:
        self.base_url = base_url
        self.charger_id = charger_id
        self.version = version
        self.username = username
        self.password = password
        self.timeout = timeout
        self.ssl_context = ssl_context
        self._ws: Any = None
        self._pending: dict[str, asyncio.Future] = {}
        self._receive_task: Optional[asyncio.Task] = None
        self._closed = False

    @property
    def url(self) -> str:
        return f"{self.base_url.rstrip('/')}/{self.charger_id}"

    @property
    def subprotocol(self) -> str:
        return "ocpp1.6" if self.version == "1.6" else "ocpp2.0.1"

    def _build_headers(self) -> dict[str, str]:
        if self.username is not None:
            token = base64.b64encode(
                f"{self.username}:{self.password or ''}".encode()
            ).decode()
            return {"Authorization": f"Basic {token}"}
        return {}

    async def connect(self) -> None:
        headers = self._build_headers()
        connect_kwargs: dict[str, Any] = {
            "subprotocols": [self.subprotocol],
            "open_timeout": self.timeout,
        }
        if headers:
            connect_kwargs["additional_headers"] = headers
        if self.ssl_context is not None:
            connect_kwargs["ssl"] = self.ssl_context

        self._ws = await websockets.connect(self.url, **connect_kwargs)
        self._receive_task = asyncio.create_task(self._receive_loop())

    async def _receive_loop(self) -> None:
        try:
            async for raw in self._ws:
                try:
                    data = json.loads(raw)
                    if isinstance(data, list) and data[0] in (3, 4):
                        msg_id = data[1]
                        fut = self._pending.pop(msg_id, None)
                        if fut and not fut.done():
                            fut.set_result(data)
                except (json.JSONDecodeError, IndexError, KeyError):
                    pass
        except Exception:
            for fut in self._pending.values():
                if not fut.done():
                    fut.cancel()
            self._pending.clear()

    async def send_call(self, action: str, payload: dict[str, Any]) -> list[Any]:
        if not self._ws or self._closed:
            raise RuntimeError("Not connected")
        msg_id = str(uuid.uuid4())[:8]
        message = json.dumps([2, msg_id, action, payload])
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[list[Any]] = loop.create_future()
        self._pending[msg_id] = fut
        await self._ws.send(message)
        try:
            return await asyncio.wait_for(asyncio.shield(fut), timeout=self.timeout)
        except asyncio.TimeoutError:
            self._pending.pop(msg_id, None)
            raise

    async def send_raw(self, data: str) -> None:
        if not self._ws or self._closed:
            raise RuntimeError("Not connected")
        await self._ws.send(data)

    async def recv_raw(self) -> str:
        if not self._ws or self._closed:
            raise RuntimeError("Not connected")
        return await asyncio.wait_for(self._ws.recv(), timeout=self.timeout)

    async def close(self) -> None:
        self._closed = True
        if self._receive_task and not self._receive_task.done():
            self._receive_task.cancel()
            try:
                await self._receive_task
            except (asyncio.CancelledError, Exception):
                pass
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass


class ScanSession:
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._shared: Optional[OCPPConnection] = None
        self._owned: list[OCPPConnection] = []
        self.boot_response: Optional[dict] = None

    @property
    def target(self) -> str:
        return self.config.target

    @property
    def charger_id(self) -> str:
        return self.config.charger_id

    @property
    def version(self) -> str:
        return self.config.version

    @property
    def security_profile(self) -> Optional[int]:
        return self.config.security_profile

    @property
    def timeout(self) -> float:
        return self.config.timeout

    def is_tls(self) -> bool:
        return urlparse(self.config.target).scheme in ("wss", "https")

    def get_host_port(self) -> tuple[str, int]:
        parsed = urlparse(self.config.target)
        host = parsed.hostname or "localhost"
        if parsed.port:
            port = parsed.port
        elif parsed.scheme in ("wss", "https"):
            port = 443
        else:
            port = 80
        return host, port

    def _boot_payload(self) -> dict[str, Any]:
        if self.version == "1.6":
            return {"chargePointModel": "OCPPScan", "chargePointVendor": "OCPPScan"}
        return {
            "reason": "PowerUp",
            "chargingStation": {"model": "OCPPScan", "vendorName": "OCPPScan"},
        }

    async def setup(self) -> Optional[str]:
        """Establish the shared connection and send BootNotification. Returns error string or None."""
        conn = OCPPConnection(
            base_url=self.config.target,
            charger_id=self.config.charger_id,
            version=self.config.version,
            username=self.config.username,
            password=self.config.password,
            timeout=self.config.timeout,
        )
        try:
            await conn.connect()
        except Exception as e:
            return f"Could not connect to {self.target}: {e}"

        self._shared = conn

        try:
            resp = await conn.send_call("BootNotification", self._boot_payload())
            if len(resp) > 2:
                self.boot_response = resp[2]
        except asyncio.TimeoutError:
            pass
        except Exception:
            pass

        return None

    async def get_shared_connection(self) -> OCPPConnection:
        if self._shared is None or self._shared._closed:
            await self.setup()
        assert self._shared is not None
        return self._shared

    async def new_connection(
        self,
        charger_id: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        include_auth: bool = True,
        base_url: Optional[str] = None,
        send_boot: bool = False,
    ) -> OCPPConnection:
        cfg = self.config
        effective_user = (username if username is not None else cfg.username) if include_auth else None
        effective_pass = (password if password is not None else cfg.password) if include_auth else None
        conn = OCPPConnection(
            base_url=base_url or cfg.target,
            charger_id=charger_id or cfg.charger_id,
            version=cfg.version,
            username=effective_user,
            password=effective_pass,
            timeout=cfg.timeout,
        )
        await conn.connect()
        if send_boot:
            try:
                await conn.send_call("BootNotification", self._boot_payload())
            except Exception:
                pass
        self._owned.append(conn)
        return conn

    async def close(self) -> None:
        if self._shared:
            await self._shared.close()
        for conn in self._owned:
            try:
                await conn.close()
            except Exception:
                pass
        self._owned.clear()
