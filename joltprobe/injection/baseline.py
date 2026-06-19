from __future__ import annotations

import asyncio
import statistics
import time

from joltprobe.connection import OCPPConnection

_BASELINE_COUNT = 3
_BASELINE_INTERVAL = 0.05
_FALLBACK_MS = 1000.0


async def establish_baseline(conn: OCPPConnection, count: int = _BASELINE_COUNT) -> float:
    """Send Heartbeat messages and return median round-trip time in milliseconds."""
    times: list[float] = []
    for _ in range(count):
        start = time.monotonic()
        try:
            await conn.send_call("Heartbeat", {})
            times.append((time.monotonic() - start) * 1000.0)
        except Exception:
            pass
        await asyncio.sleep(_BASELINE_INTERVAL)
    return statistics.median(times) if times else _FALLBACK_MS


async def establish_connection_baseline(
    session: "ScanSession",  # type: ignore[name-defined]
    count: int = _BASELINE_COUNT,
) -> float:
    """Time connection attempts with the configured charger_id, return median in ms."""
    from joltprobe.connection import ScanSession  # noqa: F401 — runtime import

    times: list[float] = []
    for _ in range(count):
        start = time.monotonic()
        try:
            conn = await session.new_connection(
                charger_id=session.charger_id,
                send_boot=False,
            )
            times.append((time.monotonic() - start) * 1000.0)
            await conn.close()
        except Exception:
            times.append((time.monotonic() - start) * 1000.0)
        await asyncio.sleep(_BASELINE_INTERVAL)
    return statistics.median(times) if times else _FALLBACK_MS
