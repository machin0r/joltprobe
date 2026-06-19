import asyncio
import json
import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

HERE = Path(__file__).parent

_which = shutil.which("joltprobe")
JOLTPROBE_CMD: list[str] = [_which] if _which else [sys.executable, "-m", "joltprobe.cli"]

app = FastAPI(title="JoltProbe", docs_url=None, redoc_url=None)

def _build_checks_manifest() -> dict:
    from joltprobe.checks import CATEGORIES

    result = {}
    for category, check_classes in CATEGORIES.items():
        result[category] = [
            {
                "id": cls.id,
                "name": cls.name,
                "severity": cls.severity.value if hasattr(cls.severity, "value") else cls.severity,
                "applies_to": cls.applies_to,
                "what": cls.what,
                "fail": cls.fail,
                "pass": cls.pass_,
            }
            for cls in check_classes
        ]
    return result


CHECKS_MANIFEST: dict = _build_checks_manifest()


@app.get("/", response_class=HTMLResponse)
async def root():
    return (HERE / "index.html").read_text(encoding="utf-8")


@app.get("/checks")
async def get_checks():
    return JSONResponse(CHECKS_MANIFEST)


@app.get("/scan-result/{scan_id}")
async def get_scan_result(scan_id: str):
    if not all(c in "0123456789abcdef" for c in scan_id):
        return JSONResponse({"error": "invalid id"}, status_code=400)
    path = Path(tempfile.gettempdir()) / f"joltprobe-{scan_id}.json"
    if not path.exists():
        return JSONResponse({"error": "not found"}, status_code=404)
    try:
        return JSONResponse(json.loads(path.read_text()))
    except Exception:
        return JSONResponse({"error": "parse error"}, status_code=500)


class ScanRequest(BaseModel):
    target: str
    charger_id: str
    version: str = "1.6"
    checks: Optional[str] = None
    timeout: float = 10.0
    security_profile: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    enable_dos: bool = False
    enable_soap: bool = False
    idtag_attempts: int = 20


class RunCheckRequest(BaseModel):
    check_id: str
    target: str
    charger_id: str
    version: str = "1.6"
    timeout: float = 10.0
    security_profile: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None


def _build_scan_cmd(req: ScanRequest, result_file: Optional[str] = None) -> list[str]:
    cmd = [*JOLTPROBE_CMD, "scan", req.target, "--charger-id", req.charger_id]
    cmd += ["--version", req.version]
    if req.checks:
        cmd += ["--checks", req.checks]
    if req.timeout != 10.0:
        cmd += ["--timeout", str(req.timeout)]
    if req.security_profile is not None:
        cmd += ["--security-profile", str(req.security_profile)]
    if req.username:
        cmd += ["--username", req.username]
    if req.password:
        cmd += ["--password", req.password]
    if req.enable_dos:
        cmd += ["--enable-dos"]
    if req.enable_soap:
        cmd += ["--soap"]
    if req.idtag_attempts != 20:
        cmd += ["--idtag-attempts", str(req.idtag_attempts)]
    if result_file:
        cmd += ["--output", result_file]
    return cmd


def _build_check_cmd(req: RunCheckRequest) -> list[str]:
    cmd = [*JOLTPROBE_CMD, "checks", "run", req.check_id]
    cmd += ["--target", req.target, "--charger-id", req.charger_id]
    cmd += ["--version", req.version]
    if req.timeout != 10.0:
        cmd += ["--timeout", str(req.timeout)]
    if req.security_profile is not None:
        cmd += ["--security-profile", str(req.security_profile)]
    if req.username:
        cmd += ["--username", req.username]
    if req.password:
        cmd += ["--password", req.password]
    return cmd


async def _stream_subprocess(
    cmd: list[str],
    scan_id: Optional[str] = None,
):
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={**os.environ, "NO_COLOR": "1", "TERM": "dumb", "FORCE_COLOR": "0"},
    )
    try:
        if proc.stdout:
            async for line in proc.stdout:
                text = line.decode("utf-8", errors="replace").rstrip("\n")
                yield f"data: {json.dumps({'line': text})}\n\n"
        await proc.wait()
        done: dict = {"done": True, "exit_code": proc.returncode}
        if scan_id:
            done["scan_id"] = scan_id
        yield f"data: {json.dumps(done)}\n\n"
    except (asyncio.CancelledError, GeneratorExit):
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            proc.kill()
        raise


@app.post("/scan")
async def run_scan(req: ScanRequest):
    scan_id = uuid.uuid4().hex
    result_path = Path(tempfile.gettempdir()) / f"joltprobe-{scan_id}.json"
    cmd = _build_scan_cmd(req, result_file=str(result_path))
    return StreamingResponse(_stream_subprocess(cmd, scan_id=scan_id), media_type="text/event-stream")


@app.post("/run-check")
async def run_check(req: RunCheckRequest):
    cmd = _build_check_cmd(req)
    return StreamingResponse(_stream_subprocess(cmd), media_type="text/event-stream")


def main():
    import uvicorn

    reload = bool(os.getenv("OCPPSCAN_DEV"))
    uvicorn.run(
        "frontend.app:app" if reload else app,
        host="127.0.0.1",
        port=8080,
        reload=reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
