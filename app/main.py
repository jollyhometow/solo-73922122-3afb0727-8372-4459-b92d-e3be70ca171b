"""FastAPI 离线诊断服务：全部计算基于用户提交的 JSON，不访问宿主文件系统。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from .engine import RequestError, SnapshotError, build_request, build_snapshot
from .resolver import diagnose
from .pam_engine import PamConfigError, analyze as pam_analyze, build_payload as build_pam_payload

app = FastAPI(
    title="共享文件服务器读取权限 / PAM 认证栈离线诊断",
    version="1.1.0",
    description=(
        "基于运维采集的目录快照 JSON，模拟 Linux 无特权进程的路径解析与权限判定，"
        "定位“文件有读权限却打不开”的首个受阻点；并提供 /etc/pam.d 认证栈（auth）"
        "离线分析，按 Linux-PAM pam_authenticate 语义模拟 required/requisite/"
        "sufficient/optional、include/substack、方括号控制与跳转。全程不访问宿主机文件系统。"
    ),
)

STATIC_DIR = Path(__file__).resolve().parent / "static"


class DiagnosePayload(BaseModel):
    snapshot: Any
    request: Any


def _json_error(exc: SnapshotError | RequestError, status: int = 422) -> JSONResponse:
    kind = "snapshot_error" if isinstance(exc, SnapshotError) else "request_error"
    return JSONResponse(
        status_code=status,
        content={
            "ok": False,
            "error_type": kind,
            "message": exc.message,
            "loc": exc.loc,
            "loc_text": "$" + "".join(f"[{p!r}]" for p in exc.loc) if exc.loc else "$",
        },
    )


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/pam", include_in_schema=False)
def pam_index() -> FileResponse:
    return FileResponse(STATIC_DIR / "pam.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/examples")
def examples() -> JSONResponse:
    data = json.loads((STATIC_DIR / "examples.json").read_text(encoding="utf-8"))
    return JSONResponse(data)


@app.get("/api/pam/examples")
def pam_examples() -> JSONResponse:
    data = json.loads((STATIC_DIR / "pam_examples.json").read_text(encoding="utf-8"))
    return JSONResponse(data)


@app.post("/api/validate-snapshot")
def validate_snapshot(payload: dict[str, Any]) -> JSONResponse:
    try:
        snap = build_snapshot(payload.get("snapshot"))
    except SnapshotError as exc:
        return _json_error(exc)
    return JSONResponse(
        content={
            "ok": True,
            "node_count": len(snap.nodes),
            "warnings": snap.warnings,
            "paths": sorted(snap.nodes.keys()),
        }
    )


@app.post("/api/diagnose")
def diagnose_endpoint(payload: DiagnosePayload) -> JSONResponse:
    # 先校验快照（带定位），再校验请求
    try:
        snap = build_snapshot(payload.snapshot)
    except SnapshotError as exc:
        return _json_error(exc)
    try:
        req = build_request(payload.request)
    except RequestError as exc:
        return _json_error(exc)

    result = diagnose(snap, req)
    result["snapshot_warnings"] = snap.warnings
    return JSONResponse(content={"ok": True, "result": result})


# --------------------------------------------------------------------------- #
# PAM 认证栈离线分析
# --------------------------------------------------------------------------- #
@app.post("/api/pam/analyze")
def pam_analyze_endpoint(payload: dict[str, Any]) -> JSONResponse:
    try:
        entry, files, returns = build_pam_payload(payload)
        result = pam_analyze(entry, files, returns)
    except PamConfigError as exc:
        return JSONResponse(
            status_code=422,
            content={
                "ok": False,
                "error_type": "pam_config_error",
                "message": exc.message,
                "loc": exc.loc,
                "loc_text": "$" + "".join(f"[{p!r}]" for p in exc.loc) if exc.loc else "$",
            },
        )
    return JSONResponse(content={"ok": True, "result": result})
