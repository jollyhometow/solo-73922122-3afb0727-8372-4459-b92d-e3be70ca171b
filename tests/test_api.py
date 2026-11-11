"""HTTP API 层测试：错误定位、示例可诊断、静态页面可访问。"""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

SNAP = {
    "nodes": [
        {"path": "/", "type": "directory", "uid": 0, "gid": 0, "mode": "755"},
        {"path": "/d", "type": "directory", "uid": 0, "gid": 0, "mode": "755"},
        {"path": "/d/f.txt", "type": "file", "uid": 0, "gid": 0, "mode": "644"},
    ]
}
REQ = {"uid": 1001, "gid": 1001, "supp_groups": [], "path": "/d/f.txt"}


def test_health_and_index():
    assert client.get("/health").json() == {"status": "ok"}
    r = client.get("/")
    assert r.status_code == 200
    assert "离线诊断" in r.text


def test_diagnose_ok():
    r = client.post("/api/diagnose", json={"snapshot": SNAP, "request": REQ})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["result"]["readable"] is True


def test_snapshot_error_has_loc():
    bad = json.loads(json.dumps(SNAP))
    bad["nodes"][1]["mode"] = "999"
    r = client.post("/api/diagnose", json={"snapshot": bad, "request": REQ})
    assert r.status_code == 422
    body = r.json()
    assert body["error_type"] == "snapshot_error"
    assert body["loc"] == ["nodes", "1", "mode"]
    assert "mode" in body["loc_text"]


def test_request_error_has_loc():
    bad = dict(REQ, uid=0)
    r = client.post("/api/diagnose", json={"snapshot": SNAP, "request": bad})
    assert r.status_code == 422
    assert r.json()["loc"] == ["uid"]


def test_validate_endpoint_warns_on_missing_parent():
    snap = {"nodes": [
        {"path": "/", "type": "directory", "uid": 0, "gid": 0, "mode": "755"},
        {"path": "/orphan/f.txt", "type": "file", "uid": 0, "gid": 0, "mode": "644"},
    ]}
    r = client.post("/api/validate-snapshot", json={"snapshot": snap})
    assert r.status_code == 200
    assert any("父目录" in w for w in r.json()["warnings"])


def test_all_bundled_examples_are_valid_and_diagnosable():
    data = json.loads(
        (Path(__file__).resolve().parents[1] / "app/static/examples.json").read_text("utf-8")
    )
    assert len(data["examples"]) >= 6
    for ex in data["examples"]:
        r = client.post("/api/diagnose",
                        json={"snapshot": ex["snapshot"], "request": ex["request"]})
        assert r.status_code == 200, f"示例 {ex['id']} 诊断失败: {r.text}"
        result = r.json()["result"]
        assert result["steps"], f"示例 {ex['id']} 没有解析步骤"
        assert "category" in result


def test_eloop_example_category():
    data = json.loads(
        (Path(__file__).resolve().parents[1] / "app/static/examples.json").read_text("utf-8")
    )
    ex = next(e for e in data["examples"] if e["id"] == "eloop-40")
    r = client.post("/api/diagnose",
                    json={"snapshot": ex["snapshot"], "request": ex["request"]})
    result = r.json()["result"]
    assert result["category"] == "link_limit_exceeded"
    assert result["symlink_follows"] == 41
