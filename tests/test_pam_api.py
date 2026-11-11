"""PAM 分析 HTTP API 层测试：路由、错误定位、示例可分析、页面可访问。"""

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

PAM_EXAMPLES = json.loads(
    (Path(__file__).resolve().parents[1] / "app/static/pam_examples.json").read_text("utf-8")
)


def test_pam_page_served():
    r = client.get("/pam")
    assert r.status_code == 200
    assert "PAM" in r.text
    # 首页已接入 PAM 入口
    home = client.get("/").text
    assert '/pam' in home


def test_pam_examples_endpoint():
    r = client.get("/api/pam/examples")
    assert r.status_code == 200
    data = r.json()
    assert len(data["examples"]) >= 6
    # 必须包含子栈示例
    assert any("substack" in e["id"] for e in data["examples"])


def test_analyze_required_requisite_die():
    payload = {
        "entry": "sshd",
        "files": [{"name": "sshd",
                   "content": "auth required pam_env.so\nauth requisite pam_deny.so\n"
                              "auth required pam_permit.so\n"}],
        "returns": [
            {"file": "sshd", "line": 1, "return": "success"},
            {"file": "sshd", "line": 2, "return": "auth_err"},
            {"file": "sshd", "line": 3, "return": "success"},
        ],
    }
    r = client.post("/api/pam/analyze", json=payload)
    assert r.status_code == 200
    result = r.json()["result"]
    assert result["return_code"] == "auth_err"
    assert result["authenticated"] is False
    # 包含调用与跳过的源行
    assert any(s["line"] == 3 for s in result["skipped"])
    assert all("state_before" in s and "state_after" in s
               for s in result["steps"] if s["kind"] == "module")


def test_analyze_missing_reference_is_422_with_loc():
    payload = {
        "entry": "sshd",
        "files": [{"name": "sshd", "content": "auth include system-auth\n"}],
        "returns": [],
    }
    r = client.post("/api/pam/analyze", json=payload)
    assert r.status_code == 422
    body = r.json()
    assert body["ok"] is False
    assert body["error_type"] == "pam_config_error"
    assert "缺失引用" in body["message"]
    assert body["loc"] == ["files"]
    assert body["loc_text"] == "$['files']"


def test_analyze_cycle_is_422():
    payload = {
        "entry": "sshd",
        "files": [
            {"name": "sshd", "content": "auth include a\n"},
            {"name": "a", "content": "auth include sshd\n"},
        ],
        "returns": [],
    }
    r = client.post("/api/pam/analyze", json=payload)
    assert r.status_code == 422
    assert "循环" in r.json()["message"]


def test_analyze_missing_return_is_422():
    payload = {
        "entry": "sshd",
        "files": [{"name": "sshd", "content": "auth required pam_a.so\n"}],
        "returns": [],
    }
    r = client.post("/api/pam/analyze", json=payload)
    assert r.status_code == 422
    assert "缺少模块返回码" in r.json()["message"]


def test_all_bundled_pam_examples_either_analyze_or_reject_cleanly():
    for ex in PAM_EXAMPLES["examples"]:
        r = client.post("/api/pam/analyze", json=ex["payload"])
        if ex["id"] == "missing-reference-error":
            assert r.status_code == 422, f"示例 {ex['id']} 应被拒绝"
            assert r.json()["loc"]
        else:
            assert r.status_code == 200, f"示例 {ex['id']} 分析失败: {r.text}"
            result = r.json()["result"]
            assert "return_code" in result
            assert "steps" in result and "skipped" in result
            assert isinstance(result["authenticated"], bool)


def test_substack_example_returns_full_trail():
    ex = next(e for e in PAM_EXAMPLES["examples"] if e["id"] == "substack-die-isolation")
    r = client.post("/api/pam/analyze", json=ex["payload"])
    result = r.json()["result"]
    kinds = [s["kind"] for s in result["steps"]]
    assert "substack_enter" in kinds and "substack_return" in kinds
    # 父栈模块在子栈 die 后仍被调用
    assert any(s.get("file") == "sshd" and s["line"] == 2
               for s in result["steps"] if s["kind"] == "module")
    assert result["authenticated"] is False
