"""PAM 认证栈离线分析引擎的语义测试。

语义依据 Linux-PAM 上游源码：libpam/pam_dispatch.c、pam_misc.c、
pam_tokens.h、pam_handlers.c。覆盖简单控制、方括号控制/跳转、
include/substack、reset 边界、子栈终止、坏跳转、错误定位与拒绝。
"""

import pytest

from app.pam_engine import (
    ACT_BAD,
    ACT_DIE,
    ACT_DONE,
    ACT_IGNORE,
    ACT_OK,
    ACT_RESET,
    MAX_FILES,
    MAX_LINES,
    PamConfigError,
    analyze,
    build_payload,
)


# --------------------------------------------------------------------------- #
# 工具
# --------------------------------------------------------------------------- #
def payload(files, entry="sshd", returns=None):
    return {
        "entry": entry,
        "files": [{"name": n, "content": c} for n, c in files],
        "returns": returns or [],
    }


def run(files, entry="sshd", returns=None):
    e, f, r = build_payload(payload(files, entry, returns))
    return analyze(e, f, r)


def ret(file, line, value):
    return {"file": file, "line": line, "return": value}


class TestSimpleControls:
    def test_required_all_success(self):
        r = run([("sshd", "auth required pam_a.so\nauth required pam_b.so\n")],
                returns=[ret("sshd", 1, "success"), ret("sshd", 2, "success")])
        assert r["authenticated"] is True
        assert r["return_code"] == "success"

    def test_required_failure_does_not_short_circuit(self):
        # required 失败后继续执行后续模块（与 requisite 区分）
        r = run([("sshd", "auth required pam_a.so\nauth required pam_b.so\n")],
                returns=[ret("sshd", 1, "auth_err"), ret("sshd", 2, "success")])
        assert r["authenticated"] is False
        assert r["return_code"] == "auth_err"
        assert len(r["steps"]) == 2  # 第二个模块仍被调用

    def test_requisite_die_skips_rest(self):
        r = run([("sshd", "auth required pam_env.so\nauth requisite pam_deny.so\n"
                           "auth required pam_permit.so\n")],
                returns=[ret("sshd", 1, "success"), ret("sshd", 2, "auth_err"),
                         ret("sshd", 3, "success")])
        assert r["authenticated"] is False
        assert r["return_code"] == "auth_err"
        called = [(s["file"], s["line"]) for s in r["steps"] if s["kind"] == "module"]
        assert called == [("sshd", 1), ("sshd", 2)]
        assert any(s["line"] == 3 for s in r["skipped"])

    def test_requisite_success_continues(self):
        r = run([("sshd", "auth requisite pam_a.so\nauth required pam_b.so\n")],
                returns=[ret("sshd", 1, "success"), ret("sshd", 2, "success")])
        assert r["authenticated"] is True

    def test_sufficient_success_short_circuits(self):
        r = run([("sshd", "auth sufficient pam_a.so\nauth required pam_deny.so\n")],
                returns=[ret("sshd", 1, "success"), ret("sshd", 2, "auth_err")])
        assert r["authenticated"] is True
        called = [s["line"] for s in r["steps"] if s["kind"] == "module"]
        assert called == [1]
        assert any(s["line"] == 2 for s in r["skipped"])

    def test_sufficient_failure_is_ignored_and_continues(self):
        r = run([("sshd", "auth sufficient pam_a.so\nauth required pam_b.so\n")],
                returns=[ret("sshd", 1, "auth_err"), ret("sshd", 2, "success")])
        assert r["authenticated"] is True
        assert len([s for s in r["steps"] if s["kind"] == "module"]) == 2

    def test_optional_all_fail_denies(self):
        # 没有任何正向印象 => 最终失败
        r = run([("sshd", "auth optional pam_a.so\nauth optional pam_b.so\n")],
                returns=[ret("sshd", 1, "auth_err"), ret("sshd", 2, "user_unknown")])
        assert r["authenticated"] is False
        assert r["final_impression"] == "undef"

    def test_optional_one_success_grants(self):
        r = run([("sshd", "auth optional pam_a.so\nauth optional pam_b.so\n")],
                returns=[ret("sshd", 1, "auth_err"), ret("sshd", 2, "success")])
        assert r["authenticated"] is True

    def test_ignore_return_does_not_taint_state(self):
        r = run([("sshd", "auth required pam_a.so\nauth required pam_b.so\n")],
                returns=[ret("sshd", 1, "ignore"), ret("sshd", 2, "success")])
        assert r["authenticated"] is True

    def test_first_failure_is_retained(self):
        # bad 之后再来不同失败：首个失败优先，状态保留 auth_err
        r = run([("sshd", "auth required pam_a.so\nauth required pam_b.so\n")],
                returns=[ret("sshd", 1, "auth_err"), ret("sshd", 2, "user_unknown")])
        assert r["return_code"] == "auth_err"
        assert r["final_impression"] == "negative"


class TestBracketControl:
    def test_bracket_default_and_explicit(self):
        r = run([("sshd", "auth [success=ok default=bad] pam_a.so\n")],
                returns=[ret("sshd", 1, "user_unknown")])
        assert r["authenticated"] is False
        step = r["steps"][0]
        assert step["action"] == "bad"

    def test_bracket_spaces_inside(self):
        r = run([("sshd", "auth [ success = ok  default = ignore ] pam_a.so\n")],
                returns=[ret("sshd", 1, "success")])
        assert r["authenticated"] is True
        assert r["steps"][0]["action"] == "ok"

    def test_default_only_fills_unset_regardless_of_order(self):
        # default 在前、显式在后：显式值必须覆盖默认（对齐 _pam_set_default_control）
        r = run([("sshd", "auth [default=bad success=ok] pam_a.so\n")],
                returns=[ret("sshd", 1, "success")])
        assert r["authenticated"] is True
        # 显式在前、default 在后：default 不得覆盖已显式设置项
        e, f, _ = build_payload(payload(
            [("sshd", "auth [success=ok default=bad] pam_a.so\n")],
            returns=[ret("sshd", 1, "success")]))
        from app.pam_engine import RETURN_VALUES
        actions = f["sshd"].lines[0].actions
        assert actions[RETURN_VALUES["success"]] == ACT_OK
        assert actions[RETURN_VALUES["auth_err"]] == ACT_BAD

    def test_bracket_unspecified_defaults_to_bad(self):
        # 不给 default 也不显式给出 auth_err => 上游兜底 bad
        e, f, _ = build_payload(payload(
            [("sshd", "auth [success=ok] pam_a.so\n")],
            returns=[ret("sshd", 1, "auth_err")]))
        from app.pam_engine import RETURN_VALUES
        assert f["sshd"].lines[0].actions[RETURN_VALUES["auth_err"]] == ACT_BAD

    def test_bracket_illegal_action_rejected(self):
        with pytest.raises(PamConfigError) as ei:
            build_payload(payload(
                [("sshd", "auth [success=maybe] pam_a.so\n")],
                returns=[ret("sshd", 1, "success")]))
        assert "动作" in ei.value.message

    def test_bracket_illegal_return_rejected(self):
        with pytest.raises(PamConfigError) as ei:
            build_payload(payload(
                [("sshd", "auth [abort=ok] pam_a.so\n")],
                returns=[ret("sshd", 1, "success")]))
        assert "返回值" in ei.value.message

    def test_jump_forward_lands_on_target(self):
        # success=2：跳过第 2、3 行，落到第 4 行
        r = run([("sshd",
                  "auth [success=2 default=bad] pam_a.so\n"
                  "auth required pam_deny.so\n"
                  "auth required pam_deny.so\n"
                  "auth required pam_permit.so\n")],
                returns=[ret("sshd", 1, "success"), ret("sshd", 2, "auth_err"),
                         ret("sshd", 3, "auth_err"), ret("sshd", 4, "success")])
        called = [s["line"] for s in r["steps"] if s["kind"] == "module"]
        assert called == [1, 4]
        assert r["authenticated"] is True
        assert sorted(s["line"] for s in r["skipped"]) == [2, 3]

    def test_jump_past_tail_is_bad_jump(self):
        r = run([("sshd", "auth [success=9 default=bad] pam_a.so\n")],
                returns=[ret("sshd", 1, "success")])
        assert r["authenticated"] is False
        assert r["return_code"] == "auth_err"
        assert r["steps"][0].get("bad_jump") == 9

    def test_zero_jump_rejected(self):
        with pytest.raises(PamConfigError):
            build_payload(payload(
                [("sshd", "auth [success=0] pam_a.so\n")],
                returns=[ret("sshd", 1, "success")]))


class TestIncludeSubstack:
    def test_include_flattens_no_boundary(self):
        r = run([
            ("sshd", "auth required pam_permit.so\nauth include common-auth\n"),
            ("common-auth", "auth required pam_permit.so\n"),
        ], returns=[ret("sshd", 1, "success"), ret("common-auth", 1, "success")])
        # include 内联：没有 substack 进出步骤，两个模块都在 level 0
        called = [s["kind"] for s in r["steps"]]
        assert "substack_enter" not in called
        assert r["authenticated"] is True

    def test_substack_die_does_not_kill_parent(self):
        r = run([
            ("sshd", "auth substack password-auth\nauth required pam_permit.so\n"),
            ("password-auth", "auth requisite pam_deny.so\nauth required pam_permit.so\n"),
        ], returns=[
            ret("sshd", 2, "success"),
            ret("password-auth", 1, "auth_err"),
            ret("password-auth", 2, "success"),
        ])
        # 父栈第 2 行仍执行（die 只终止子栈）
        parent_called = [s["line"] for s in r["steps"]
                         if s["kind"] == "module" and s["file"] == "sshd"]
        assert parent_called == [2]
        # 子栈失败按 required 回并 => 整体拒绝
        assert r["authenticated"] is False
        assert any(s["kind"] == "substack_enter" for s in r["steps"])
        assert any(s["kind"] == "substack_return" for s in r["steps"])

    def test_substack_success_merges_and_grants(self):
        r = run([
            ("sshd", "auth substack common-auth\nauth required pam_permit.so\n"),
            ("common-auth", "auth required pam_permit.so\n"),
        ], returns=[ret("sshd", 2, "success"), ret("common-auth", 1, "success")])
        assert r["authenticated"] is True

    def test_substack_ignore_merge_keeps_parent(self):
        # 子栈终态 ignore（optional 模块返回 ignore）：回并不动父状态；
        # 父栈自己随后成功 => 通过
        r = run([
            ("sshd", "auth substack common-auth\nauth required pam_permit.so\n"),
            ("common-auth", "auth optional pam_a.so\n"),
        ], returns=[ret("sshd", 2, "success"), ret("common-auth", 1, "ignore")])
        assert r["authenticated"] is True
        # 子栈返回步骤记录的终态为 ignore，且未把父栈改成失败
        sub_ret = next(s for s in r["steps"] if s["kind"] == "substack_return")
        assert sub_ret["substack_return"] == "ignore"

    def test_missing_include_rejected(self):
        with pytest.raises(PamConfigError) as ei:
            build_payload(payload(
                [("sshd", "auth include ghost\n")], returns=[]))
        assert "缺失引用" in ei.value.message

    def test_missing_substack_rejected(self):
        with pytest.raises(PamConfigError) as ei:
            build_payload(payload(
                [("sshd", "auth substack ghost\n")], returns=[]))
        assert "缺失引用" in ei.value.message

    def test_include_cycle_rejected(self):
        with pytest.raises(PamConfigError) as ei:
            build_payload(payload([
                ("sshd", "auth include a\n"),
                ("a", "auth include b\n"),
                ("b", "auth include a\n"),
            ]))
        assert "循环" in ei.value.message

    def test_substack_cycle_rejected(self):
        with pytest.raises(PamConfigError) as ei:
            build_payload(payload([
                ("sshd", "auth substack a\n"),
                ("a", "auth substack sshd\n"),
            ]))
        assert "循环" in ei.value.message

    def test_jump_counts_whole_substack_as_one_unit(self):
        r = run([
            ("sshd",
             "auth [success=2 default=bad] pam_a.so\n"
             "auth substack common-auth\n"
             "auth required pam_deny.so\n"
             "auth required pam_permit.so\n"),
            ("common-auth", "auth required pam_permit.so\n"),
        ], returns=[
            ret("sshd", 1, "success"), ret("sshd", 3, "auth_err"),
            ret("sshd", 4, "success"), ret("common-auth", 1, "success"),
        ])
        # 跳过 substack（1 单元）+ 第 3 行（第 2 单元），落到第 4 行
        called = [(s["file"], s["line"]) for s in r["steps"] if s["kind"] == "module"]
        assert called == [("sshd", 1), ("sshd", 4)]
        assert r["authenticated"] is True


class TestReset:
    def test_reset_at_top_restores_initial_boundary(self):
        # include 内联无子栈边界：reset 恢复顶层初始 undef/auth_err
        r = run([
            ("sshd",
             "auth required pam_permit.so\n"
             "auth include common-auth\n"
             "auth required pam_deny.so\n"),
            ("common-auth", "auth [auth_err=reset default=ok] pam_unix.so\n"),
        ], returns=[
            ret("sshd", 1, "success"), ret("sshd", 3, "auth_err"),
            ret("common-auth", 1, "auth_err"),
        ])
        # reset 后状态回到 undef/auth_err，第 3 行再 bad
        reset_step = next(s for s in r["steps"]
                          if s["kind"] == "module" and s["action"] == "reset")
        assert reset_step["state_after"]["impression"] == "undef"
        assert r["authenticated"] is False

    def test_reset_in_substack_restores_saved_boundary(self):
        r = run([
            ("sshd",
             "auth required pam_permit.so\n"
             "auth substack common-auth\n"
             "auth required pam_permit.so\n"),
            ("common-auth",
             "auth [auth_err=reset default=ok] pam_unix.so\n"
             "auth sufficient pam_ldap.so\n"),
        ], returns=[
            ret("sshd", 1, "success"), ret("sshd", 3, "success"),
            ret("common-auth", 1, "auth_err"),
            ret("common-auth", 2, "success"),
        ])
        # 进入子栈前父栈已 positive/success，reset 恢复该边界而非初始 undef
        reset_step = next(s for s in r["steps"]
                          if s["kind"] == "module" and s["action"] == "reset")
        assert reset_step["state_after"]["impression"] == "positive"
        assert reset_step["state_after"]["status"] == "success"
        assert r["authenticated"] is True


class TestParsingAndValidation:
    def test_non_auth_lines_ignored(self):
        r = run([("sshd",
                  "account required pam_a.so\n"
                  "password requisite pam_b.so\n"
                  "auth required pam_c.so\n"
                  "# a comment\n\n")],
                returns=[ret("sshd", 3, "success")])
        assert r["authenticated"] is True
        ignored = r["files"][0]["ignored_lines"]
        # account/password/注释 + 1 个空行（尾部换行不另计空行）
        reasons = [x["reason"] for x in ignored]
        assert sum("非 auth" in x for x in reasons) == 2
        assert sum("空行或注释" in x for x in reasons) == 2
        assert len(ignored) == 4

    def test_backslash_continuation_keeps_start_line(self):
        r = run([("sshd", "auth required pam_a.so \\\n  debug quiet\n")],
                returns=[ret("sshd", 1, "success")])
        assert r["files"][0]["auth_lines"][0]["line"] == 1
        assert r["authenticated"] is True

    def test_leading_dash_accepted(self):
        r = run([("sshd", "auth required -pam_a.so\n")],
                returns=[ret("sshd", 1, "success")])
        assert r["authenticated"] is True

    def test_at_include_supported(self):
        r = run([
            ("sshd", "@include common-auth\n"),
            ("common-auth", "auth required pam_permit.so\n"),
        ], returns=[ret("common-auth", 1, "success")])
        assert r["authenticated"] is True

    def test_too_many_files(self):
        files = [(f"svc{i}", "auth required pam_a.so\n") for i in range(MAX_FILES + 1)]
        with pytest.raises(PamConfigError) as ei:
            build_payload(payload(files))
        assert str(MAX_FILES) in ei.value.message

    def test_too_many_lines(self):
        content = "\n".join("auth required pam_a.so" for _ in range(MAX_LINES + 1))
        with pytest.raises(PamConfigError) as ei:
            build_payload(payload([("sshd", content)]))
        assert str(MAX_LINES) in ei.value.message

    def test_entry_must_exist(self):
        with pytest.raises(PamConfigError) as ei:
            build_payload(payload([("sshd", "auth required pam_a.so\n")], entry="login"))
        assert ei.value.loc == ["entry"]

    def test_duplicate_file_name(self):
        with pytest.raises(PamConfigError) as ei:
            build_payload({
                "entry": "sshd",
                "files": [
                    {"name": "sshd", "content": "auth required pam_a.so\n"},
                    {"name": "sshd", "content": "auth required pam_b.so\n"},
                ],
                "returns": [],
            })
        assert "重复" in ei.value.message

    def test_missing_module_return(self):
        with pytest.raises(PamConfigError) as ei:
            build_payload(payload(
                [("sshd", "auth required pam_a.so\n")], returns=[]))
        assert "缺少模块返回码" in ei.value.message

    def test_return_for_non_module_line_rejected(self):
        with pytest.raises(PamConfigError) as ei:
            build_payload(payload(
                [("sshd", "auth include common-auth\n"),
                 ("common-auth", "auth required pam_a.so\n")],
                returns=[ret("sshd", 1, "success"),
                         ret("common-auth", 1, "success")]))
        assert "不是 auth 模块行" in ei.value.message

    def test_bad_return_value_rejected(self):
        with pytest.raises(PamConfigError) as ei:
            build_payload(payload(
                [("sshd", "auth required pam_a.so\n")],
                returns=[ret("sshd", 1, "abort")]))
        assert "return" in ei.value.message

    def test_return_line_out_of_range(self):
        with pytest.raises(PamConfigError) as ei:
            build_payload(payload(
                [("sshd", "auth required pam_a.so\n")],
                returns=[ret("sshd", 9, "success")]))
        assert "超出" in ei.value.message

    def test_illegal_control_rejected(self):
        with pytest.raises(PamConfigError):
            build_payload(payload(
                [("sshd", "auth weirdcontrol pam_a.so\n")],
                returns=[ret("sshd", 1, "success")]))

    def test_empty_auth_stack_warns_and_denies(self):
        r = run([("sshd", "account required pam_a.so\n")], returns=[])
        assert r["authenticated"] is False
        assert r["warnings"]

    def test_action_constants_match_upstream(self):
        # 与 pam_private.h 的负值编码保持一致
        assert ACT_IGNORE == 0
        assert ACT_OK == -1 and ACT_DONE == -2
        assert ACT_BAD == -3 and ACT_DIE == -4 and ACT_RESET == -5
