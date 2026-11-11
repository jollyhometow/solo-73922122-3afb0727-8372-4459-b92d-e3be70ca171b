"""关键语义测试：逐级搜索、ACL 优先级/mask/不退回 other、物理 ..、40 次限制、错误定位。"""

import pytest

from app.engine import (
    MAX_SYMLINKS,
    RequestError,
    SnapshotError,
    build_request,
    build_snapshot,
)
from app.resolver import diagnose


# --------------------------------------------------------------------------- #
# 工具
# --------------------------------------------------------------------------- #
def run(nodes, req, *, users=None, groups=None):
    snap = build_snapshot(
        {"nodes": nodes, "users": users or {}, "groups": groups or {}}
    )
    r = build_request(req)
    return diagnose(snap, r)


def d(path, mode="755", uid=0, gid=0, **kw):
    base = {"path": path, "type": "directory", "uid": uid, "gid": gid, "mode": mode}
    base.update(kw)
    return base


def f(path, mode="644", uid=0, gid=0, **kw):
    base = {"path": path, "type": "file", "uid": uid, "gid": gid, "mode": mode}
    base.update(kw)
    return base


def l(path, target, mode="777", **kw):
    base = {"path": path, "type": "symlink", "uid": 0, "gid": 0,
            "mode": mode, "link_target": target}
    base.update(kw)
    return base


def basic_tree(**over):
    # shared 目录 700 属 root：1001 对目标文件是属主可读，
    # 却在目录解析阶段因 other 无 x 被挡（“文件有读权限却打不开”）
    nodes = [d("/"), d("/data", "755"), d("/data/shared", "700", uid=0, gid=1000),
             f("/data/shared/a.txt", "644", uid=1001, gid=1001)]
    return nodes


# --------------------------------------------------------------------------- #
# 1. 目录 search 优先于文件 read
# --------------------------------------------------------------------------- #
class TestSearchBeforeRead:
    def test_dir_no_x_blocks_even_if_file_owner_readable(self):
        # 文件属主可读，但 shared 目录 700 属 root：在进入该目录的 search 检查处被挡
        res = run(basic_tree(),
                  {"uid": 1001, "gid": 1001, "supp_groups": [100],
                   "path": "/data/shared/a.txt"})
        assert res["readable"] is False
        assert res["category"] == "permission_denied"
        assert res["errno"] == "EACCES"
        # 失败节点是 shared 目录自身（缺 x），在解析其内部组件 a.txt 时触发
        assert res["first_failure"]["cwd"] == "/data/shared"
        assert res["first_failure"]["component"] == "a.txt"
        assert res["steps"][res["first_failure"]["step_index"]]["node"]["path"] == "/data/shared"
        assert res["adopted"]["matched"]["kind"] == "mode_other"

    def test_eacces_takes_precedence_over_enoent(self):
        # 目录不可搜索时，即使目标不存在也先报 EACCES
        nodes = [d("/"), d("/secret", "700")]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [],
                          "path": "/secret/whatever"})
        assert res["errno"] == "EACCES"
        assert res["category"] == "permission_denied"

    def test_missing_gives_enoent(self):
        nodes = [d("/"), d("/data", "755")]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [],
                          "path": "/data/gone.txt"})
        assert res["readable"] is False
        assert res["category"] == "path_missing"
        assert res["errno"] == "ENOENT"

    def test_all_x_and_r_grants(self):
        nodes = [d("/"), d("/data", "755"),
                 f("/data/a.txt", "644", uid=0, gid=0)]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [],
                          "path": "/data/a.txt"})
        assert res["readable"] is True
        assert res["category"] == "ok"
        # 逐级 search：根 /、进入 data，最后文件 r —— 共 3 次权限检查
        kinds = [s["kind"] for s in res["steps"] if s["kind"] == "permission_check"]
        assert len(kinds) == 3
        assert res["adopted"]["matched"]["kind"] == "mode_other"


# --------------------------------------------------------------------------- #
# 2. 经典 mode 权限
# --------------------------------------------------------------------------- #
class TestClassicMode:
    def test_owner_uses_user_bits(self):
        nodes = [d("/"), f("/f", "600", uid=1001, gid=2000)]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [], "path": "/f"})
        assert res["readable"] is True
        assert res["adopted"]["matched"]["kind"] == "mode_owner"

    def test_group_match_uses_group_bits(self):
        nodes = [d("/"), f("/f", "640", uid=0, gid=2000)]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [2000], "path": "/f"})
        assert res["readable"] is True
        assert res["adopted"]["matched"]["kind"] == "mode_group"

    def test_group_matched_no_r_does_not_fallback_to_other(self):
        # 组位 ---, other r--，但组身份命中 => 拒绝，不得退回 other
        nodes = [d("/"), f("/f", "604", uid=0, gid=2000)]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [2000], "path": "/f"})
        assert res["readable"] is False
        assert res["adopted"]["matched"]["kind"] == "mode_group"
        considered_kinds = [c["kind"] for c in res["adopted"]["considered"]]
        assert "mode_other" not in considered_kinds

    def test_other_when_no_identity_match(self):
        nodes = [d("/"), f("/f", "604", uid=0, gid=2000)]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [], "path": "/f"})
        assert res["readable"] is True
        assert res["adopted"]["matched"]["kind"] == "mode_other"


# --------------------------------------------------------------------------- #
# 3. POSIX ACL
# --------------------------------------------------------------------------- #
ACL = [
    {"type": "user_obj", "perms": "rw-"},
    {"type": "user", "qualifier": 1002, "perms": "rwx"},
    {"type": "group_obj", "perms": "r--"},
    {"type": "group", "qualifier": 2000, "perms": "--x"},
    {"type": "mask", "perms": "r--"},
    {"type": "other", "perms": "---"},
]


class TestACL:
    def _tree(self, acl=None, mode="640"):
        return [d("/"), f("/f", mode, uid=0, gid=3000, acl=acl or ACL)]

    def test_owner_always_user_obj_even_if_named_user_exists(self):
        # 文件属主 UID=1002，同时存在 user:1002 条目；属主必须走 user_obj（rw-）
        acl = [dict(e) for e in ACL]
        nodes = [d("/"), f("/f", "640", uid=1002, gid=3000, acl=acl)]
        res = run(nodes, {"uid": 1002, "gid": 1002, "supp_groups": [], "path": "/f"})
        assert res["adopted"]["matched"]["kind"] == "acl_user_obj"
        assert res["readable"] is True

    def test_named_user_masked_no_fallback(self):
        # bob 命名条目 rwx 被 mask r-- 约束 => 可读
        nodes = self._tree()
        res = run(nodes, {"uid": 1002, "gid": 1002, "supp_groups": [], "path": "/f"})
        m = res["adopted"]["matched"]
        assert m["kind"] == "acl_named_user"
        assert m["effective_perms"] == "r--"
        assert res["readable"] is True
        assert all(c["kind"] != "acl_other" for c in res["adopted"]["considered"])

    def test_named_user_denied_by_mask_still_no_other_fallback(self):
        acl = [
            {"type": "user_obj", "perms": "rw-"},
            {"type": "user", "qualifier": 1002, "perms": "r--"},
            {"type": "group_obj", "perms": "---"},
            {"type": "mask", "perms": "---"},
            {"type": "other", "perms": "r--"},
        ]
        nodes = self._tree(acl)
        res = run(nodes, {"uid": 1002, "gid": 1002, "supp_groups": [], "path": "/f"})
        assert res["readable"] is False
        m = res["adopted"]["matched"]
        assert m["kind"] == "acl_named_user"
        assert m["effective_perms"] == "---"
        assert all(c["kind"] != "acl_other" for c in res["adopted"]["considered"])

    def test_group_union_then_mask(self):
        # 主组命中 group_obj r--，附加组命中 group:2000 --x；并集 r-x & mask r-- = r--
        nodes = self._tree()
        res = run(nodes, {"uid": 1004, "gid": 3000,
                          "supp_groups": [2000], "path": "/f"})
        m = res["adopted"]["matched"]
        assert m["kind"] == "acl_group_union"
        assert m["raw_bits"] == 0b101
        assert m["effective_bits"] == 0b100
        assert res["readable"] is True

    def test_group_matched_without_perm_no_other_fallback(self):
        # other 有 r，但组身份命中且有效权限无 r => 拒绝
        acl = [
            {"type": "user_obj", "perms": "rw-"},
            {"type": "group_obj", "perms": "---"},
            {"type": "mask", "perms": "---"},
            {"type": "other", "perms": "r--"},
        ]
        nodes = self._tree(acl)
        res = run(nodes, {"uid": 1004, "gid": 3000, "supp_groups": [], "path": "/f"})
        assert res["readable"] is False
        assert res["adopted"]["matched"]["kind"] == "acl_group_union"
        assert all(c["kind"] != "acl_other" for c in res["adopted"]["considered"])

    def test_other_reachable_only_when_no_group_matches(self):
        nodes = self._tree()
        # 1004 的组集合不含 3000/2000 => other（---）拒绝
        res = run(nodes, {"uid": 1004, "gid": 1004, "supp_groups": [], "path": "/f"})
        assert res["readable"] is False
        assert res["adopted"]["matched"]["kind"] == "acl_other"

    def test_acl_numeric_perms_accepted(self):
        acl = [
            {"type": "user_obj", "perms": 6},
            {"type": "group_obj", "perms": 4},
            {"type": "other", "perms": 0},
        ]
        nodes = [d("/"), f("/f", "640", acl=acl)]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [], "path": "/f"})
        assert res["adopted"]["acl_used"] is True
        assert res["adopted"]["matched"]["kind"] == "acl_other"

    def test_extended_acl_requires_mask(self):
        bad = [
            {"type": "user_obj", "perms": "rw-"},
            {"type": "user", "qualifier": 1002, "perms": "r--"},
            {"type": "group_obj", "perms": "---"},
            {"type": "other", "perms": "---"},
        ]
        with pytest.raises(SnapshotError) as ei:
            build_snapshot({"nodes": [d("/"), f("/f", acl=bad)]})
        assert "mask" in ei.value.message
        assert ei.value.loc[-1] == "acl"


# --------------------------------------------------------------------------- #
# 4. 软链接 / 物理 .. / 40 次
# --------------------------------------------------------------------------- #
class TestSymlinks:
    def test_relative_symlink_expands_from_link_directory(self):
        # cwd=/a/sub 时相对链接 ../../b/t.txt 展开为 /b/t.txt
        nodes = [
            d("/"), d("/a", "755"), d("/a/sub", "755"),
            d("/b", "755"), f("/b/t.txt", "644"),
            l("/a/sub/ln", "../../b/t.txt"),
        ]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [],
                          "path": "/a/sub/ln"})
        assert res["readable"] is True
        assert res["final_node"]["path"] == "/b/t.txt"
        assert res["symlink_follows"] == 1

    def test_absolute_symlink_restarts_at_root(self):
        nodes = [d("/"), d("/x", "700", uid=1001, gid=1001), d("/y", "755"),
                 f("/y/t.txt", "644"), l("/x/ln", "/y/t.txt", uid=1001, gid=1001)]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [],
                          "path": "/x/ln"})
        assert res["readable"] is True
        assert res["final_node"]["path"] == "/y/t.txt"

    def test_dotdot_is_physical_not_lexical(self):
        # /home/alice/link -> ../bob ; 解析后 cwd=/home/bob；
        # 再跟 .. 必须回到 /home，而不是词法上的 /home/alice
        nodes = [
            d("/"), d("/home", "755"),
            d("/home/alice", "750", uid=1001, gid=1001),
            d("/home/bob", "755", uid=1003, gid=1003),
            d("/home/carl", "755", uid=1005, gid=1005),
            f("/home/carl/secret.txt", "600", uid=1005, gid=1005),
            l("/home/alice/link", "../bob", uid=1001, gid=1001),
        ]
        # 词法规范化会把 /home/alice/link/../carl 当成 /home/alice/carl（不存在 => ENOENT）
        # carl 为 755 可进入，但 secret.txt 属主 1005 且 600 => 文件 r 检查 EACCES；
        # 若错误地做词法折叠，则会在 /home/alice 下找不到 carl 而报 ENOENT
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [],
                          "path": "/home/alice/link/../carl/secret.txt"})
        assert res["errno"] == "EACCES"
        assert res["first_failure"]["cwd"] == "/home/carl"
        assert res["final_node"]["path"] == "/home/carl/secret.txt"

    def test_loop_hits_eloop_at_41st(self):
        nodes = [d("/"), d("/loop", "755"),
                 l("/loop/a", "b"), l("/loop/b", "a")]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [],
                          "path": "/loop/a"})
        assert res["readable"] is False
        assert res["category"] == "link_limit_exceeded"
        assert res["errno"] == "ELOOP"
        assert res["symlink_follows"] == MAX_SYMLINKS + 1

    def test_exactly_40_follows_allowed(self):
        # 构造 40 次链接后到达普通文件：a1->a2->...->a40->target
        nodes = [d("/"), d("/chain", "755")]
        for i in range(1, 40):
            nodes.append(l(f"/chain/a{i}", f"a{i+1}"))
        nodes.append(l("/chain/a40", "target"))
        nodes.append(f("/chain/target", "644"))
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [],
                          "path": "/chain/a1"})
        assert res["symlink_follows"] == 40
        assert res["readable"] is True

    def test_symlink_permissions_are_not_checked(self):
        # 链接本身 mode 000 不影响跟随
        nodes = [d("/"), d("/d", "755"), f("/d/t", "644"),
                 l("/d/ln", "t", mode="000")]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [],
                          "path": "/d/ln"})
        assert res["readable"] is True


# --------------------------------------------------------------------------- #
# 5. 类型区分
# --------------------------------------------------------------------------- #
class TestTypes:
    def test_directory_target_is_not_regular(self):
        nodes = [d("/"), d("/d", "755")]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [], "path": "/d"})
        assert res["category"] == "not_regular"
        assert res["errno"] == "ENOTREG"

    def test_other_type_target_is_not_regular(self):
        nodes = [d("/"), d("/dev", "755"),
                 {"path": "/dev/null", "type": "other", "uid": 0, "gid": 0, "mode": "666"}]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [], "path": "/dev/null"})
        assert res["category"] == "not_regular"

    def test_enotdir_mid_component(self):
        nodes = [d("/"), f("/regular", "644")]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [],
                          "path": "/regular/child"})
        assert res["category"] == "not_regular"
        assert res["errno"] == "ENOTDIR"


# --------------------------------------------------------------------------- #
# 6. 快照/请求校验与定位
# --------------------------------------------------------------------------- #
class TestValidation:
    def test_missing_root(self):
        with pytest.raises(SnapshotError) as ei:
            build_snapshot({"nodes": [f("/a")]})
        assert "根目录" in ei.value.message

    def test_relative_path_rejected(self):
        with pytest.raises(SnapshotError) as ei:
            build_snapshot({"nodes": [d("/"), f("rel/path")]})
        assert ei.value.loc == ["nodes", "1", "path"]

    def test_dup_path(self):
        with pytest.raises(SnapshotError) as ei:
            build_snapshot({"nodes": [d("/"), d("/a"), f("/a", "644")]})
        assert "重复" in ei.value.message

    def test_symlink_needs_target(self):
        with pytest.raises(SnapshotError) as ei:
            build_snapshot({"nodes": [d("/"),
                                      {"path": "/ln", "type": "symlink",
                                       "uid": 0, "gid": 0, "mode": "777"}]})
        assert ei.value.loc[-1] == "link_target"

    def test_bad_mode(self):
        with pytest.raises(SnapshotError) as ei:
            build_snapshot({"nodes": [d("/"), f("/f", "888")]})
        assert ei.value.loc == ["nodes", "1", "mode"]

    def test_bool_uid_rejected(self):
        with pytest.raises(SnapshotError) as ei:
            build_snapshot({"nodes": [d("/"), f("/f", "644", uid=True)]})
        assert ei.value.loc == ["nodes", "1", "uid"]

    def test_too_many_nodes(self):
        nodes = [d("/")] + [f(f"/f{i}", "644") for i in range(100)]
        with pytest.raises(SnapshotError) as ei:
            build_snapshot({"nodes": nodes})
        assert "100" in ei.value.message

    def test_acl_duplicate_entry(self):
        acl = [
            {"type": "user_obj", "perms": "rw-"},
            {"type": "user", "qualifier": 1002, "perms": "r--"},
            {"type": "user", "qualifier": 1002, "perms": "rwx"},
            {"type": "group_obj", "perms": "---"},
            {"type": "mask", "perms": "r--"},
            {"type": "other", "perms": "---"},
        ]
        with pytest.raises(SnapshotError) as ei:
            build_snapshot({"nodes": [d("/"), f("/f", acl=acl)]})
        assert "重复" in ei.value.message

    def test_non_normalized_path_rejected(self):
        with pytest.raises(SnapshotError) as ei:
            build_snapshot({"nodes": [d("/"), d("/a/./b")]})
        assert "规范化" in ei.value.message

    def test_request_uid_must_be_nonzero(self):
        with pytest.raises(RequestError) as ei:
            build_request({"uid": 0, "gid": 0, "supp_groups": [], "path": "/f"})
        assert ei.value.loc == ["uid"]

    def test_request_relative_path(self):
        with pytest.raises(RequestError) as ei:
            build_request({"uid": 1, "gid": 0, "supp_groups": [], "path": "f"})
        assert ei.value.loc == ["path"]

    def test_request_bad_groups(self):
        with pytest.raises(RequestError):
            build_request({"uid": 1, "gid": 0, "supp_groups": ["x"], "path": "/f"})


class TestParsingEdge:
    def test_integer_and_4digit_mode(self):
        # 整数 mode 与含 setuid/setgid/sticky 的 4 位八进制都可解析，特殊位不影响读判定
        nodes = [d("/", 0o755),
                 d("/tmp", "1777"),
                 f("/tmp/f", 0o644)]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [],
                          "path": "/tmp/f"})
        assert res["readable"] is True
        assert res["final_node"]["mode"] == "644"

    def test_dotdot_at_root_stays_at_root(self):
        nodes = [d("/"), d("/data", "755"), f("/data/f", "644")]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [],
                          "path": "/../../data/f"})
        assert res["readable"] is True
        assert res["final_node"]["path"] == "/data/f"

    def test_dot_component(self):
        nodes = [d("/"), d("/data", "755"), f("/data/f", "644")]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [],
                          "path": "/data/./f"})
        assert res["readable"] is True

    def test_root_path_targets_directory(self):
        nodes = [d("/")]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [], "path": "/"})
        assert res["category"] == "not_regular"
        assert res["errno"] == "ENOTREG"

    def test_trailing_slash_on_file_is_enotdir(self):
        nodes = [d("/"), f("/f", "644")]
        res = run(nodes, {"uid": 1001, "gid": 1001, "supp_groups": [], "path": "/f/"})
        assert res["errno"] == "ENOTDIR"

    def test_invalid_acl_perm_string(self):
        acl = [
            {"type": "user_obj", "perms": "abc"},
            {"type": "group_obj", "perms": "---"},
            {"type": "other", "perms": "---"},
        ]
        with pytest.raises(SnapshotError) as ei:
            build_snapshot({"nodes": [d("/"), f("/f", acl=acl)]})
        assert ei.value.loc[:3] == ["nodes", "1", "acl"]

    def test_named_group_requires_qualifier(self):
        acl = [
            {"type": "user_obj", "perms": "rw-"},
            {"type": "group", "perms": "r--"},
            {"type": "group_obj", "perms": "---"},
            {"type": "mask", "perms": "r--"},
            {"type": "other", "perms": "---"},
        ]
        with pytest.raises(SnapshotError) as ei:
            build_snapshot({"nodes": [d("/"), f("/f", acl=acl)]})
        assert "qualifier" in ei.value.message
