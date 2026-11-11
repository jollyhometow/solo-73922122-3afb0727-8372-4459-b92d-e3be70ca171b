"""
纯快照的 Linux 无特权进程路径解析与访问诊断引擎。

本模块 *不* 访问宿主机文件系统：所有节点来自运维采集的 JSON 目录快照。
语义对齐 Linux namei / generic_permission + POSIX.1e（Linux 实现风格）：

* 逐级检查目录 search (--x) 权限，路径不存在前先报沿途 EACCES；
* 软链接按其所在目录解析相对目标，绝对目标从 "/" 重新开始；
* ".." 不做词法折叠，按物理父目录回退（经过软链接时与 naive 规范化不同）；
* 最多跟随 MAXSYMLINKS(=40) 次，第 41 次触发 ELOOP；
* ACL：所有者优先；命名用户 / 匹配组命后由 mask 约束且 *不* 退回 other。
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import Any, Optional

MAX_NODES = 100
# Linux include/linux/namei.h: #define MAXSYMLINKS 40
MAX_SYMLINKS = 40

VALID_TYPES = {"file", "directory", "symlink", "other"}
VALID_ACL_TYPES = {"user_obj", "user", "group_obj", "group", "mask", "other"}
VALID_QUAL_TYPES = {"user", "group"}
PERM_CHARS = {"r": 4, "w": 2, "x": 1}


class SnapshotError(ValueError):
    """快照本身结构/取值非法，loc 指向出错位置。"""

    def __init__(self, message: str, loc: Optional[list[str]] = None):
        super().__init__(message)
        self.message = message
        self.loc = loc or []


class RequestError(ValueError):
    """读取请求 JSON 非法，loc 指向出错字段。"""

    def __init__(self, message: str, loc: Optional[list[str]] = None):
        super().__init__(message)
        self.message = message
        self.loc = loc or []


# --------------------------------------------------------------------------- #
# 数据模型
# --------------------------------------------------------------------------- #
@dataclass
class ACL_Entry:
    type: str
    perms: int  # 0..7
    qualifier: Optional[int] = None  # 命名 user/group 的 UID/GID
    raw: str = ""


@dataclass
class Node:
    path: str
    type: str
    uid: int
    gid: int
    mode: int  # 仅低 12 位有效
    mode_raw: str
    acl: list[ACL_Entry] = field(default_factory=list)
    link_target: Optional[str] = None


@dataclass
class Snapshot:
    nodes: dict[str, Node]
    users: dict[int, str]
    groups: dict[int, str]
    warnings: list[str]


# --------------------------------------------------------------------------- #
# 校验 / 构建
# --------------------------------------------------------------------------- #
def _is_int(v: Any) -> bool:
    # bool 是 int 的子类，显式拒绝 true/false
    return isinstance(v, int) and not isinstance(v, bool)


def _parse_perms(v: Any, loc: list[str]) -> int:
    if _is_int(v):
        if 0 <= v <= 7:
            return int(v)
        raise SnapshotError("perms 为数字时必须在 0..7 之间", loc)
    if isinstance(v, str):
        s = v.strip()
        if len(s) != 3:
            raise SnapshotError("perms 字符串必须是 3 位 rwx 形式（如 r-x），无权限位写 -", loc)
        bits = 0
        for i, (ch, want, bit) in enumerate(zip(s, "rwx", (4, 2, 1))):
            if ch == want:
                bits |= bit
            elif ch != "-":
                raise SnapshotError(f"perms 第 {i + 1} 位只能是 {want} 或 -", loc)
        return bits
    raise SnapshotError("perms 必须是 rwx 三元组字符串或 0..7 的整数", loc)


def _parse_mode(v: Any, loc: list[str]) -> tuple[int, str]:
    raw: str
    if _is_int(v):
        n = int(v)
        if not 0 <= n <= 0o7777:
            raise SnapshotError("mode 整数必须在 0..0o7777 之间", loc)
        return n, format(n, "o")
    if isinstance(v, str):
        raw = v.strip()
        s = raw[1:] if raw.startswith("0o") or raw.startswith("0O") else raw
        if not (3 <= len(s) <= 4) or any(c not in "01234567" for c in s):
            raise SnapshotError("mode 必须是 3 或 4 位八进制字符串（如 0750 / 644）", loc)
        return int(s, 8), raw
    raise SnapshotError("mode 必须是八进制字符串或整数", loc)


def _parse_acl(value: Any, loc: list[str]) -> list[ACL_Entry]:
    if not isinstance(value, list):
        raise SnapshotError("acl 必须是数组", loc)
    entries: list[ACL_Entry] = []
    seen: set[tuple[str, Optional[int]]] = set()
    for i, raw_entry in enumerate(value):
        eloc = loc + [str(i)]
        if not isinstance(raw_entry, dict):
            raise SnapshotError("ACL 条目必须是对象", eloc)
        etype = raw_entry.get("type")
        if etype not in VALID_ACL_TYPES:
            raise SnapshotError(
                f"ACL type 必须是 {sorted(VALID_ACL_TYPES)} 之一", eloc + ["type"]
            )
        if "perms" not in raw_entry:
            raise SnapshotError("ACL 条目缺少 perms", eloc + ["perms"])
        perms = _parse_perms(raw_entry["perms"], eloc + ["perms"])
        entry = ACL_Entry(type=etype, perms=perms, raw=_perms_str(perms))

        if etype in VALID_QUAL_TYPES:
            if "qualifier" not in raw_entry:
                word = "UID" if etype == "user" else "GID"
                raise SnapshotError(
                    f"命名 {etype} 条目必须提供 qualifier（{word}）", eloc + ["qualifier"]
                )
            q = raw_entry["qualifier"]
            if not _is_int(q) or q < 0:
                raise SnapshotError("qualifier 必须是非负整数", eloc + ["qualifier"])
            entry.qualifier = int(q)
        elif "qualifier" in raw_entry and raw_entry["qualifier"] is not None:
            raise SnapshotError(f"{etype} 条目不能带 qualifier", eloc + ["qualifier"])

        key = (entry.type, entry.qualifier)
        if key in seen:
            raise SnapshotError(
                f"ACL 条目重复: {_acl_label(entry)}", eloc
            )
        seen.add(key)
        entries.append(entry)

    base = {e.type for e in entries}
    for required in ("user_obj", "group_obj", "other"):
        if required not in base:
            raise SnapshotError(
                f"ACL 缺少必需的基础条目 {required}（含 ACL 时须同时给出 user_obj/group_obj/other）",
                loc,
            )
    has_named = any(e.type in VALID_QUAL_TYPES for e in entries)
    if has_named and "mask" not in base:
        raise SnapshotError(
            "存在命名 user/group 条目时必须提供 mask（Linux 扩展 ACL）", loc
        )
    if "mask" in base and not has_named:
        # 仅 mask 而无命名条目：Linux 上 mask 只约束 group_obj，属于最小化 ACL，允许但提示
        pass
    if len(entries) > 64:
        raise SnapshotError("单个节点 ACL 条目过多（>64）", loc)
    return entries


def _parse_id_map(value: Any, key: str) -> dict[int, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise SnapshotError(f"{key} 必须是 ID -> 名称 的对象", [key])
    out: dict[int, str] = {}
    for k, v in value.items():
        try:
            nid = int(k)
        except (TypeError, ValueError):
            raise SnapshotError(f"{key} 的键必须是整数 ID 字符串", [key, str(k)])
        if nid < 0:
            raise SnapshotError(f"{key} 的 ID 不能为负", [key, str(k)])
        if not isinstance(v, str) or not v:
            raise SnapshotError(f"{key} 的值必须是非空字符串", [key, str(k)])
        out[nid] = v
    return out


def build_snapshot(data: Any) -> Snapshot:
    """把解析后的 JSON 对象校验并构建为 Snapshot，错误带定位 loc。"""
    if not isinstance(data, dict):
        raise SnapshotError("快照必须是 JSON 对象", [])
    if "nodes" not in data:
        raise SnapshotError("快照缺少 nodes 字段", ["nodes"])
    raw_nodes = data["nodes"]
    if not isinstance(raw_nodes, list):
        raise SnapshotError("nodes 必须是数组", ["nodes"])
    if not raw_nodes:
        raise SnapshotError("nodes 不能为空，至少需要根目录 /", ["nodes"])
    if len(raw_nodes) > MAX_NODES:
        raise SnapshotError(
            f"快照最多 {MAX_NODES} 个节点，当前 {len(raw_nodes)} 个", ["nodes"]
        )

    users = _parse_id_map(data.get("users"), "users")
    groups = _parse_id_map(data.get("groups"), "groups")

    nodes: dict[str, Node] = {}
    warnings: list[str] = []

    for i, rn in enumerate(raw_nodes):
        loc = ["nodes", str(i)]
        if not isinstance(rn, dict):
            raise SnapshotError("节点必须是 JSON 对象", loc)

        path = rn.get("path")
        if not isinstance(path, str) or not path:
            raise SnapshotError("节点 path 必须是非空字符串", loc + ["path"])
        if not path.startswith("/"):
            raise SnapshotError("节点 path 必须是绝对路径（以 / 开头）", loc + ["path"])
        if path != "/" and path.endswith("/"):
            raise SnapshotError("非根路径不能以 / 结尾", loc + ["path"])
        norm = posixpath.normpath(path)
        if norm != path:
            raise SnapshotError(
                f"path 必须是规范化路径，应写作 {norm!r}（不要包含 /./、// 或 / 结尾）",
                loc + ["path"],
            )
        if path in nodes:
            raise SnapshotError(f"路径 {path} 在快照中重复", loc + ["path"])

        ntype = rn.get("type")
        if ntype not in VALID_TYPES:
            raise SnapshotError(
                f"type 必须是 {sorted(VALID_TYPES)} 之一", loc + ["type"]
            )

        uid = rn.get("uid")
        if not _is_int(uid) or uid < 0:
            raise SnapshotError("uid 必须是非负整数", loc + ["uid"])
        gid = rn.get("gid")
        if not _is_int(gid) or gid < 0:
            raise SnapshotError("gid 必须是非负整数", loc + ["gid"])

        if "mode" not in rn:
            raise SnapshotError("节点缺少 mode", loc + ["mode"])
        mode, mode_raw = _parse_mode(rn["mode"], loc + ["mode"])

        acl = _parse_acl(rn["acl"], loc + ["acl"]) if "acl" in rn else []
        if acl and not any(e.type == "mask" for e in acl):
            # 最小化 ACL（仅基础三项）允许；有命名条目时上面已强制 mask
            pass
        if acl:
            go = next(e for e in acl if e.type == "group_obj")
            group_bits = (mode >> 3) & 7
            mask = next((e for e in acl if e.type == "mask"), None)
            eff = go.perms & (mask.perms if mask else 7)
            if eff != group_bits:
                warnings.append(
                    f"节点 {path}：mode 组权限 {_perms_str(group_bits)} 与 ACL 组有效权限 "
                    f"{_perms_str(eff)} 不一致，诊断以 ACL 为准（真实系统 getfacl 会同步重写 mode）"
                )

        link_target = None
        if ntype == "symlink":
            lt = rn.get("link_target")
            if not isinstance(lt, str) or not lt:
                raise SnapshotError(
                    "symlink 节点必须提供非空字符串 link_target", loc + ["link_target"]
                )
            if "\x00" in lt:
                raise SnapshotError("link_target 不能包含 NUL 字符", loc + ["link_target"])
            link_target = lt
        elif "link_target" in rn and rn["link_target"] is not None:
            raise SnapshotError("只有 symlink 节点才能带 link_target", loc + ["link_target"])

        nodes[path] = Node(
            path=path,
            type=ntype,
            uid=int(uid),
            gid=int(gid),
            mode=mode,
            mode_raw=mode_raw,
            acl=acl,
            link_target=link_target,
        )

    if "/" not in nodes:
        raise SnapshotError("快照必须包含根目录节点 /", ["nodes"])
    if nodes["/"].type != "directory":
        raise SnapshotError("根节点 / 的 type 必须是 directory", ["nodes", "0", "type"])

    # 父目录存在性（仅警告，运行时缺失会以 ENOENT/ENOTDIR 精确报出）
    for p, node in nodes.items():
        if p == "/":
            continue
        parent = posixpath.dirname(p) or "/"
        if parent not in nodes:
            warnings.append(f"节点 {p} 的父目录 {parent} 不在快照中，解析到此处会报路径缺失")
        elif nodes[parent].type != "directory":
            warnings.append(f"节点 {p} 的父路径 {parent} 不是目录，解析会报 ENOTDIR")

    return Snapshot(nodes=nodes, users=users, groups=groups, warnings=warnings)


def build_request(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise RequestError("请求必须是 JSON 对象", [])
    uid = data.get("uid")
    if not _is_int(uid) or uid <= 0:
        raise RequestError("uid 必须是非 0 正整数（无特权进程，root 不适用）", ["uid"])
    gid = data.get("gid")
    if not _is_int(gid) or gid < 0:
        raise RequestError("gid 必须是非负整数", ["gid"])
    groups = data.get("supp_groups", [])
    if not isinstance(groups, list) or not all(_is_int(g) and g >= 0 for g in groups):
        raise RequestError("supp_groups 必须是非负整数数组", ["supp_groups"])
    path = data.get("path")
    if not isinstance(path, str) or not path:
        raise RequestError("path 必须是非空字符串", ["path"])
    if not path.startswith("/"):
        raise RequestError("path 必须是绝对路径（以 / 开头）", ["path"])
    if "\x00" in path:
        raise RequestError("path 不能包含 NUL 字符", ["path"])
    return {
        "uid": int(uid),
        "gid": int(gid),
        "supp_groups": [int(g) for g in groups],
        "path": path,
    }


# --------------------------------------------------------------------------- #
# 权限判定（generic_permission + POSIX ACL）
# --------------------------------------------------------------------------- #
def _perms_str(bits: int) -> str:
    return "".join(ch if bits & b else "-" for ch, b in (("r", 4), ("w", 2), ("x", 1)))


def _mode_triple(mode: int, shift: int) -> int:
    return (mode >> shift) & 7


def _name_for(uid: Optional[int], mapping: dict[int, str]) -> str:
    if uid is None:
        return ""
    return mapping.get(uid, f"#{uid}")


def _acl_label(e: ACL_Entry) -> str:
    if e.type == "user_obj":
        return "user::" + _perms_str(e.perms)
    if e.type == "user":
        return f"user:{e.qualifier}:" + _perms_str(e.perms)
    if e.type == "group_obj":
        return "group::" + _perms_str(e.perms)
    if e.type == "group":
        return f"group:{e.qualifier}:" + _perms_str(e.perms)
    if e.type == "mask":
        return "mask::" + _perms_str(e.perms)
    return "other::" + _perms_str(e.perms)


def check_permission(
    node: Node,
    want: int,
    uid: int,
    gid: int,
    supp_groups: set[int],
    users: dict[int, str],
    groups: dict[int, str],
) -> dict[str, Any]:
    """
    返回 {granted, effective_perms, matched, considered, acl_used}。
    关键语义：
      1. 所有者永远走 user_obj（ACL 命名 user 条目不会匹配属主自己）；
      2. 命名 user 命中即终局（mask 约束），不退回 group/other；
      3. 任一匹配组的权限取并集后再与 mask；命中组即终局，不退回 other；
      4. 无任何组命中才走 other。
    """
    considered: list[dict[str, Any]] = []
    acl_used = bool(node.acl)

    def consider(
        kind: str,
        raw_bits: int,
        *,
        matched: bool,
        label: str,
        mask_bits: Optional[int] = None,
        qualifier: Optional[int] = None,
        qname: str = "",
    ) -> dict[str, Any]:
        effective = raw_bits if mask_bits is None else raw_bits & mask_bits
        item = {
            "kind": kind,
            "label": label,
            "matched_identity": matched,
            "raw_perms": _perms_str(raw_bits),
            "raw_bits": raw_bits,
            "effective_perms": _perms_str(effective),
            "effective_bits": effective,
        }
        if mask_bits is not None:
            item["mask_perms"] = _perms_str(mask_bits)
        if qualifier is not None:
            item["qualifier"] = qualifier
            if qname:
                item["qualifier_name"] = qname
        considered.append(item)
        return item

    # 1) 属主优先 -----------------------------------------------------------
    if uid == node.uid:
        if acl_used:
            uo = next(e for e in node.acl if e.type == "user_obj")
            item = consider(
                "acl_user_obj", uo.perms, matched=True,
                label=f"ACL user:({_name_for(node.uid, users)}):{_perms_str(uo.perms)} — 进程是属主",
                qualifier=node.uid, qname=_name_for(node.uid, users),
            )
        else:
            bits = _mode_triple(node.mode, 6)
            item = consider(
                "mode_owner", bits, matched=True,
                label=f"mode 属主位 {_perms_str(bits)} — 进程 UID {uid} == 属主 UID {node.uid}",
                qualifier=node.uid, qname=_name_for(node.uid, users),
            )
        return _result(item["effective_bits"], want, item, considered, acl_used)

    # 2) ACL 命名 user（属主不匹配后才可能到达） -----------------------------
    if acl_used:
        named_user = next(
            (e for e in node.acl if e.type == "user" and e.qualifier == uid), None
        )
        mask = next((e for e in node.acl if e.type == "mask"), None)
        if named_user is not None:
            item = consider(
                "acl_named_user", named_user.perms, matched=True,
                label=(
                    f"ACL user:{_name_for(uid, users)}:{_perms_str(named_user.perms)} 命中进程 UID {uid}"
                    + (f"，受 mask {_perms_str(mask.perms)} 约束" if mask else "")
                ),
                mask_bits=mask.perms if mask else None,
                qualifier=uid, qname=_name_for(uid, users),
            )
            # 命中即终局：绝不退回 other
            return _result(item["effective_bits"], want, item, considered, acl_used)
        # 未命中的命名 user 也记录，便于展示“查过但不匹配”
        for e in node.acl:
            if e.type == "user":
                consider(
                    "acl_named_user", e.perms, matched=False,
                    label=f"ACL user:{_name_for(e.qualifier, users)} 不匹配进程 UID {uid}",
                    mask_bits=mask.perms if mask else None,
                    qualifier=e.qualifier, qname=_name_for(e.qualifier, users),
                )

    # 3) 组：文件组 + 所有命名组，命中身份取并集，再统一受 mask ---------------
    group_matches: list[ACL_Entry] = []
    group_checked: list[ACL_Entry] = []
    if acl_used:
        mask = next((e for e in node.acl if e.type == "mask"), None)
        go = next(e for e in node.acl if e.type == "group_obj")
        group_checked.append(go)
        if gid == node.gid or node.gid in supp_groups:
            group_matches.append(go)
        for e in node.acl:
            if e.type == "group":
                group_checked.append(e)
                if e.qualifier == gid or e.qualifier in supp_groups:
                    group_matches.append(e)

        if group_matches:
            union = 0
            for e in group_matches:
                union |= e.perms
            mask_bits = mask.perms if mask else 7
            labels = []
            for e in group_matches:
                if e.type == "group_obj":
                    labels.append(
                        f"ACL group:({_name_for(node.gid, groups)}):{_perms_str(e.perms)}（主组/附加组命中文件 GID {node.gid}）"
                    )
                else:
                    labels.append(
                        f"ACL group:{_name_for(e.qualifier, groups)}:{_perms_str(e.perms)}（命中 GID {e.qualifier}）"
                    )
            item = consider(
                "acl_group_union", union, matched=True,
                label="匹配组权限并集 " + _perms_str(union)
                      + (f"，受 mask {_perms_str(mask_bits)} 约束 → {_perms_str(union & mask_bits)}"
                         if mask else "")
                      + "；命中即终局，不退回 other｜" + "；".join(labels),
                mask_bits=mask_bits,
            )
            return _result(item["effective_bits"], want, item, considered, acl_used)

        # 记录查过但没命中的组项
        for e in group_checked:
            if e.type == "group_obj":
                consider(
                    "acl_group_obj", e.perms, matched=False,
                    label=f"ACL group:({_name_for(node.gid, groups)}) 不匹配进程任何 GID",
                    mask_bits=mask.perms if mask else None,
                    qualifier=node.gid, qname=_name_for(node.gid, groups),
                )
            else:
                consider(
                    "acl_named_group", e.perms, matched=False,
                    label=f"ACL group:{_name_for(e.qualifier, groups)} 不匹配进程任何 GID",
                    mask_bits=mask.perms if mask else None,
                    qualifier=e.qualifier, qname=_name_for(e.qualifier, groups),
                )
    else:
        # 经典 mode 组
        bits = _mode_triple(node.mode, 3)
        matched = gid == node.gid or node.gid in supp_groups
        item = consider(
            "mode_group", bits, matched=matched,
            label=(
                f"mode 组位 {_perms_str(bits)} — 进程 GID 集合命中文件 GID {node.gid}"
                if matched else
                f"mode 组位 {_perms_str(bits)} — 文件 GID {node.gid} 不在进程组集合中"
            ),
            qualifier=node.gid, qname=_name_for(node.gid, groups),
        )
        if matched:
            return _result(item["effective_bits"], want, item, considered, acl_used)

    # 4) other（前面全部未命中身份才到达） -----------------------------------
    if acl_used:
        ot = next(e for e in node.acl if e.type == "other")
        item = consider(
            "acl_other", ot.perms, matched=True,
            label=f"ACL other:{_perms_str(ot.perms)} — 属主与所有组条目均未命中，落入 other",
        )
    else:
        bits = _mode_triple(node.mode, 0)
        item = consider(
            "mode_other", bits, matched=True,
            label=f"mode other 位 {_perms_str(bits)} — 属主/组均未命中",
        )
    return _result(item["effective_bits"], want, item, considered, acl_used)


def _result(
    effective_bits: int,
    want: int,
    matched: dict[str, Any],
    considered: list[dict[str, Any]],
    acl_used: bool,
) -> dict[str, Any]:
    missing = want & ~effective_bits
    return {
        "granted": missing == 0,
        "effective_bits": effective_bits,
        "effective_perms": _perms_str(effective_bits),
        "wanted_bits": want,
        "wanted_perms": _perms_str(want),
        "missing_bits": missing,
        "matched": matched,
        "considered": considered,
        "acl_used": acl_used,
    }
