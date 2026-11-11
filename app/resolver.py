"""
Linux namei 风格的路径解析（完全基于快照，不触碰宿主文件系统）。

规则要点：
* 每个目录在被用于查找/穿越组件前做一次 search(x) 检查，EACCES 优先于 ENOENT；
* 软链接：相对目标按链接所在目录拼接，绝对目标从 "/" 重新展开；
* 不做词法 ".." 折叠——".." 回退到 cwd 的物理父目录（软链接场景与 naive 规范化不同）；
* 最多跟随 40 个软链接，第 41 次返回 ELOOP；
* 最终节点不是普通文件时，区分 ENOTDIR（中间组件不是目录）与最终非普通文件。
"""

from __future__ import annotations

import posixpath
from typing import Any, Optional

from .engine import (
    MAX_SYMLINKS,
    Node,
    Snapshot,
    check_permission,
)

# 结果分类 -> 对外稳定错误码
CATEGORY = {
    "EACCES": "permission_denied",
    "ENOENT": "path_missing",
    "ELOOP": "link_limit_exceeded",
    "ENOTDIR": "not_regular",
    "ENOTREG": "not_regular",
}


class DiagError(Exception):
    def __init__(self, errno: str, message: str, step: dict[str, Any]):
        super().__init__(message)
        self.errno = errno
        self.message = message
        self.step = step


def _split_components(path: str) -> list[str]:
    # 保留 "." 与 ".."；连续 "/" 产生的空串丢弃
    return [c for c in path.split("/") if c != ""]


def _join(base_dir: str, target: str) -> str:
    if target.startswith("/"):
        return target
    if base_dir == "/":
        return "/" + target
    return base_dir + "/" + target


def _node_brief(node: Node, snap: Snapshot) -> dict[str, Any]:
    return {
        "path": node.path,
        "type": node.type,
        "uid": node.uid,
        "gid": node.gid,
        "mode": node.mode_raw,
        "owner_name": snap.users.get(node.uid),
        "group_name": snap.groups.get(node.gid),
        "has_acl": bool(node.acl),
        "link_target": node.link_target,
    }


def _perm_step(
    node: Node,
    want: int,
    req: dict[str, Any],
    snap: Snapshot,
    *,
    purpose: str,
    component: Optional[str],
    cwd: str,
) -> dict[str, Any]:
    decision = check_permission(
        node,
        want,
        req["uid"],
        req["gid"],
        set([req["gid"], *req["supp_groups"]]),
        snap.users,
        snap.groups,
    )
    want_label = "搜索(x)" if want == 1 else "读取(r)"
    return {
        "kind": "permission_check",
        "ok": decision["granted"],
        "title": f"检查 {node.path} 的{want_label}权限（{purpose}）",
        "detail": (
            f"进程 uid={req['uid']} gid={req['gid']} "
            f"groups={sorted(set([req['gid'], *req['supp_groups']]))}；"
            f"采用权限项：{decision['matched']['label']}；"
            f"需要 {decision['wanted_perms']}，有效权限 {decision['effective_perms']}"
        ),
        "cwd": cwd,
        "component": component,
        "node": _node_brief(node, snap),
        "want": want_label,
        "decision": decision,
    }


def diagnose(snap: Snapshot, req: dict[str, Any]) -> dict[str, Any]:
    """执行完整诊断，返回结构化结果（含 steps 与 adopted 权限项）。"""
    steps: list[dict[str, Any]] = []
    follows = 0
    cwd = "/"  # 物理绝对路径
    stack = _split_components(req["path"])
    trailing_slash = len(req["path"]) > 1 and req["path"].endswith("/")
    # 已通过 search 检查的目录（同一次解析中不重复检查；软链接回到旧目录也已放行过）
    searched: set[str] = set()

    steps.append({
        "kind": "start",
        "ok": True,
        "title": "开始解析绝对路径",
        "detail": f"请求路径 {req['path']}，从根目录 / 出发（无特权进程，cap_dac_override 无效）",
        "cwd": cwd,
        "symlink_follows": follows,
    })

    def require_search(dir_node: Node, component: Optional[str], purpose: str) -> None:
        if dir_node.path in searched:
            return
        step = _perm_step(
            dir_node, 1, req, snap,
            purpose=purpose, component=component, cwd=cwd,
        )
        steps.append(step)
        if not step["decision"]["granted"]:
            raise DiagError(
                "EACCES",
                f"目录 {dir_node.path} 缺少搜索(x)权限：{step['decision']['matched']['label']}，"
                f"有效权限 {step['decision']['effective_perms']} 不含 x",
                step,
            )
        searched.add(dir_node.path)

    final_node: Optional[Node] = None

    try:
        # 根路径 "/"：组件栈为空，最终节点就是根目录
        if not stack:
            final_node = snap.nodes["/"]
            require_search(final_node, None, "访问根目录 /")
        while stack:
            comp = stack.pop(0)
            cur_dir = snap.nodes[cwd]
            # 任何组件（含 . 与 ..）都要求当前目录可搜索；EACCES 先于 ENOENT
            require_search(cur_dir, comp, f"在 {cwd} 中解析组件 {comp}")

            if comp == ".":
                steps.append({
                    "kind": "traverse", "ok": True,
                    "title": "组件 . 保持在当前目录", "detail": f"cwd 仍为 {cwd}",
                    "cwd": cwd, "component": comp,
                })
                continue

            if comp == "..":
                parent = posixpath.dirname(cwd) or "/"
                steps.append({
                    "kind": "parent", "ok": True,
                    "title": "物理回退到父目录（不做词法折叠）",
                    "detail": f"{cwd}/.. -> {parent}"
                              + ("（根目录的父目录仍是自身）" if cwd == "/" else ""),
                    "cwd": parent, "component": comp,
                })
                cwd = parent
                continue

            # 普通组件：当前 cwd 已通过 search，直接查找
            candidate = _join(cwd, comp)
            node = snap.nodes.get(candidate)

            if node is None:
                step = {
                    "kind": "error", "ok": False,
                    "title": f"路径缺失：{candidate} 不在快照中",
                    "detail": f"目录 {cwd} 已通过搜索检查，但其中没有名为 {comp} 的条目",
                    "cwd": cwd, "component": comp, "errno": "ENOENT",
                }
                steps.append(step)
                raise DiagError("ENOENT", f"路径 {candidate} 不存在（快照中无此节点）", step)

            if node.type == "symlink":
                follows += 1
                if follows > MAX_SYMLINKS:
                    step = {
                        "kind": "error", "ok": False,
                        "title": f"软链接跟随次数超过上限 {MAX_SYMLINKS}",
                        "detail": (
                            f"第 {follows} 次遇到软链接 {node.path} -> {node.link_target}；"
                            f"Linux MAXSYMLINKS={MAX_SYMLINKS}，返回 ELOOP"
                        ),
                        "cwd": cwd, "component": comp, "errno": "ELOOP",
                        "symlink_follows": follows,
                    }
                    steps.append(step)
                    raise DiagError("ELOOP", f"软链接层级超过 {MAX_SYMLINKS}（ELOOP）", step)

                target = node.link_target
                if target.startswith("/"):
                    new_cwd = "/"
                    detail = f"绝对目标，从根重新展开：{target}"
                else:
                    new_cwd = cwd
                    detail = (f"相对目标，按链接所在目录 {cwd} 展开："
                              f"{cwd if cwd == '/' else cwd + '/'}{target}")
                target_components = _split_components(target)
                steps.append({
                    "kind": "symlink", "ok": True,
                    "title": f"展开软链接 {node.path}（第 {follows}/{MAX_SYMLINKS} 次）",
                    "detail": detail,
                    "cwd": new_cwd, "component": comp,
                    "link_path": node.path, "link_target": target,
                    "remaining_after_expand": target_components + stack,
                    "symlink_follows": follows,
                })
                # 替换当前组件为目标组件序列；下一轮循环会按需检查 new_cwd 的 search
                stack = target_components + stack
                cwd = new_cwd
                continue

            # 非链接节点
            if stack:
                # 还有后续组件：当前节点必须是目录
                if node.type != "directory":
                    step = {
                        "kind": "error", "ok": False,
                        "title": f"中间组件 {node.path} 不是目录",
                        "detail": f"该节点类型为 {node.type}，无法继续穿越（ENOTDIR）",
                        "cwd": cwd, "component": comp, "errno": "ENOTDIR",
                        "node": _node_brief(node, snap),
                    }
                    steps.append(step)
                    raise DiagError(
                        "ENOTDIR",
                        f"路径组件 {node.path} 不是目录，无法继续解析（ENOTDIR）", step
                    )
                steps.append({
                    "kind": "traverse", "ok": True,
                    "title": f"进入目录 {node.path}",
                    "detail": f"组件 {comp} 解析为目录，cwd {cwd} -> {node.path}",
                    "cwd": node.path, "component": comp,
                    "node": _node_brief(node, snap),
                })
                cwd = node.path
            else:
                final_node = node

        # 栈空：拿到最终节点
        if trailing_slash and final_node.type != "directory":
            step = {
                "kind": "error", "ok": False,
                "title": f"路径以 / 结尾但 {final_node.path} 不是目录",
                "detail": f"实际类型为 {final_node.type}（ENOTDIR）",
                "cwd": cwd, "errno": "ENOTDIR",
                "node": _node_brief(final_node, snap),
            }
            steps.append(step)
            raise DiagError("ENOTDIR", f"{final_node.path} 不是目录但路径以 / 结尾（ENOTDIR）", step)

        if final_node.type != "file":
            step = {
                "kind": "error", "ok": False,
                "title": f"目标 {final_node.path} 不是普通文件（type={final_node.type}）",
                "detail": "读取请求只对普通文件成立；目录/设备/FIFO/套接字等走 open(O_RDONLY) 语义不同",
                "cwd": cwd, "errno": "ENOTREG",
                "node": _node_brief(final_node, snap),
            }
            steps.append(step)
            raise DiagError(
                "ENOTREG",
                f"目标存在但类型为 {final_node.type}，不是普通文件，无法按普通文件读取", step
            )

        # 最终普通文件：检查 r
        rstep = _perm_step(
            final_node, 4, req, snap,
            purpose="打开普通文件 O_RDONLY", component=None, cwd=cwd,
        )
        steps.append(rstep)
        if not rstep["decision"]["granted"]:
            raise DiagError(
                "EACCES",
                f"文件 {final_node.path} 缺少读取(r)权限：{rstep['decision']['matched']['label']}，"
                f"有效权限 {rstep['decision']['effective_perms']} 不含 r",
                rstep,
            )

        steps.append({
            "kind": "done", "ok": True,
            "title": f"读取放行：open({final_node.path}, O_RDONLY) 成功",
            "detail": f"全程 {follows} 次软链接，所有目录 search 与文件 read 检查均通过",
            "cwd": cwd, "symlink_follows": follows,
        })

        return {
            "readable": True,
            "category": "ok",
            "errno": None,
            "message": "允许读取：路径存在、为普通文件，且沿途目录 x 与文件 r 权限全部满足",
            "final_node": _node_brief(final_node, snap),
            "symlink_follows": follows,
            "steps": steps,
            "adopted": rstep["decision"],
            "first_failure": None,
        }

    except DiagError as exc:
        return {
            "readable": False,
            "category": CATEGORY[exc.errno],
            "errno": exc.errno,
            "message": exc.message,
            "final_node": _node_brief(final_node, snap) if final_node else None,
            "symlink_follows": follows,
            "steps": steps,
            "adopted": exc.step.get("decision"),
            "first_failure": {
                "errno": exc.errno,
                "category": CATEGORY[exc.errno],
                "message": exc.message,
                "step_index": len(steps) - 1,
                "step_title": exc.step.get("title"),
                "cwd": exc.step.get("cwd"),
                "component": exc.step.get("component"),
            },
        }
