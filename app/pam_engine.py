"""
PAM 认证栈离线分析引擎（仅分析 auth 管理组，不加载任何模块）。

本模块 *不* 访问宿主机文件系统、也不 dlopen PAM 模块：所有 /etc/pam.d 配置与
每个模块行的返回码都由浏览器提交。模块返回值被限制在四种可观察结果：

    success(0) / auth_err(7) / user_unknown(10) / ignore(25)

控制流语义严格对齐 Linux-PAM 上游源码（libpam/pam_dispatch.c、pam_misc.c、
pam_tokens.h、pam_handlers.c）：

* 简单控制 required/requisite/sufficient/optional 按上游固定动作表展开；
* 方括号控制 value=action 仅接受 ignore/ok/bad/done/die/reset 与正整数跳转，
  支持 default；
* ok/bad 的累计遵循“首个结果优先”（impression/status 双变量）；
* reset 恢复进入当前栈级（substack）时保存的状态；顶层 reset 恢复初始边界；
* done/die 只终止当前栈级，父级继续把 substack 结果按 required 语义回并；
* 跳转以“同一栈级的下一个处理单元”为单位，整个 substack 算一个单位；
  跳过栈尾仍有余数即 bad jump（PAM_MUST_FAIL_CODE）；
* include 仅做文本展开（无状态隔离），substack 有独立状态边界。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
MAX_FILES = 8
MAX_LINES = 60
PAM_SUBSTACK_MAX_LEVEL = 32  # 上游 PAM_SUBSTACK_MAX_LEVEL

# 允许人工填写的模块返回码（PAM 整数码见 pam_tokens.h）
RETURN_VALUES: dict[str, int] = {
    "success": 0,       # PAM_SUCCESS
    "auth_err": 7,      # PAM_AUTH_ERR
    "user_unknown": 10,  # PAM_USER_UNKNOWN
    "ignore": 25,       # PAM_IGNORE
}
RETURN_NAMES: dict[int, str] = {v: k for k, v in RETURN_VALUES.items()}

# 动作编码（负值=命名动作，正值=向前跳转 N 个单元，0=ignore），与上游一致
ACT_IGNORE = 0
ACT_OK = -1
ACT_DONE = -2
ACT_BAD = -3
ACT_DIE = -4
ACT_RESET = -5
ACTION_NAMES = {
    ACT_IGNORE: "ignore",
    ACT_OK: "ok",
    ACT_DONE: "done",
    ACT_BAD: "bad",
    ACT_DIE: "die",
    ACT_RESET: "reset",
}
NAMED_ACTIONS: dict[str, int] = {v: k for k, v in ACTION_NAMES.items()}

SIMPLE_CONTROLS = {"required", "requisite", "sufficient", "optional"}
BRACKET_ACTIONS = {"ignore", "ok", "bad", "done", "die", "reset"}

# 上游 pam_handlers.c 中简单控制对应的固定动作表（只列本工具支持的 4 种返回码；
# default 行兜底其余返回码）。
SIMPLE_CONTROL_TABLE: dict[str, dict[str, Any]] = {
    # required: 成功 ok，ignore 透传，其余失败但继续
    "required": {"success": ACT_OK, "ignore": ACT_IGNORE, "default": ACT_BAD},
    # requisite: 成功 ok，ignore 透传，其余立即 die
    "requisite": {"success": ACT_OK, "ignore": ACT_IGNORE, "default": ACT_DIE},
    # optional: 成功 ok，其余（含失败）忽略
    "optional": {"success": ACT_OK, "default": ACT_IGNORE},
    # sufficient: 成功立即 done，其余忽略
    "sufficient": {"success": ACT_DONE, "default": ACT_IGNORE},
}

# 初始/兜底失败码。上游 _pam_dispatch_aux 以 PAM_PERM_DENIED 初始化 status；
# 对外统一用四值模型表达为 auth_err。
INITIAL_STATUS = "auth_err"


class PamConfigError(ValueError):
    """配置/输入非法或分析期不可恢复错误，loc 指向出错位置。"""

    def __init__(self, message: str, loc: Optional[list[str]] = None):
        super().__init__(message)
        self.message = message
        self.loc = loc or []


# --------------------------------------------------------------------------- #
# 数据模型
# --------------------------------------------------------------------------- #
@dataclass
class PamLine:
    """一条参与 auth 分析的有效配置行（空行/注释/非 auth 行不产生 PamLine）。"""

    file: str
    line_no: int          # 物理行号（1 起，续行指向起始行）
    raw: str
    kind: str             # module | include | substack
    control_raw: str
    actions: dict[int, int] = field(default_factory=dict)  # 返回码整数 -> 动作
    module: Optional[str] = None
    args: list[str] = field(default_factory=list)
    target: Optional[str] = None      # include/substack 目标文件名
    # 执行期填充
    unit_index: int = -1              # 扁平后在所属文件单元序列中的下标


@dataclass
class PamFile:
    name: str
    content: str
    lines: list[PamLine] = field(default_factory=list)   # 仅 auth 有效行
    skipped: list[dict[str, Any]] = field(default_factory=list)  # 非 auth/空/注释行


# --------------------------------------------------------------------------- #
# 输入校验与构建
# --------------------------------------------------------------------------- #
def _loc(*parts: str) -> list[str]:
    return list(parts)


def build_payload(data: Any) -> tuple[str, dict[str, PamFile], dict[tuple[str, int], str]]:
    """
    校验浏览器提交的 JSON，返回 (入口服务名, {文件名: PamFile}, 返回码映射)。
    返回码映射键为 (文件名, 物理行号)，值为四值之一。
    """
    if not isinstance(data, dict):
        raise PamConfigError("请求体必须是 JSON 对象", [])

    entry = data.get("entry")
    if not isinstance(entry, str) or not entry.strip():
        raise PamConfigError("入口服务 entry 必须是非空字符串（如 sshd）", ["entry"])
    entry = entry.strip()
    if "\x00" in entry or "/" in entry or entry.startswith("."):
        raise PamConfigError(
            "入口服务名必须是 /etc/pam.d 下的纯文件名（不能含 / 或以 . 开头）", ["entry"]
        )

    raw_files = data.get("files")
    if not isinstance(raw_files, list) or not raw_files:
        raise PamConfigError("files 必须是非空数组（最多 %d 份配置）" % MAX_FILES, ["files"])
    if len(raw_files) > MAX_FILES:
        raise PamConfigError(
            f"最多提交 {MAX_FILES} 份 /etc/pam.d 配置，当前 {len(raw_files)} 份", ["files"]
        )

    files: dict[str, PamFile] = {}
    for i, rf in enumerate(raw_files):
        floc = _loc("files", str(i))
        if not isinstance(rf, dict):
            raise PamConfigError("每个配置项必须是对象", floc)
        name = rf.get("name")
        if not isinstance(name, str) or not name.strip():
            raise PamConfigError("配置 name 必须是非空字符串", floc + ["name"])
        name = name.strip()
        if "/" in name or name.startswith(".") or "\x00" in name:
            raise PamConfigError(
                "配置 name 必须是 /etc/pam.d 下的纯文件名（不能含 / 或以 . 开头）",
                floc + ["name"],
            )
        if name in files:
            raise PamConfigError(f"配置文件名 {name} 重复", floc + ["name"])
        content = rf.get("content")
        if not isinstance(content, str):
            raise PamConfigError("配置 content 必须是字符串", floc + ["content"])
        physical = content.split("\n")
        if len(physical) > MAX_LINES:
            raise PamConfigError(
                f"配置 {name} 共 {len(physical)} 行，超过单文件 {MAX_LINES} 行上限",
                floc + ["content"],
            )
        files[name] = _parse_file(name, content, floc)

    if entry not in files:
        raise PamConfigError(
            f"入口服务 {entry} 不在已提交的 {len(files)} 份配置中（files.name 列表："
            f"{sorted(files)}）",
            ["entry"],
        )

    # ---- 返回码映射 -------------------------------------------------------
    raw_returns = data.get("returns")
    if not isinstance(raw_returns, list):
        raise PamConfigError("returns 必须是数组", ["returns"])
    returns: dict[tuple[str, int], str] = {}
    for i, rr in enumerate(raw_returns):
        rloc = _loc("returns", str(i))
        if not isinstance(rr, dict):
            raise PamConfigError("每个返回码项必须是对象", rloc)
        fname = rr.get("file")
        if not isinstance(fname, str) or not fname.strip():
            raise PamConfigError("返回码项缺少 file（配置文件名）", rloc + ["file"])
        fname = fname.strip()
        if fname not in files:
            raise PamConfigError(
                f"返回码项引用的文件 {fname} 不在 files 中", rloc + ["file"]
            )
        line_no = rr.get("line")
        if not isinstance(line_no, int) or isinstance(line_no, bool) or line_no < 1:
            raise PamConfigError("返回码项 line 必须是 ≥1 的整数行号", rloc + ["line"])
        value = rr.get("return")
        if not isinstance(value, str) or value not in RETURN_VALUES:
            raise PamConfigError(
                f"返回码 return 必须是 {sorted(RETURN_VALUES)} 之一", rloc + ["return"]
            )
        key = (fname, line_no)
        if key in returns:
            raise PamConfigError(
                f"返回码项重复：{fname}:{line_no} 只能填写一次", rloc
            )
        returns[key] = value

    # ---- 引用完整性：缺失引用 / 循环 / 嵌套深度（分析前一次性预校验）---------
    _validate_references(entry, files)

    # ---- 返回码行合法性：越界行、非模块行 -----------------------------------
    for fname, pf in files.items():
        max_line = len(pf.content.split("\n"))
        module_lines = {pl.line_no for pl in pf.lines if pl.kind == "module"}
        for (rf_name, ln), _val in returns.items():
            if rf_name != fname:
                continue
            if ln > max_line:
                raise PamConfigError(
                    f"返回码项 {fname}:{ln} 超出该文件物理行数（共 {max_line} 行）",
                    ["returns"],
                )
            if ln not in module_lines:
                raise PamConfigError(
                    f"返回码项 {fname}:{ln} 不是 auth 模块行（只能为模块行填写返回码；"
                    f"include/substack、空行、注释与非 auth 行不需要）",
                    ["returns"],
                )

    # ---- 每个模块行都必须有返回码 -------------------------------------------
    for fname, pf in files.items():
        for pl in pf.lines:
            if pl.kind == "module" and (fname, pl.line_no) not in returns:
                raise PamConfigError(
                    f"模块行 {fname}:{pl.line_no} 缺少模块返回码（returns 中必须为 "
                    f"{pl.module} 填写 success/auth_err/user_unknown/ignore 之一）",
                    ["returns"],
                )

    return entry, files, returns


def _validate_references(entry: str, files: dict[str, PamFile]) -> None:
    """遍历引用图，定位缺失引用、循环引用与过深嵌套。"""

    def walk(fname: str, chain: list[tuple[str, str]], depth: int) -> None:
        for pl in files[fname].lines:
            if pl.kind not in ("include", "substack"):
                continue
            target = pl.target
            if target not in files:
                raise PamConfigError(
                    f"{fname}:{pl.line_no} 的 {pl.kind} 引用了未提交的配置 "
                    f"/etc/pam.d/{target}（缺失引用，无法离线分析）",
                    ["files"],
                )
            if any(f == target for f, _ in chain):
                cycle = " -> ".join([f for f, _ in chain] + [target])
                raise PamConfigError(
                    f"检测到 PAM 引用循环：{cycle}（由 {fname}:{pl.line_no} 的 "
                    f"{pl.kind} 触发），Linux-PAM 会嵌套到上限后失败",
                    ["files"],
                )
            if depth + 1 > PAM_SUBSTACK_MAX_LEVEL:
                raise PamConfigError(
                    f"include/substack 嵌套深度超过 {PAM_SUBSTACK_MAX_LEVEL} 层上限",
                    ["files"],
                )
            walk(target, chain + [(target, pl.kind)], depth + 1)

    walk(entry, [(entry, "entry")], 0)


# --------------------------------------------------------------------------- #
# 配置行解析
# --------------------------------------------------------------------------- #
def _join_continuations(physical: list[str]) -> list[tuple[int, str]]:
    """
    处理反斜杠续行：返回 [(起始物理行号, 合并后文本)]。
    空行/纯注释行保留为 (行号, "")，便于 skipped 展示与行号校验。
    """
    out: list[tuple[int, str]] = []
    buf = ""
    start = 1
    # 尾部单个换行（文件以 \n 结尾）不应产生额外的空物理行
    physical = physical[:-1] if len(physical) > 1 and physical[-1] == "" else physical
    for idx, line in enumerate(physical, start=1):
        stripped = line.rstrip("\r")
        if buf:
            if stripped.endswith("\\"):
                buf += " " + stripped[:-1].strip()
            else:
                buf += " " + stripped.strip()
                out.append((start, buf))
                buf = ""
            continue
        if stripped.endswith("\\") and stripped.strip() != "\\":
            buf = stripped[:-1].strip()
            start = idx
        else:
            out.append((idx, stripped.strip()))
    if buf:  # 尾部悬空续行：按一行处理
        out.append((start, buf))
    return out


def _parse_bracket_control(text: str, loc: list[str]) -> dict[int, int]:
    """解析 [value=action ...] 方括号控制（容忍等号两侧任意空白）。"""
    inner = text.strip()
    if not (inner.startswith("[") and inner.endswith("]")) or len(inner) < 2:
        raise PamConfigError(
            "方括号控制必须形如 [success=ok default=bad]，以 [ 开头、] 结尾", loc
        )
    body = inner[1:-1].strip()
    if not body:
        raise PamConfigError("方括号控制内容为空", loc)

    # 逐段匹配：返回值(default 或四值之一) = 动作(命名动作或正整数)
    ret_alt = "default|" + "|".join(sorted(RETURN_VALUES, key=len, reverse=True))
    act_alt = "|".join(sorted(BRACKET_ACTIONS, key=len, reverse=True))
    pattern = re.compile(
        rf"({ret_alt})\s*=\s*({act_alt}|\d+)"
    )
    actions: dict[int, int] = {}
    default_action: Optional[int] = None
    pos = 0
    while pos < len(body):
        m = pattern.match(body, pos)
        if not m:
            raise PamConfigError(
                f"方括号片段 {body[pos:].strip()!r} 非法：必须是 返回值=动作"
                f"（返回值支持 default/{'/'.join(sorted(RETURN_VALUES))}，"
                f"动作支持 {'/'.join(sorted(BRACKET_ACTIONS))} 或正整数跳转）",
                loc,
            )
        ret_tok, act_tok = m.group(1), m.group(2)
        action = _parse_action_token(act_tok, loc)
        if ret_tok == "default":
            if default_action is not None:
                raise PamConfigError("default 在同一方括号控制中重复", loc)
            # 仅记录，最后才物化（上游 _pam_set_default_control 只填未设置项），
            # 因此其后出现的显式返回值仍可覆盖默认动作
            default_action = action
        else:
            code = RETURN_VALUES[ret_tok]
            if code in actions:
                raise PamConfigError(f"返回值 {ret_tok} 在同一方括号控制中重复", loc)
            actions[code] = action
        pos = m.end()
        # 跳过段间空白
        while pos < len(body) and body[pos].isspace():
            pos += 1
    # default 只填充未显式给出的返回值；完全未给 default 时按上游默认 bad
    fallback = ACT_BAD if default_action is None else default_action
    for code in RETURN_VALUES.values():
        actions.setdefault(code, fallback)
    return actions


def _parse_action_token(act_tok: str, loc: list[str]) -> int:
    if act_tok in NAMED_ACTIONS:
        return NAMED_ACTIONS[act_tok]
    if act_tok.isdigit():
        n = int(act_tok)
        if n <= 0:
            raise PamConfigError("跳转动作必须是正整数（0 跳转非法，等价语义用 ignore）", loc)
        return n
    raise PamConfigError(
        f"动作 {act_tok!r} 非法：仅支持 {sorted(BRACKET_ACTIONS)} 或正整数跳转", loc
    )


def _parse_file(name: str, content: str, floc: list[str]) -> PamFile:
    pf = PamFile(name=name, content=content)
    physical = content.split("\n")
    for line_no, text in _join_continuations(physical):
        if not text or text.startswith("#"):
            pf.skipped.append(
                {"file": name, "line": line_no, "raw": text, "reason": "空行或注释"}
            )
            continue

        tokens = text.split()
        # @include 旧式语法
        if tokens[0] == "@include":
            if len(tokens) != 2:
                raise PamConfigError(
                    f"{name}:{line_no} 的 @include 必须且只能带一个目标文件名",
                    floc + ["content", str(line_no)],
                )
            pf.lines.append(
                PamLine(name, line_no, text, "include", "include", target=tokens[1])
            )
            continue

        # 允许前导 '-'（不记录模块加载失败），解析时剥除
        if tokens[0].startswith("-") and tokens[0] != "-":
            tokens[0] = tokens[0][1:]
        elif tokens[0] == "-":
            tokens = tokens[1:]
            if not tokens:
                raise PamConfigError(
                    f"{name}:{line_no} 缺少模块类型", floc + ["content", str(line_no)]
                )

        if len(tokens) < 2:
            raise PamConfigError(
                f"{name}:{line_no} 配置行至少需要 类型 + 控制/目标 两列",
                floc + ["content", str(line_no)],
            )

        mtype = tokens[0]
        if mtype != "auth":
            pf.skipped.append(
                {
                    "file": name,
                    "line": line_no,
                    "raw": text,
                    "reason": f"非 auth 管理组（{mtype}），本工具仅分析 auth",
                }
            )
            continue

        # 方括号控制内部允许空格（对齐上游 _pam_tokenize 的 [ ] 分组）：
        # 从第 2 列起，把以 [ 开头、到以 ] 结尾的若干 token 重组为一个控制串。
        if tokens[1].startswith("[") and not tokens[1].endswith("]"):
            control_parts = [tokens[1]]
            end = 2
            while end < len(tokens) and not control_parts[-1].endswith("]"):
                control_parts.append(tokens[end])
                end += 1
            if not control_parts[-1].endswith("]"):
                raise PamConfigError(
                    f"{name}:{line_no} 方括号控制缺少闭合的 ]",
                    floc + ["content", str(line_no)],
                )
            control = " ".join(control_parts)
            rest = tokens[end:]
        else:
            control = tokens[1]
            rest = tokens[2:]
        loc = floc + ["content", str(line_no)]

        if control.startswith("["):
            actions = _parse_bracket_control(control, loc)
        elif control in ("include", "substack"):
            if len(rest) < 1:
                raise PamConfigError(
                    f"{name}:{line_no} 的 {control} 缺少目标文件名", loc
                )
            if len(rest) > 1:
                raise PamConfigError(
                    f"{name}:{line_no} 的 {control} 不能带额外参数", loc
                )
            pf.lines.append(
                PamLine(name, line_no, text, control, control, target=rest[0])
            )
            continue
        elif control in SIMPLE_CONTROLS:
            table = SIMPLE_CONTROL_TABLE[control]
            actions = {}
            default_act = table["default"]
            for rn, code in RETURN_VALUES.items():
                actions[code] = table.get(rn, default_act)
        else:
            raise PamConfigError(
                f"{name}:{line_no} 控制字段 {control!r} 非法：必须是 "
                f"{sorted(SIMPLE_CONTROLS)}、include/substack 或方括号控制",
                loc,
            )

        if not rest:
            raise PamConfigError(
                f"{name}:{line_no} 缺少模块名（auth 行第三列）", loc
            )
        pf.lines.append(
            PamLine(
                file=name,
                line_no=line_no,
                raw=text,
                kind="module",
                control_raw=control,
                actions=actions,
                module=rest[0],
                args=rest[1:],
            )
        )
    return pf


# --------------------------------------------------------------------------- #
# 执行期数据结构
# --------------------------------------------------------------------------- #
@dataclass
class Unit:
    """扁平执行单元：模块调用、include 边界或 substack（含子单元列表）。"""

    kind: str                 # module | substack
    line: PamLine
    children: list["Unit"] = field(default_factory=list)
    # 执行结果（module 单元）
    ret_name: Optional[str] = None
    ret_code: Optional[int] = None
    action: Optional[int] = None


@dataclass
class LevelState:
    """一个栈级的累计状态（对应上游 impression/status 与 substate 保存值）。"""

    impression: str = "undef"   # undef | positive | negative
    status: str = INITIAL_STATUS


class _StopLevel(Exception):
    """done/die/bad jump：终止当前栈级（上游 goto decision_made）。"""

    def __init__(self, action: int):
        self.action = action


class _JumpTo(Exception):
    """正整数跳转：把当前栈级游标前移 N 个单元。"""

    def __init__(self, target_idx: int):
        self.target_idx = target_idx


def _flatten(
    pf: PamFile,
    files: dict[str, PamFile],
    chain: list[tuple[str, str]],
    depth: int,
    loc_hint: list[str],
) -> list[Unit]:
    """
    把一个配置文件的 auth 行展开为执行单元序列。
    chain 记录 (文件, 引用方式) 用于循环/缺失检测；depth 限制 include/substack 嵌套。
    """
    units: list[Unit] = []
    for pl in pf.lines:
        if pl.kind == "module":
            units.append(Unit(kind="module", line=pl))
            continue

        target = pl.target
        # 缺失引用：include/substack 目标文件未提交
        if target not in files:
            raise PamConfigError(
                f"{pf.name}:{pl.line_no} 的 {pl.kind} 引用了未提交的配置 "
                f"/etc/pam.d/{target}（缺失引用，无法离线分析）",
                loc_hint,
            )
        # 循环引用检测（同一文件在当前引用链上再次进入）
        if any(f == target for f, _ in chain):
            cycle = " -> ".join([f for f, _ in chain] + [target])
            raise PamConfigError(
                f"检测到 PAM 引用循环：{cycle}（由 {pf.name}:{pl.line_no} 的 "
                f"{pl.kind} 触发），Linux-PAM 会嵌套到上限后失败",
                loc_hint,
            )
        if depth + 1 > PAM_SUBSTACK_MAX_LEVEL:
            raise PamConfigError(
                f"include/substack 嵌套深度超过 {PAM_SUBSTACK_MAX_LEVEL} 层上限",
                loc_hint,
            )
        child_units = _flatten(
            files[target], files, chain + [(target, pl.kind)], depth + 1, loc_hint
        )
        if pl.kind == "include":
            # include：文本内联，直接把子单元并入当前序列（无状态边界）
            units.extend(child_units)
        else:
            units.append(Unit(kind="substack", line=pl, children=child_units))
    return units


# --------------------------------------------------------------------------- #
# 分析主流程
# --------------------------------------------------------------------------- #
def analyze(
    entry: str,
    files: dict[str, PamFile],
    returns: dict[tuple[str, int], str],
) -> dict[str, Any]:
    """执行 pam_authenticate 语义模拟，返回结构化逐步结果。"""
    loc_hint = ["files"]
    top_units = _flatten(files[entry], files, [(entry, "entry")], 0, loc_hint)

    steps: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    warnings: list[str] = []

    # 记录每个模块单元的返回码（来自用户填写）
    def fill_returns(units: list[Unit]) -> None:
        for u in units:
            if u.kind == "module":
                key = (u.line.file, u.line.line_no)
                u.ret_name = returns[key]
                u.ret_code = RETURN_VALUES[u.ret_name]
                u.action = u.line.actions[u.ret_code]
            else:
                fill_returns(u.children)

    fill_returns(top_units)

    if not top_units:
        warnings.append(
            f"入口服务 {entry} 的 auth 栈为空（没有任何 auth 模块）；"
            "Linux-PAM 对此返回 PAM_PERM_DENIED（本工具记为 auth_err）"
        )

    top = LevelState()
    # 顶层 reset 的恢复边界即初始状态（对应上游 substates[0]）
    top_boundary = LevelState()

    def snapshot_state(st: LevelState) -> LevelState:
        return LevelState(impression=st.impression, status=st.status)

    def _apply_required_merge(sub_ret: str, st: LevelState) -> None:
        # substack 占位处理器按 required 回并：success->ok, ignore->ignore, 其它->bad
        if sub_ret == "success":
            _do_ok("success", st)
        elif sub_ret == "ignore":
            return  # ignore：不动累计
        else:
            _do_bad(sub_ret, st)

    def _do_ok(ret: str, st: LevelState) -> None:
        # 上游 _PAM_ACTION_OK/DONE 的赋值条件（首个结果优先）
        if st.impression == "undef" or (st.impression == "positive" and st.status == "success"):
            st.impression = "positive"
            st.status = ret

    def _do_bad(ret: str, st: LevelState) -> None:
        # 上游 _PAM_ACTION_BAD/DIE：仅在尚未 negative 时记录，首个失败优先；
        # 不把 PAM_IGNORE 作为状态返回（映射为兜底失败码 auth_err）
        if st.impression != "negative":
            st.impression = "negative"
            st.status = "auth_err" if ret == "ignore" else ret

    def _dispatch_action(action: int, u: Unit, st: LevelState,
                         boundary: LevelState, idx: int) -> None:
        """处理单个模块动作；done/die/坏跳转抛 _StopLevel，跳转抛 _JumpTo。"""
        ret = u.ret_name
        step = steps[-1]
        if action == ACT_IGNORE:
            _mark_state(step, st, "ignore：累计状态不变")
            return
        if action == ACT_OK:
            before = (st.impression, st.status)
            _do_ok(ret, st)
            note = "ok：记为正向结果" if before != (st.impression, st.status) \
                else "ok：已有失败在先或状态不更优，累计不变"
            _mark_state(step, st, note)
            return
        if action == ACT_BAD:
            before = (st.impression, st.status)
            _do_bad(ret, st)
            note = "bad：记为负向结果" if before != (st.impression, st.status) \
                else "bad：已有失败在先（首个失败优先），累计不变"
            _mark_state(step, st, note)
            return
        if action == ACT_RESET:
            restored = snapshot_state(boundary)
            st.impression = restored.impression
            st.status = restored.status
            _mark_state(
                step, st,
                f"reset：恢复进入当前栈级时保存的边界状态"
                f"（{restored.impression}/{restored.status}）",
            )
            return
        if action == ACT_DONE:
            _do_ok(ret, st)
            _mark_state(step, st, "done：评估动作；仅当已形成正向印象时才结束当前栈级")
            if st.impression == "positive":
                raise _StopLevel(ACT_DONE)
            return  # 非 positive：上游不跳转，继续后续模块
        if action == ACT_DIE:
            _do_bad(ret, st)
            _mark_state(step, st, "die：记录失败并立即结束当前栈级")
            raise _StopLevel(ACT_DIE)

        # 正整数跳转：auth 链（非缓存链）上跳转本身不改累计状态
        n = action
        units = step["_units"]
        cur = idx
        remain = n
        while remain > 0 and cur + 1 < len(units):
            cur += 1
            skipped.append(
                _skip_record(units[cur], step["level"],
                             f"跳转 {n} 跳过（第 {n - remain + 1}/{n} 个同栈级单元）")
            )
            remain -= 1
        if remain > 0:
            # 跳过栈尾仍有余数 => bad jump：置 negative + PAM_MUST_FAIL_CODE 并终止
            st.impression = "negative"
            st.status = INITIAL_STATUS
            _mark_state(
                step, st,
                f"跳转 {n} 越过当前栈级尾部（bad jump）：置失败并结束当前栈级",
                bad_jump=n,
            )
            raise _StopLevel(ACT_DIE)
        _mark_state(step, st, f"跳转：向前跳过 {n} 个同栈级单元，落到单元索引 #{idx + n + 1}（0 基）")
        # run_level 接住后把 idx 设为目标单元；跳过的是 idx+1..idx+n
        raise _JumpTo(idx + n + 1)

    def run_level(units: list[Unit], st: LevelState, level: int,
                  boundary: LevelState) -> None:
        idx = 0
        while idx < len(units):
            u = units[idx]
            if u.kind == "substack":
                # 进入子栈：保存当前状态作为子栈 reset/回并边界
                sub_boundary = snapshot_state(st)
                sub_st = LevelState(impression=st.impression, status=st.status)
                steps.append(_step_enter(u, level, sub_st))
                # 子栈内 done/die/bad-jump 只终止子栈自身
                try:
                    run_level(u.children, sub_st, level + 1, sub_boundary)
                except _StopLevel:
                    pass
                # 子栈印象仍为 undef（只有 ignore 被触发）时，对父级等价 PAM_IGNORE
                if sub_st.impression == "undef":
                    sub_ret = "ignore"
                else:
                    sub_ret = sub_st.status
                steps.append(_step_substack_return(u, level, sub_st, sub_ret))
                # 父级按 required 语义回并子栈结果
                _apply_required_merge(sub_ret, st)
                idx += 1
                continue

            # ---- 普通模块 -------------------------------------------------
            action = u.action
            step = _step_module(u, level, st, "call")
            step["_units"] = units  # 供跳转遍历同栈级单元（输出前剔除内部字段）
            steps.append(step)
            try:
                _dispatch_action(action, u, st, boundary, idx)
            except _JumpTo as j:
                idx = j.target_idx
                continue
            except _StopLevel as stop:
                label = ACTION_NAMES.get(stop.action, str(stop.action))
                for j in range(idx + 1, len(units)):
                    skipped.append(
                        _skip_record(units[j], level, f"当前栈级被 {label} 终止，未执行")
                    )
                return
            idx += 1

    try:
        run_level(top_units, top, 0, top_boundary)
    except _StopLevel:
        pass  # 顶层 done/die/bad-jump：分析结束

    # 上游收尾健全性检查：status=success 但 impression 非 positive => 强制失败
    if top.status == "success" and top.impression != "positive":
        top.status = INITIAL_STATUS
        warnings.append("终态健全性检查：status=success 但无正向印象，按 PAM 规则改判 auth_err")

    # 剔除仅供内部使用的临时字段
    for s in steps:
        s.pop("_units", None)

    authenticated = top.impression == "positive" and top.status == "success"
    return {
        "entry": entry,
        "return_code": top.status,
        "authenticated": authenticated,
        "final_impression": top.impression,
        "steps": steps,
        "skipped": skipped,
        "warnings": warnings,
        "files": [
            {
                "name": pf.name,
                "auth_lines": [
                    {"line": l.line_no, "raw": l.raw, "kind": l.kind,
                     "module": l.module, "target": l.target,
                     "control": l.control_raw}
                    for l in pf.lines
                ],
                "ignored_lines": pf.skipped,
            }
            for pf in files.values()
        ],
    }


# --------------------------------------------------------------------------- #
# 步骤/跳过记录构造
# --------------------------------------------------------------------------- #
def _step_module(u: Unit, level: int, st: LevelState, phase: str) -> dict[str, Any]:
    return {
        "kind": "module",
        "phase": phase,
        "level": level,
        "file": u.line.file,
        "line": u.line.line_no,
        "raw": u.line.raw,
        "module": u.line.module,
        "control": u.line.control_raw,
        "module_return": u.ret_name,
        "action": ACTION_NAMES.get(u.action, str(u.action)),
        "state_before": {"impression": st.impression, "status": st.status},
        "state_after": None,
        "note": "",
    }


def _step_enter(u: Unit, level: int, st: LevelState) -> dict[str, Any]:
    return {
        "kind": "substack_enter",
        "level": level,
        "file": u.line.file,
        "line": u.line.line_no,
        "raw": u.line.raw,
        "target": u.line.target,
        "state_before": {"impression": st.impression, "status": st.status},
        "state_after": {"impression": st.impression, "status": st.status},
        "note": f"进入 substack /etc/pam.d/{u.line.target}，保存当前状态为子栈边界",
    }


def _step_substack_return(u: Unit, level: int, sub_st: LevelState,
                          sub_ret: str) -> dict[str, Any]:
    return {
        "kind": "substack_return",
        "level": level,
        "file": u.line.file,
        "line": u.line.line_no,
        "raw": u.line.raw,
        "target": u.line.target,
        "substack_return": sub_ret,
        "state_before": {"impression": sub_st.impression, "status": sub_st.status},
        "state_after": {"impression": sub_st.impression, "status": sub_st.status},
        "note": "子栈结束，结果将按 required 语义回并父栈",
    }


def _skip_record(u: Unit, level: int, reason: str) -> dict[str, Any]:
    return {
        "kind": u.kind,
        "level": level,
        "file": u.line.file,
        "line": u.line.line_no,
        "raw": u.line.raw,
        "module": u.line.module,
        "target": u.line.target,
        "reason": reason,
    }


def _mark_state(step: dict[str, Any], st: LevelState, note: str,
                bad_jump: Optional[int] = None) -> None:
    step["state_after"] = {"impression": st.impression, "status": st.status}
    step["note"] = note
    if bad_jump is not None:
        step["bad_jump"] = bad_jump
