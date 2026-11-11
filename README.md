# 共享文件服务器 · 离线诊断台（读取权限 + PAM 认证栈）

本工具提供两个相互独立、全程离线的诊断台，均只在内存中计算，**不读取、不探测宿主机上的任何文件或路径**：

1. **文件读取权限诊断**（首页 `/`）：编辑目录快照 JSON 与读取请求，按 Linux 无特权进程规则模拟
   路径解析（namei）与 DAC / POSIX ACL 判定，定位“文件有读权限却打不开”的首个受阻点。
2. **PAM 认证栈诊断**（`/pam`）：编辑最多 8 份 `/etc/pam.d` 配置与每个模块行的返回码，
   按 Linux-PAM `pam_authenticate` 语义模拟 auth 管理组的完整控制流，定位“SSH 认证失败 / 意外放行”的 PAM 配置原因。

容器以非 root、只读根文件系统、丢弃全部 Linux capability 的方式运行，也不挂载宿主目录。

## 一、启动

### 方式 A：Docker Compose（推荐，可实际演示）

```bash
docker compose up --build
# 浏览器打开
#   http://localhost:8000/        文件读取权限诊断
#   http://localhost:8000/pam     PAM 认证栈（auth）诊断
```

### 方式 B：本机 Python（3.11+）

```bash
python3 -m pip install -r requirements.txt   # 离线环境请提前准备 wheelhouse
./run.sh                                      # 等价于 uvicorn app.main:app --port 8000
# 打开 http://localhost:8000/pam
```

健康检查：`GET /health`；OpenAPI 文档：`GET /docs`。

---

# 第一部分：文件读取权限诊断


## 二、快照与请求格式

### 快照 snapshot（最多 100 个节点）

```json
{
  "users":  {"1001": "alice"},
  "groups": {"1000": "staff"},
  "nodes": [
    {
      "path": "/srv/secret.txt",          // 必须绝对、规范化、唯一
      "type": "file",                     // file | directory | symlink | other
      "uid": 0, "gid": 0,
      "mode": "640",                      // 3~4 位八进制字符串，也接受整数
      "link_target": "../etc/x",          // 仅 symlink 需要
      "acl": [                             // 可选，POSIX.1e 访问 ACL
        {"type": "user_obj",  "perms": "rw-"},
        {"type": "user",      "qualifier": 1001, "perms": "rwx"},
        {"type": "group_obj", "perms": "r--"},
        {"type": "group",     "qualifier": 1000, "perms": "r-x"},
        {"type": "mask",      "perms": "r--"},
        {"type": "other",     "perms": "---"}
      ]
    }
  ]
}
```

- `perms` 接受 `"rwx"` 三元组（无权限位写 `-`）或整数 `0..7`；
- 含命名 `user`/`group` 条目（扩展 ACL）时**必须**带 `mask`，否则快照校验报错；
- 必须包含根目录 `/` 且类型为 `directory`；
- 校验错误会返回精确定位，例如 `$['nodes']['2']['mode']`。

### 请求 request

```json
{ "uid": 1001, "gid": 1001, "supp_groups": [100, 1000], "path": "/srv/secret.txt" }
```

- `uid` 必须是**非 0 正整数**（root 拥有 cap_dac_override，不适用本诊断）；
- `path` 必须是绝对路径，允许包含 `.`、`..` 与软链接，按 Linux 规则物理解析。

## 三、判定语义（与 Linux 对齐）

1. **逐级搜索权限**：进入/使用每个目录前检查其 `--x`；`EACCES` 优先于 `ENOENT`
   （目录不可搜索时，即使目标不存在也先报权限不足）。
2. **软链接**：相对目标按链接所在目录展开，绝对目标从 `/` 重新展开；
   链接自身的 mode 不参与判定；最多跟随 **40** 次（`MAXSYMLINKS`），第 41 次报 `ELOOP`。
3. **不提前折叠 `..`**：`..` 回退到当前物理目录的父目录——经过软链接后，
   结果与字符串规范化不同（见内置示例 3）。
4. **经典 mode**：属主 → 组（主组或任一附加组命中即用组位）→ other。
5. **POSIX ACL**：
   - 属主永远使用 `user_obj`（命名 user 条目不匹配属主自身）；
   - 命名 `user` 命中即终局，权限受 `mask` 约束，**不退回** group/other；
   - 所有命中的组条目（含 `group_obj` 与命名 `group`）权限取**并集**后再与 `mask`；
     只要组身份命中就**不退回** other；
   - 属主与所有组条目均未命中身份时才使用 `other`。
6. **结果分类**：`permission_denied`（EACCES）、`path_missing`（ENOENT）、
   `link_limit_exceeded`（ELOOP）、`not_regular`（最终节点非普通文件 / 中间组件 ENOTDIR）、`ok`。

> 说明：本工具模拟普通文件的 `open(O_RDONLY)` 判定，不覆盖 sticky bit 删除规则、
> setuid/setgid、capabilities 与挂载选项（nosuid/nodev 等）——这些不影响无特权进程的读授权结论。

## 四、HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET  | `/` | 文件读取权限诊断页面（单文件、零外部依赖，可离线） |
| GET  | `/pam` | PAM 认证栈诊断页面（单文件、零外部依赖，可离线） |
| GET  | `/health` | 健康检查 |
| GET  | `/api/examples` | 文件诊断内置 6 个可编辑示例 |
| GET  | `/api/pam/examples` | PAM 诊断内置 7 个可编辑示例（含子栈示例） |
| POST | `/api/validate-snapshot` | 仅校验快照，返回节点数与告警 |
| POST | `/api/diagnose` | 入参 `{ "snapshot": {...}, "request": {...} }`，返回完整诊断 |
| POST | `/api/pam/analyze` | 入参 PAM 负载，返回 auth 栈逐步分析（见第二部分） |

## 五、测试

```bash
python3 -m pytest tests/ -q
```

文件诊断覆盖：逐级 search 与 EACCES 优先级、mode/ACL 各分支、mask 约束、命中后不退回 other、
组权限并集、相对/绝对软链接、物理 `..`、第 40/41 次链接边界、非普通文件与 ENOTDIR、
快照/请求校验定位，以及全部内置示例的端到端诊断。

PAM 诊断覆盖（`test_pam_engine.py` / `test_pam_api.py`）：required/requisite/sufficient/optional
动作差异、方括号控制与正整数跳转、坏跳转、include 文本内联与 substack 状态隔离、子栈 die 不杀父栈、
substack 跳转计数、reset 的顶层/子栈恢复边界、缺失引用与循环引用拒绝、续行行号、非 auth 行忽略、
8 文件/60 行上限与返回码定位，以及全部内置示例的端到端分析。

## 六、目录结构

```
app/
  engine.py          # 快照校验 + mode/ACL 权限判定
  resolver.py        # namei 风格路径解析（软链接、物理 ..、40 次限制）
  pam_engine.py      # PAM auth 栈解析、校验与 pam_authenticate 控制流模拟
  main.py            # FastAPI 路由（文件诊断 + PAM 诊断）
  static/
    index.html       # 文件读取权限诊断台（离线单页）
    pam.html         # PAM 认证栈诊断台（离线单页）
    examples.json    # 文件诊断 6 个可编辑示例
    pam_examples.json# PAM 诊断 7 个可编辑示例（含子栈）
tests/               # pytest 测试（含 PAM 引擎与 API 测试）
Dockerfile, docker-compose.yml, requirements.txt, run.sh
```

---

# 第二部分：PAM 认证栈（auth）离线诊断

## 1. 能做什么 / 不能做什么

- **只分析 `auth` 管理组**：`account` / `password` / `session` 行会被识别并标注为“跳过，不参与分析”。
- **不加载任何 PAM 模块**：每个模块行“返回什么”由你在浏览器按 **文件名 + 物理行号** 填写，
  取值仅限 `success` / `auth_err` / `user_unknown` / `ignore` 四种（对应 `PAM_SUCCESS` /
  `PAM_AUTH_ERR` / `PAM_USER_UNKNOWN` / `PAM_IGNORE`）。
- 最多提交 **8 份** `/etc/pam.d` 配置，单文件最多 **60 行**；支持反斜杠续行（行号取起始行）、
  空行、`#` 注释、前导 `-`（静默模块加载）与 `@include` 旧式语法。
- 缺失引用、引用循环、非法控制/动作/返回码都会被**精确定位并拒绝（HTTP 422），且不产生分析结果**。

## 2. 负载格式（`POST /api/pam/analyze`）

```json
{
  "entry": "sshd",
  "files": [
    { "name": "sshd",
      "content": "auth substack password-auth\nauth required pam_permit.so\n" },
    { "name": "password-auth",
      "content": "auth requisite pam_deny.so\nauth required pam_permit.so\n" }
  ],
  "returns": [
    { "file": "sshd", "line": 2, "return": "success" },
    { "file": "password-auth", "line": 1, "return": "auth_err" },
    { "file": "password-auth", "line": 2, "return": "success" }
  ]
}
```

- `entry`：入口服务名，必须是 `/etc/pam.d` 下的纯文件名且出现在 `files[].name` 中；
- `files[].content`：配置原文，按真实物理行填写；
- `returns[]`：为**每个 auth 模块行**填写一个返回码；`include`/`substack` 行、空行、注释、
  非 auth 行**不需要也不允许**填写返回码，否则报错定位。

## 3. 控制流语义（严格对齐 Linux-PAM 源码）

实现依据上游 `libpam/pam_dispatch.c`、`pam_misc.c`、`pam_tokens.h`、`pam_handlers.c`：

- **简单控制**（按上游固定动作表展开）
  - `required`：成功 `ok`、`ignore` 透传、其余 `bad`（记录失败但继续）；
  - `requisite`：成功 `ok`、`ignore` 透传、其余 `die`（立即终止当前栈级）；
  - `sufficient`：成功 `done`（已形成正向印象时立即结束）、其余 `ignore`；
  - `optional`：成功 `ok`、其余 `ignore`（全程无正向印象则最终拒绝）。
- **方括号控制** `[value=action ...]`：返回值支持四值与 `default`；动作仅支持
  `ignore / ok / bad / done / die / reset` 与**正整数**跳转（0 跳转非法）。
  等号两侧允许空格；未显式给出的返回值按上游默认 `bad`。
- **累计状态**：内部维护 `impression`（undef/positive/negative）与 `status`，
  遵循上游“首个结果优先”——已 negative 后后续失败不覆盖、positive 且 success 时才用新成功覆盖。
- **include 与 substack 的区别**
  - `include`：仅做文本内联，**不建立状态边界**，其中的 `reset` 恢复的是顶层/外层边界；
  - `substack`：建立独立栈级，进入时保存当前状态作为该子栈的 `reset` 与回并边界；
    子栈结束后把终态按 **required** 语义回并父栈（success→ok，ignore→不动，其余→bad）。
- **子栈终止**：子栈内的 `done`/`die`/坏跳转**只终止子栈自身**，控制返回父级继续执行。
- **跳转计数**：以“同一栈级的下一个处理单元”为单位，**整个 substack 算一个单元**；
  若跳过的数量越过当前栈级尾部仍有余数，即上游的 **bad jump**，强制置 negative 并以
  `PAM_PERM_DENIED`（本工具记为 `auth_err`）结束。
- **reset 边界**：恢复“进入当前栈级时保存”的状态；顶层 reset 恢复初始边界（undef/auth_err）。
- **终态健全性**：若 `status=success` 但没有正向印象，按上游规则改判失败。

## 4. 返回结构要点

```jsonc
{
  "ok": true,
  "result": {
    "entry": "sshd",
    "return_code": "auth_err",      // PAM 最终返回码（四值模型）
    "authenticated": false,          // 是否等价 pam_authenticate == PAM_SUCCESS
    "final_impression": "negative",
    "steps": [ /* 每个模块调用 / 进出子栈，含 state_before/state_after、动作、源文件行号 */ ],
    "skipped": [ /* 被 die/done/跳转跳过的源行与原因 */ ],
    "warnings": [ /* 空 auth 栈等告警 */ ],
    "files": [ /* 每份配置参与分析的 auth 行与被忽略的非 auth/空/注释行 */ ]
  }
}
```

## 5. 内置示例（`/api/pam/examples`）

1. requisite 失败立即 die，后续模块全部跳过；
2. sufficient 成功即 done 短路放行；
3. **substack 隔离**：内部 die 不杀父栈，结果按 required 回并（子栈示例）；
4. include 文本内联无状态边界，reset 恢复顶层初始状态；
5. 方括号跳转，整个 substack 只算一个跳转单元；
6. substack 内 reset 恢复进入子栈时保存的边界状态；
7. 缺失引用被定位拒绝（用于演示错误定位，运行即 422）。
