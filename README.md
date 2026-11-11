# 共享文件服务器读取权限 · 离线诊断台

运维排查「文件有读权限却打不开」时，用本工具在浏览器里编辑 **目录快照 JSON** 和 **读取请求 JSON**，
由 FastAPI 后端按 Linux 无特权进程规则完整模拟路径解析（namei）与 DAC / POSIX ACL 判定，
输出：能否读取、首个失败原因与分类、逐步解析过程、每一步实际采用的权限项。

**全程只在内存中计算，不读取、不探测宿主机上的任何文件或路径**；容器以非 root、只读根文件系统、
丢弃全部 Linux capability 的方式运行，也不挂载宿主目录。

## 一、启动

### 方式 A：Docker Compose（推荐，可实际演示）

```bash
docker compose up --build
# 浏览器打开
#   http://localhost:8000/
```

页面即诊断入口：左侧选择/编辑示例 JSON，右侧展示结论与逐步解析。

### 方式 B：本机 Python（3.11+）

```bash
python3 -m pip install -r requirements.txt   # 离线环境请提前准备 wheelhouse
./run.sh                                      # 等价于 uvicorn app.main:app --port 8000
# 打开 http://localhost:8000/
```

健康检查：`GET /health`；OpenAPI 文档：`GET /docs`。

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
| GET  | `/` | 浏览器诊断页面（单文件、零外部依赖，可离线） |
| GET  | `/health` | 健康检查 |
| GET  | `/api/examples` | 内置 6 个可编辑示例 |
| POST | `/api/validate-snapshot` | 仅校验快照，返回节点数与告警 |
| POST | `/api/diagnose` | 入参 `{ "snapshot": {...}, "request": {...} }`，返回完整诊断 |

## 五、测试

```bash
python3 -m pytest tests/ -q
```

覆盖：逐级 search 与 EACCES 优先级、mode/ACL 各分支、mask 约束、命中后不退回 other、
组权限并集、相对/绝对软链接、物理 `..`、第 40/41 次链接边界、非普通文件与 ENOTDIR、
快照/请求校验定位，以及全部内置示例的端到端诊断。

## 六、目录结构

```
app/
  engine.py          # 快照校验 + mode/ACL 权限判定
  resolver.py        # namei 风格路径解析（软链接、物理 ..、40 次限制）
  main.py            # FastAPI 路由
  static/
    index.html       # 离线单页诊断台
    examples.json    # 6 个可编辑示例
tests/               # pytest 测试
Dockerfile, docker-compose.yml, requirements.txt, run.sh
```
