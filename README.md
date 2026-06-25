# UFW OkBoy

**动态防火墙白名单管理工具** — 授权用户认证后自动将其 IP 注册到 UFW，IP 变化时无缝切换，保持防火墙规则整洁可追溯。

[English](README.en.md) | 中文

<p align="center">
  <img src="docs/web-client.png" alt="Web 客户端界面" width="380">
</p>

---

## v2.0 新特性

| 特性 | 说明 |
|------|------|
| **SQLite 数据库** | 替换 JSON 状态文件，支持事务、并发读取 (WAL 模式)、结构化查询 |
| **管理员组 + 用户组** | 管理员通过 CLI/API 管理用户和组，不再需要修改配置文件 |
| **组→端口映射** | 每个用户组对应一个端口，用户加入多个组即获得多端口访问授权 |
| **业务组开关** | 用户可自行开启/关闭业务组，仅已开启的组生成防火墙规则 |
| **IP 即时清理** | IP 变更时旧 IP 从所有已开启组端口立即移除 |
| **CLI + API 双通道** | 9+ CLI 命令（含 `upgrade`）+ 多组 REST API 端点（admin/users、admin/groups、me/groups、me/membership 等），全部管理员权限守卫 |
| **审计日志** | 所有管理操作记录到 audit_log 表，可追溯 |
| **一键部署** | 多发行版支持 (Ubuntu/Debian/CentOS/RHEL)，域名+自签双模式 SSL |
| **向后兼容** | 现有 knock.py / knock.sh / Web UI 客户端无需任何修改 |

## v2.1 新增

| 特性 | 说明 |
|------|------|
| **协调性修复** | 分组变更（加/删用户入组）后在线用户 IP **立即**同步 UFW；knock 心跳路径每 30s 幂等对账（reconcile）自愈残留/旧 IP 规则，无竞态残留 |
| **UFW 规则精确化** | 删除按 comment `ufw-okboy:<用户>:<组>` 精确匹配，跨组同端口不再互删 |
| **管理员 Web 管理页** | 管理员登录后可见控制台：用户/分组/规则 CRUD，无需 CLI |
| **分组授权多选** | 用户多组时在管理页选择授权哪些分组（默认勾选第一个，保存后批量提交），服务端二次验证拒绝越权开放端口 |
| **PIN 加密锁** | 管理页敏感凭据经 PIN→PBKDF2→AES-GCM 加密，localStorage 只存密文，密钥不落地不传输，无后门恢复 |
| **端口白名单** | 新增 `allowed_ports` 配置（opt-in），限制新建分组可绑端口，防越权开敏感端口 |
| **版本化 DB 迁移** | `schema_version` 表 + 迁移注册表，未来改 schema 不破坏已部署实例，向前兼容不丢数据 |
| **智能升级** | `app.py upgrade --check` 检测 GitHub 新版本（仅提示）；`--force` 手动升级（备份 DB→拉取→迁移→重启→健康检查→失败自动回滚）。root 服务不自动联网拉代码 |
| **版本号体系** | `VERSION` 文件单一真源 + `app.py --version`，构建/升级统一读取 |
| **暴力/滥用限流** | 同一 IP 认证失败过多自动 429（按 IP，不误伤正常用户）；Nginx limit_req 协同；`failed_attempts` 索引加速 |
| **用户下线 + 强制重认证** | 一键 `revoke`：关端口 + 清在线态 + 轮换密钥（旧凭据即时失效）；管理页 Revoke 按钮 |
| **管理员 TOTP 二次验证** | **所有管理写操作**（建/删用户·分组、成员变更、下线、提权）启用 TOTP 后需 6 位动态码（RFC 6238，兼容 Authenticator），管理页 Two-Factor 面板自助启用 |
| **审计日志查看** | 管理页 Audit Log 面板直接查看操作审计，无需登录服务器 |
| **数据备份 / 恢复** | `backup`/`restore`：SQLite 在线备份 API + SHA-256 校验和 + 滚动保留 + 篡改拒绝 |
| **防 IP 伪造 (H-9)** | X-Real-IP / X-Forwarded-For 仅信任 `trusted_proxies` 列表内的直连来源，杜绝伪造 IP 入白名单 |
| **knock 原子化** | IP 变更的状态更新与 ip_change 日志合并为单事务，消除撕裂窗口 |

## v2.1.1 安全修复

| 修复 | 说明 |
|------|------|
| **step-up 越权封堵** | 建用户/建分组/成员增删等管理写操作此前缺二次验证，偷到 admin 密钥（无 TOTP）者可绕过校验直接新建管理员；现所有管理写操作统一纳入 step-up |
| **防 2FA 接管** | `totp/enroll` 再注册需当前动态码，杜绝用泄露会话覆盖/关闭管理员 2FA |
| **防 IP 伪造** | `X-Forwarded-For` 取最右 hop（紧邻可信代理），客户端无法伪造最左项把任意 IP 注册进白名单 |
| **TOTP 重放保护** | 用过的动态码在窗口内重放即拒（RFC 6238 §5.2）；step-up 失败计入 IP 限流；可由 `totp_replay_protection` 开关 |

## v2.2 新增

| 特性 | 说明 |
|------|------|
| **国内友好安装** | 离线安装包（内置 manylinux wheels，装依赖零联网）；pip 自动镜像兜底（pypi 不通自动切清华源，`--mirror` 可指定）；GitHub 镜像 `--gh-mirror`；公网 IP 自动探测用于自签证书 SAN（`--ip` 可覆盖）；自签 + IP + 任意高位端口为默认路径，**无需备案域名**；自签证书有效期 10 年。详见 [国内部署专题](GUIDE.md#国内部署专题) |
| **客户端自签直通** | `knock.sh` 支持 `-k`/`INSECURE`，`knock.py` 支持 `verify_ssl: false` 配置；修复 install-client 写错配置格式导致自动敲门失效的 bug |
| **Web 管理台健壮性** | 修复"复制 token 后报 `Unexpected token '<'`"崩溃（根因：nginx 限流突发返回 HTML 错误页）；前端非 JSON 响应安全解析 + 幂等 GET 退避重试；后端 `/api` 全路径 JSON 错误契约 |
| **安全深化** | step-up 覆盖补全（管理员改他人成员关系）；TOTP 禁用/再注册纳入重放保护；用户名/组名字符与端口范围校验；登录错误统一文案防用户名枚举 |
| **稳定性** | reconcile 单条 ufw 失败不再中断整体（陈旧规则仍清理）；DB 改线程局部连接消除多线程隐患；凭据"先验证后持久化" |

## 为什么需要它

服务器上的敏感端口（管理后台、数据库、API）通过 UFW 防火墙白名单限制访问。但客户端 IP 会变——切换 WiFi、出差、重启路由器——每次都要找管理员手动改规则。

**UFW OkBoy 让这件事自动化**：用户打开网页认证一次，服务器自动更新防火墙；IP 变了，下一个心跳周期无感切换。

## 工作流程

```
客户端（浏览器 / Python / Shell）
    |
    | HTTPS + HMAC-SHA256 签名认证
    v
Nginx（反向代理，TLS 加密，传递真实 IP）
    |
    v
Flask API（验证身份，提取客户端 IP，查询用户组）
    |
    v
UFW（移除旧规则 → 添加新规则 → 注释：ufw-okboy:<用户名>:<组名>）
    |
    v
SQLite 数据库（users / groups / membership / audit_log）
```

## 核心特性

| 特性 | 说明 |
|------|------|
| **网页客户端** | 浏览器打开即用，每 30 秒自动续期，关闭后重开自动恢复。手机适用 |
| **规则整洁** | 每用户每端口仅一条规则，IP 变更时自动替换，不留残余 |
| **规则可追溯** | UFW 规则带注释 `ufw-okboy:<用户名>:<组名>`，`ufw status` 直观可查 |
| **组管理** | 管理员通过 CLI/API 创建用户组、绑定端口、管理成员 |
| **业务组开关** | 用户可自行开关组，灵活控制哪些端口生效 |
| **防凭证共享** | 同一账号只能绑定一个 IP，共享即互踢；异常 IP 切换自动告警 |
| **自动过期清理** | 7 天未活跃的规则由每日定时任务自动清除 |
| **认证安全** | HMAC-SHA256 + 时间戳，密钥不上线，全程 HTTPS，失败尝试记录 |
| **审计日志** | 所有管理操作入审计表，可查询、可追溯 |
| **三种客户端** | Web UI / Python 脚本 / Shell 脚本（curl + openssl，零依赖） |

## 一键安装

**服务端（一行命令）：**

```bash
# 自签证书模式（无需域名，IP:port 直接访问）
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh | bash -s -- --self-signed -y

# 域名模式（自动 Let's Encrypt）
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh | bash -s -- --domain your.server.com -y
```

**客户端（一行命令）：**

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.sh | bash -s -- --server https://your-server --user alice --secret YOUR_SECRET
```

**一键升级（已安装的服务端，自动重启服务）：**

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/upgrade.sh | bash
```

> 升级前自动备份数据库 + 快照旧代码；更新后**重启服务**并健康检查，失败自动回滚。保留 config / nginx / SSL / 数据库。浏览器端硬刷新（Ctrl-Shift-R）加载新界面。

## 国内安装（中国大陆）

国内服务器常见障碍：GitHub/PyPI 下载慢或不通、域名需备案、惯用高位端口 + 自签证书。本项目对这些场景做了专门处理。

> 💡 下面是速查版。**手把手步骤 + 逐项故障排查**请看 👉 **[完整指南 · 国内部署专题](GUIDE.md#国内部署专题)**——装不上时先翻它，基本都能对症解决。

**最稳方式：离线安装包**（自带 Python 依赖 wheels，安装全程只需下载一个 tar 包）

```bash
# 在能联网的机器上构建离线包（产物含 vendor/ 内置 wheels）
bash deploy/build-release.sh
# 拷贝 dist/ufw-okboy-*.tar.gz 到目标服务器后：
tar xzf ufw-okboy-*.tar.gz && cd ufw-okboy-*
bash install.sh --self-signed --port 8443 -y     # 自动用 vendor/ 离线装依赖
```

**在线安装（GitHub/PyPI 受阻时用镜像兜底）**

```bash
# --gh-mirror 走 GitHub 代理；pip 在 pypi.org 不通时自动切清华源（也可 --mirror 指定）
curl -fsSL https://ghproxy.com/https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh \
  | bash -s -- --gh-mirror https://ghproxy.com --self-signed --port 8443 --ip <你的公网IP> -y
```

要点：
- **无需域名**：缺省即自签证书 + IP 访问；证书 SAN 自动取**公网 IP**（NAT 云主机可用 `--ip` 显式指定），有效期 10 年。
- **高位端口**：`--port 8443` 之类任意端口；脚本会 `ufw allow`，并提醒你在**云安全组**同步放行。
- **客户端连自签**：`knock.py` 在 `config.yaml` 设 `verify_ssl: false`；`knock.sh` 在 config 设 `INSECURE=1`（或 `--insecure`）；HMAC 密钥永不上网，仅关闭传输层校验。
- **离线升级**：`upgrade.sh --repo-dir <离线包目录>` 或 `--gh-mirror <代理>`；服务端 `app.py upgrade` 支持 `github_mirror` 配置 / `UFW_OKBOY_GH_MIRROR` 环境变量。

## 手动安装

**服务端（管理员）：**

```bash
git clone https://github.com/lvusyy/UFW-OkBoy.git /opt/ufw-okboy
cd /opt/ufw-okboy

# 方式 1: 使用部署脚本（推荐）
bash deploy/deploy.sh --self-signed -y

# 方式 2: 手动安装
python3 -m venv venv && venv/bin/pip install -r server/requirements.txt
cd server
../venv/bin/python app.py user-add admin --admin    # 创建管理员
cp config.example.yaml config.yaml                  # 编辑配置
sudo ../venv/bin/python app.py serve --debug         # 启动
```

**管理命令：**

```bash
# CLI 管理用户和组
python app.py user-add alice --admin         # 添加用户（管理员）
python app.py user-list                       # 列出所有用户
python app.py group-add ssh 22                # 创建组（绑定端口22）
python app.py group-list                      # 列出所有组
python app.py user-join alice ssh             # 用户加入组
python app.py user-leave alice ssh            # 用户离开组
python app.py admin-add alice                 # 设置管理员权限

# REST API（需要管理员 HMAC 认证）
curl -H "Authorization: HMAC-SHA256 admin:..." https://server/api/admin/users
curl -X POST -H "Authorization: ..." -d '{"username":"bob","secret":"..."}' https://server/api/admin/users
```

**客户端（用户）：**

浏览器打开 `https://your-server.com/` → 输入用户名和密钥 → 点击 **Connect** → 完成。

## 完整文档

详见 **[GUIDE.md](GUIDE.md)**（中文），包含：

- 🇨🇳 **[国内部署专题](GUIDE.md#国内部署专题)**：离线包 / 镜像兜底 / 自签 + 公网 IP + 高位端口 / 故障排查
- 服务端部署（UFW 前置配置、Nginx、Systemd）
- 密钥生成与安全分发流程（含发给用户的模板消息）
- 客户端使用说明（Web / Python / Shell）
- 用户组与端口管理
- 日常管理（用户增删、组管理、规则清理、故障排查）
- 安全机制与最佳实践
- 常见问题解答

## 目录结构

```
server/
  app.py              Flask API + CLI（serve / user-add / group-add / ...）
  ufw_ops.py          UFW 操作 + 状态管理
  db.py               SQLite 数据库层（6表：users/groups/membership/audit/operation/failed_attempts）
  auth.py             认证授权（HMAC verify / admin check / group check）
  static/index.html   Web 客户端（单文件 SPA，无需构建）
  config.example.yaml 配置模板
  requirements.txt    依赖清单
  tests/              单元测试（120 tests）
client/
  knock.py            Python 客户端（仅标准库）
  knock.sh            Shell 客户端（curl + openssl）
  config.example.yaml 客户端配置模板
nginx/
  ufw-okboy.conf      Nginx 反向代理配置
deploy/
  deploy.sh           一键部署脚本（多发行版 + 自签/Let's Encrypt）
  quick-install.sh    curl | bash 一行安装
  install-client.sh   客户端一键安装
  upgrade.sh          一键升级（备份→迁移→重启→失败回滚）
  build-release.sh    发布包构建脚本
  ufw-okboy.service   Systemd 服务（Gunicorn）
  ufw-okboy-cleanup.* 过期规则清理定时器
  knock.*             客户端自动续期定时器
```

## 许可证

MIT
