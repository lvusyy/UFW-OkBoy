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
| **CLI + API 双通道** | 9 个 CLI 命令 + 7 个 REST API 端点，全部管理员权限守卫 |
| **审计日志** | 所有管理操作记录到 audit_log 表，可追溯 |
| **一键部署** | 多发行版支持 (Ubuntu/Debian/CentOS/RHEL)，域名+自签双模式 SSL |
| **向后兼容** | 现有 knock.py / knock.sh / Web UI 客户端无需任何修改 |

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
  tests/              单元测试（52 tests）
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
  build-release.sh    发布包构建脚本
  ufw-okboy.service   Systemd 服务（Gunicorn）
  ufw-okboy-cleanup.* 过期规则清理定时器
  knock.*             客户端自动续期定时器
```

## 许可证

MIT
