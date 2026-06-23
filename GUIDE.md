# UFW OkBoy 使用指南

> 动态防火墙白名单管理工具 v2.0 — 让授权用户的 IP 变更不再需要手动处理。

---

## 目录

- [这是什么](#这是什么)
- [工作原理](#工作原理)
- [一键部署](#一键部署)
- [快速开始](#快速开始)
- [服务端部署](#服务端部署)
- [用户组与端口管理](#用户组与端口管理)
- [CLI 管理命令](#cli-管理命令)
- [REST API](#rest-api)
- [客户端使用](#客户端使用)
- [日常管理](#日常管理)
- [安全机制](#安全机制)
- [常见问题](#常见问题)

---

## 这是什么

你的服务器上有一些端口（比如管理后台、数据库）只允许特定 IP 访问，通过 UFW 防火墙的白名单来控制。
但现实是：用户的 IP 会变（切换网络、重启路由器、出差换地方），每次变化都要联系管理员手动更新防火墙，非常麻烦。

**UFW OkBoy** 解决的就是这个问题：

- 用户打开一个网页，完成一次认证
- 服务器自动识别用户当前的 IP，更新防火墙白名单
- 只要网页不关，每 30 秒自动"续期"一次
- 用户 IP 变了？下一次续期会自动切换，无需任何操作
- 管理员通过 CLI/API 管理用户和用户组，无需修改配置文件
- 每个用户组对应一个端口，用户加入多个组即获得多端口访问授权
- 用户可自行开关业务组，灵活控制哪些端口生效

一句话总结：**用户只需要打开网页，防火墙的事交给系统处理。管理员通过命令行管理一切。**

## 工作原理

```
用户浏览器 / 客户端脚本
      |
      | HTTPS 请求（携带 HMAC 签名认证）
      v
  Nginx（反向代理，TLS 加密，传递用户真实 IP）
      |
      v
  Flask API 服务（验证身份，查询用户组，获取用户 IP）
      |
      v
  UFW 防火墙（移除旧 IP 规则，添加新 IP 规则）
      |         注释: ufw-okboy:用户名:组名
      v
  SQLite 数据库（users / groups / membership / audit_log）
```

**关键机制：**

| 特性 | 说明 |
|------|------|
| 认证方式 | HMAC-SHA256 签名 + 时间戳，密钥永远不在网络上传输 |
| 数据存储 | SQLite 数据库（WAL 模式，支持并发读取，原子事务） |
| 用户管理 | CLI 命令 + REST API，管理员组权限控制，无需修改配置文件 |
| 用户组 | 每个组对应一个端口，用户可加入多个组获得多端口访问 |
| 业务组开关 | 用户可自行开关组，仅已开启的组生成防火墙规则 |
| 规则管理 | 每个用户每个端口只保留一条规则，IP 变更时自动替换旧规则 |
| 规则标记 | 每条 UFW 规则带注释 `ufw-okboy:用户名:组名`，`ufw status` 一目了然 |
| 审计日志 | 所有管理操作记录到 audit_log 表，可追溯 |
| 过期清理 | 长时间未活跃的用户规则会被自动清除，防火墙保持干净 |
| 防盗用 | 同一账号只能绑定一个 IP，共享凭证 = 互相踢，自损行为 |

## 一键部署

### 服务端一键安装

**自签证书模式（无需域名，IP 直接访问）：**

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh | bash -s -- --self-signed -y
```

**域名模式（自动 Let's Encrypt 证书）：**

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh | bash -s -- --domain your.server.com -y
```

**从 Release 包安装（离线）：**

```bash
# 从 GitHub Release 下载 ufw-okboy-v2.0.0.tar.gz
tar xzf ufw-okboy-v2.0.0.tar.gz
cd ufw-okboy-v2.0.0
bash install.sh --self-signed -y
```

部署脚本自动完成：
- 检测发行版（Ubuntu/Debian/CentOS/RHEL）
- 安装系统依赖（ufw, nginx, python3, certbot）
- 创建虚拟环境并安装 Python 依赖
- 生成 SSL 证书（自签或 Let's Encrypt）
- 生成 Nginx 配置并重载
- 安装 Systemd 服务并启动
- 打开防火墙 HTTPS 端口
- 交互式创建第一个管理员用户

### 客户端一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.sh | bash -s -- \
  --server https://your-server.com \
  --user alice \
  --secret YOUR_SECRET
```

自动完成：
- 下载 knock.py 客户端
- 创建配置文件（权限 600）
- 测试首次敲门
- 安装 Systemd 定时器（每 30 秒自动敲门）

## 快速开始

> 最短路径：一行命令部署服务端，30 秒完成客户端使用。

### 服务端（管理员操作）

```bash
# 方式 1: 一键部署（推荐）
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh | bash -s -- --self-signed -y

# 方式 2: 手动安装
git clone https://github.com/lvusyy/UFW-OkBoy.git /opt/ufw-okboy
cd /opt/ufw-okboy
bash deploy/deploy.sh --self-signed -y

# 部署后创建管理员和用户组
cd /opt/ufw-okboy/server
../venv/bin/python app.py user-add admin --admin     # 创建管理员
../venv/bin/python app.py group-add ssh 22            # 创建组（绑定端口22）
../venv/bin/python app.py user-join admin ssh          # 管理员加入组
```

### 客户端（用户操作）

1. 用浏览器打开 `https://your-server.com/`（或 `https://YOUR_IP:443` 自签模式）
2. 输入管理员给你的**用户名**和**密钥**
3. 点击 **Connect** — 完成！

页面会自动保持连接，每 30 秒刷新一次。关闭页面后再次打开，会自动恢复连接。

---

## 服务端部署

### 环境要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Ubuntu / Debian / CentOS / RHEL / Rocky / AlmaLinux / Fedora |
| Python | 3.10 或更高版本 |
| 防火墙 | UFW 已安装并启用 |
| Web 服务器 | Nginx（部署脚本自动安装配置） |
| 权限 | 需要 root 权限（UFW 操作需要） |
| SSL 证书 | 域名模式：Let's Encrypt 自动申请；自签模式：脚本自动生成 |

### 前置条件：UFW 防火墙配置

> **重要**：在部署本工具之前，必须先确保 UFW 的默认策略和基本规则正确。
> 操作不当可能导致你被锁在服务器外面，请务必按顺序执行。

```bash
# 1. 确保 SSH 已放行（防止把自己锁在外面！）
sudo ufw allow 22/tcp

# 2. 确保 HTTPS 端口已放行（客户端通过此端口访问）
sudo ufw allow 443/tcp

# 3. 设置默认策略为拒绝所有入站连接
sudo ufw default deny incoming
sudo ufw default allow outgoing

# 4. 启用 UFW
sudo ufw enable

# 5. 确认当前状态
sudo ufw status
```

### 使用部署脚本（推荐）

```bash
# 下载并运行部署脚本
git clone https://github.com/lvusyy/UFW-OkBoy.git
cd UFW-OkBoy

# 自签模式（无需域名，IP:port 访问）
bash deploy/deploy.sh --self-signed -y

# 域名模式（自动 Let's Encrypt）
bash deploy/deploy.sh --domain your.server.com -y

# 自定义端口
bash deploy/deploy.sh --self-signed --port 8443 -y

# 不使用 Nginx（Gunicorn 直接服务）
bash deploy/deploy.sh --self-signed --no-nginx -y
```

部署脚本参数：

| 参数 | 说明 |
|------|------|
| `--domain <域名>` | 使用 Let's Encrypt 申请证书（需 DNS A 记录已指向服务器） |
| `--port <端口>` | HTTPS 端口（默认 443） |
| `--self-signed` | 强制使用自签证书（即使有域名） |
| `--no-nginx` | 跳过 Nginx 配置，Gunicorn 直接服务 |
| `--app-dir <路径>` | 安装目录（默认 /opt/ufw-okboy） |
| `-y` / `--yes` | 非交互模式，跳过所有确认 |

### 手动部署

如需手动部署（不使用脚本），按以下步骤：

```bash
# 1. 安装依赖
sudo apt install python3 python3-venv ufw nginx  # Ubuntu/Debian
# sudo dnf install python3 ufw nginx              # CentOS/RHEL/Fedora

# 2. 克隆代码
git clone https://github.com/lvusyy/UFW-OkBoy.git /opt/ufw-okboy
cd /opt/ufw-okboy

# 3. 创建虚拟环境
python3 -m venv venv
venv/bin/pip install -r server/requirements.txt

# 4. 创建数据目录
mkdir -p /var/lib/ufw-okboy /var/log/ufw-okboy

# 5. 配置
cd server
cp config.example.yaml config.yaml
# 编辑 config.yaml 设置 db_path 和其他参数

# 6. 初始化数据库并创建管理员
../venv/bin/python app.py user-add admin --admin

# 7. 安装 Systemd 服务
cp ../deploy/ufw-okboy.service /etc/systemd/system/
cp ../deploy/ufw-okboy-cleanup.service /etc/systemd/system/
cp ../deploy/ufw-okboy-cleanup.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ufw-okboy
systemctl enable --now ufw-okboy-cleanup.timer

# 8. 配置 Nginx（参考 nginx/ufw-okboy.conf）
# 9. 配置 SSL 证书（certbot 或 openssl 自签）
```

### 验证部署

```bash
# 检查服务状态
systemctl status ufw-okboy

# 检查健康端点
curl https://your-server.com/health
# 应返回: {"ok": true, "service": "ufw-okboy"}

# 打开浏览器访问 https://your-server.com/
# 应看到登录页面

# 检查数据库
sqlite3 /var/lib/ufw-okboy/ufw-okboy.db ".tables"
# 应显示: audit_log  failed_attempts  groups  operation_log  users  user_group_membership
```

### 配置文件参考

`config.yaml` 配置项：

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `listen_host` | `127.0.0.1` | Flask 监听地址（Nginx 反代时保持 127.0.0.1） |
| `listen_port` | `5000` | Flask 监听端口 |
| `signature_ttl` | `300` | HMAC 签名有效期（秒） |
| `rule_prefix` | `ufw-okboy` | UFW 规则注释前缀 |
| `db_path` | `/var/lib/ufw-okboy/ufw-okboy.db` | SQLite 数据库路径 |
| `anomaly_window` | `3600` | 异常检测时间窗口（秒） |
| `anomaly_max_changes` | `5` | 窗口内允许的最大 IP 变更次数 |

> **注意**：v2.0 中用户和端口管理已迁移到 SQLite 数据库 + CLI/API。
> `config.yaml` 不再包含 `users` 和 `protected_ports` 字段。
> 首次运行时如检测到旧版 `config.yaml` 中的 `users` 字段，会自动迁移到数据库。

---

## 用户组与端口管理

v2.0 引入了管理员组和用户组概念，替代了 v1.0 的配置文件管理方式。

### 概念说明

| 概念 | 说明 |
|------|------|
| **管理员组** | `is_admin=1` 的用户，可以通过 CLI/API 管理用户和组 |
| **用户组** | 对应一个端口的访问组，例如 `ssh` 组对应 22 端口 |
| **组成员** | 用户加入组后，其 IP 会在该组对应端口上被授权 |
| **业务组开关** | 用户可自行开关组（`enabled` 字段），仅已开启的组生成规则 |

### 典型使用场景

```
管理员创建组:
  group-add ssh 22         → SSH 访问组
  group-add web 8080       → Web 管理后台组
  group-add db 3306        → 数据库组

用户加入组:
  user-join alice ssh      → Alice 获得 SSH 访问
  user-join alice web      → Alice 同时获得 Web 后台访问
  user-join bob ssh        → Bob 仅获得 SSH 访问

用户开关组:
  PATCH /api/membership/alice/web {enabled: false}
  → Alice 暂时关闭 Web 后台访问，UFW 规则立即移除
  → 重新开启后规则立即恢复
```

### 多组多端口授权

用户加入多个组时，其 IP 会同时在所有已开启组对应的端口上被授权：

```
Alice 加入 ssh(22) + web(8080) + db(3306)
→ ufw allow from Alice_IP to any port 22  # ufw-okboy:alice:ssh
→ ufw allow from Alice_IP to any port 8080 # ufw-okboy:alice:web
→ ufw allow from Alice_IP to any port 3306 # ufw-okboy:alice:db
```

### IP 变更时即时清理

当 Alice 的 IP 从 `1.2.3.4` 变为 `5.6.7.8`：

```
1. 移除旧规则: ufw delete allow from 1.2.3.4 to any port 22
2. 移除旧规则: ufw delete allow from 1.2.3.4 to any port 8080
3. 移除旧规则: ufw delete allow from 1.2.3.4 to any port 3306
4. 添加新规则: ufw allow from 5.6.7.8 to any port 22
5. 添加新规则: ufw allow from 5.6.7.8 to any port 8080
6. 添加新规则: ufw allow from 5.6.7.8 to any port 3306
```

所有操作在一个 HTTP 请求中完成，无感知切换。

---

## CLI 管理命令

v2.0 提供以下 CLI 命令（需 root 权限）：

### 用户管理

```bash
# 创建用户（自动生成密钥）
python app.py user-add alice
# 输出: Created user alice with secret: <64位密钥>

# 创建管理员用户
python app.py user-add admin --admin

# 列出所有用户
python app.py user-list
# ID  Username  Admin  Current IP  Last Knock
#  1  admin     Yes    203.0.113.5  2025-01-15 14:30
#  2  alice     No     198.51.100.3  2025-01-15 14:29

# 删除用户（同时清理 UFW 规则）
python app.py user-del alice

# 设置管理员权限
python app.py admin-add alice
```

### 用户组管理

```bash
# 创建用户组（绑定端口）
python app.py group-add ssh 22
python app.py group-add web 8080
python app.py group-add db 3306 --proto tcp

# 列出所有组
python app.py group-list
# ID  Name  Port  Proto  Created
#  1  ssh   22    tcp    2025-01-15
#  2  web   8080  tcp    2025-01-15

# 删除组（同时清理所有成员的该端口 UFW 规则）
python app.py group-del web
```

### 成员管理

```bash
# 用户加入组
python app.py user-join alice ssh

# 用户离开组（同时移除 UFW 规则）
python app.py user-leave alice ssh
```

### 维护命令

```bash
# 列出所有用户和 UFW 规则
python app.py list

# 清理过期规则（默认 7 天）
python app.py cleanup --max-age 7

# 从 UFW 规则恢复数据库（灾难恢复）
python app.py sync

# 启动服务
python app.py serve --debug
```

---

## REST API

v2.0 提供管理员 REST API，所有端点需要管理员 HMAC 认证。

### 认证方式

所有管理 API 使用与客户端相同的 HMAC-SHA256 认证，但要求用户具有管理员权限：

```
Authorization: HMAC-SHA256 <admin_username>:<timestamp>:<signature>
```

### 用户管理 API

```bash
# 获取用户列表
curl -H "Authorization: HMAC-SHA256 admin:..." https://server/api/admin/users

# 创建用户
curl -X POST -H "Authorization: HMAC-SHA256 admin:..." \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","secret":"<密钥>","is_admin":false}' \
  https://server/api/admin/users

# 删除用户
curl -X DELETE -H "Authorization: HMAC-SHA256 admin:..." \
  https://server/api/admin/users/2
```

### 用户组管理 API

```bash
# 获取组列表
curl -H "Authorization: HMAC-SHA256 admin:..." https://server/api/admin/groups

# 创建组
curl -X POST -H "Authorization: HMAC-SHA256 admin:..." \
  -H "Content-Type: application/json" \
  -d '{"name":"ssh","port":22,"proto":"tcp"}' \
  https://server/api/admin/groups

# 删除组
curl -X DELETE -H "Authorization: HMAC-SHA256 admin:..." \
  https://server/api/admin/groups/1
```

### 成员管理 API

```bash
# 用户加入组
curl -X POST -H "Authorization: HMAC-SHA256 admin:..." \
  -H "Content-Type: application/json" \
  -d '{"group_id":1,"enabled":true}' \
  https://server/api/admin/users/2/groups
```

### 业务组开关 API

用户可自行开关自己的组成员身份（无需管理员权限，但需要自身认证）：

```bash
# 关闭组（移除该端口的 UFW 规则）
curl -X PATCH -H "Authorization: HMAC-SHA256 alice:..." \
  -H "Content-Type: application/json" \
  -d '{"enabled":false}' \
  https://server/api/membership/2/1

# 重新开启组（恢复 UFW 规则）
curl -X PATCH -H "Authorization: HMAC-SHA256 alice:..." \
  -H "Content-Type: application/json" \
  -d '{"enabled":true}' \
  https://server/api/membership/2/1
```

### 客户端 API（向后兼容）

以下端点与 v1.0 完全兼容，现有客户端无需修改：

```bash
# 敲门（注册/更新 IP）
POST /api/knock
Authorization: HMAC-SHA256 alice:<ts>:<sig>

# 查看状态
GET /api/status
Authorization: HMAC-SHA256 alice:<ts>:<sig>

# 健康检查（无需认证）
GET /health
```

---

## 客户端使用

提供三种客户端方式，适应不同使用场景：

| 方式 | 适用场景 | 技术要求 |
|------|----------|----------|
| 网页客户端 | 日常使用，手机/电脑均可 | 只需浏览器 |
| Python 客户端 | 无界面的服务器 | 需要 Python 3 |
| Shell 客户端 | 极简环境 | 只需 curl + openssl |

### 方式一：网页客户端（推荐）

1. 打开浏览器，访问 `https://your-server.com/`
2. 输入管理员提供的**用户名**和**密钥**
3. 勾选 **Remember credentials**（记住凭证）
4. 点击 **Connect**

连接成功后页面显示：
- 绿色状态指示灯和「Connected」文字
- 当前注册的 IP 地址
- 已开启的业务组列表
- 下次自动续期的倒计时（30 秒）

关闭页面后再次打开，会自动恢复连接。

### 方式二：Python 客户端

```bash
# 一键安装（推荐）
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.sh | bash -s -- \
  --server https://your-server.com \
  --user alice \
  --secret YOUR_SECRET

# 手动安装
scp client/knock.py client/config.example.yaml user@client-machine:~/ufw-okboy/
cd ~/ufw-okboy
cp config.example.yaml config.yaml
# 编辑 config.yaml 填入服务器地址、用户名、密钥
pip install pyyaml  # 可选

# 使用
python3 knock.py                    # 单次敲门
python3 knock.py status             # 查看状态
python3 knock.py --watch 30         # 每30秒自动敲门
python3 knock.py --no-verify-ssl    # 自签证书时跳过验证
```

### 方式三：Shell 客户端

零依赖，只需 `curl` 和 `openssl`：

```bash
scp client/knock.sh user@client-machine:/usr/local/bin/ufw-okboy-knock.sh
chmod +x /usr/local/bin/ufw-okboy-knock.sh

# 配置
mkdir -p ~/.config/ufw-okboy
cat > ~/.config/ufw-okboy/config << 'EOF'
SERVER_URL=https://your-server.com
USERNAME=alice
SECRET=你的密钥
EOF
chmod 600 ~/.config/ufw-okboy/config

# 使用
ufw-okboy-knock.sh           # 敲门
ufw-okboy-knock.sh status    # 查看状态

# Cron 定时
crontab -e
# */2 * * * * /usr/local/bin/ufw-okboy-knock.sh >/dev/null 2>&1
```

### 自签证书注意事项

使用自签证书部署时，客户端需要跳过 SSL 验证：

- **Python 客户端**：`python3 knock.py --no-verify-ssl`
- **Shell 客户端**：在 config 中添加 `VERIFY_SSL=false` 或使用 `curl -k`
- **Web 客户端**：浏览器会显示安全警告，点击「高级」→「继续前往」即可

---

## 日常管理

### 查看当前状态

```bash
cd /opt/ufw-okboy/server
../venv/bin/python app.py list
```

输出示例：

```
=== Users ===
  admin                 IP: 203.0.113.5     Last knock: 2025-01-15 14:30
  alice                 IP: 198.51.100.3    Last knock: 2025-01-15 14:29

=== Groups ===
  ssh    port 22/tcp    members: admin, alice
  web    port 8080/tcp  members: alice (enabled)

=== UFW Rules (managed) ===
  22/tcp    ALLOW IN    203.0.113.5    # ufw-okboy:admin:ssh
  22/tcp    ALLOW IN    198.51.100.3   # ufw-okboy:alice:ssh
  8080/tcp  ALLOW IN    198.51.100.3   # ufw-okboy:alice:web
```

### 添加新用户

```bash
../venv/bin/python app.py user-add 新用户名
# 记住输出的密钥，分发给用户
```

### 创建新端口组并加入用户

```bash
../venv/bin/python app.py group-add db 3306
../venv/bin/python app.py user-join alice db
```

### 撤销用户访问

```bash
# 方式 1: 让用户离开特定组
../venv/bin/python app.py user-leave alice web

# 方式 2: 删除用户（清理所有规则）
../venv/bin/python app.py user-del alice

# 方式 3: 用户自行关闭组（通过 API）
curl -X PATCH -H "Authorization: HMAC-SHA256 alice:..." \
  -d '{"enabled":false}' \
  https://server/api/membership/2/1
```

### 更换用户密钥

```bash
# 删除旧用户并重建
../venv/bin/python app.py user-del alice
../venv/bin/python app.py user-add alice
# 重新加入之前的组
../venv/bin/python app.py user-join alice ssh
../venv/bin/python app.py user-join alice web
```

### 查看审计日志

```bash
sqlite3 /var/lib/ufw-okboy/ufw-okboy.db \
  "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 20;"
```

### 清理过期规则

```bash
# 手动清理（超过 7 天未活跃）
../venv/bin/python app.py cleanup --max-age 7

# 定时清理已通过 systemd timer 自动运行
systemctl status ufw-okboy-cleanup.timer
```

### 故障排查

**服务无法启动：**
```bash
journalctl -u ufw-okboy -n 50 --no-pager
```

**用户反馈连接失败：**
```bash
curl https://your-server.com/health
curl http://127.0.0.1:5000/health
tail -f /var/log/ufw-okboy/error.log
```

**数据库问题：**
```bash
# 检查表结构
sqlite3 /var/lib/ufw-okboy/ufw-okboy.db ".schema"

# 从 UFW 规则恢复
../venv/bin/python app.py sync
```

**从 v1.0 升级：**
```bash
cd /opt/ufw-okboy
git pull
venv/bin/pip install -r server/requirements.txt
# 首次启动会自动从 config.yaml 迁移用户到数据库
systemctl restart ufw-okboy
```

---

## 安全机制

### 认证原理

HMAC-SHA256 + 时间戳认证，密钥不在网络上传输：

```
客户端生成签名 = HMAC-SHA256(密钥, "用户名:当前时间戳")
发送请求头: Authorization: HMAC-SHA256 用户名:时间戳:签名
```

- **密钥不在网络上传输** — 即使请求被截获，攻击者得到的是签名，不是密钥
- **时间戳防重放** — 签名在 5 分钟后过期
- **HTTPS 双重保护** — 整个请求经过 TLS 加密传输
- **失败尝试记录** — 认证失败记录到 failed_attempts 表

### 防凭证共享

同一账号只能绑定一个 IP。Alice 将凭证分享给 Bob 后：
1. Bob 连接 → 防火墙更新为 Bob 的 IP
2. Alice 立刻失去访问权限
3. Alice 续期 → 又把 Bob 踢掉
4. 两人不断互相踢，谁都无法稳定使用

**结论：共享凭证 = 自损。**

### 异常检测

1 小时内 IP 变更超过 5 次会触发告警：

```bash
grep "ANOMALY" /var/log/ufw-okboy/error.log
```

### 审计日志

所有管理操作记录到 audit_log 表：

```sql
SELECT actor, action, target, detail, created_at
FROM audit_log
ORDER BY created_at DESC
LIMIT 20;
```

### 安全最佳实践

| 建议 | 说明 |
|------|------|
| 一人一号 | 不要多人共用同一个账号 |
| 及时换密钥 | 怀疑泄露时立即删除重建用户 |
| 保护配置文件 | config.yaml 权限设为 600 |
| 启用自动清理 | 让不活跃的规则自动过期 |
| 监控审计日志 | 定期检查 audit_log 表 |
| HTTPS 必须开启 | 不要在 HTTP 下使用 |
| 使用域名+Let's Encrypt | 优于自签证书，浏览器无警告 |

---

## 常见问题

### 我的 IP 变了怎么办？

什么都不需要做。网页客户端会在 30 秒内自动检测并更新。Python/Shell 客户端在下一个执行周期自动更新。

### 关掉网页后怎么办？

规则不会立即消失，保留到被清理为止（默认 7 天）。再次打开网页即可恢复。

### 如何只允许用户访问特定端口？

使用用户组。创建不同端口对应的组，让用户只加入需要的组：

```bash
python app.py group-add ssh 22
python app.py group-add db 3306
python app.py user-join alice ssh    # Alice 只能访问 22
python app.py user-join bob db       # Bob 只能访问 3306
```

### 如何临时关闭某端口的访问？

用户可自行关闭组（通过 API 或 Web UI），或管理员让用户离开组：

```bash
# 管理员操作
python app.py user-leave alice web

# 用户自行关闭
curl -X PATCH -H "Authorization: HMAC-SHA256 alice:..." \
  -d '{"enabled":false}' https://server/api/membership/2/2
```

### 自签证书如何使用？

部署时加 `--self-signed` 参数。客户端需要：
- Python：`--no-verify-ssl` 标志
- Shell：`curl -k` 或配置 `VERIFY_SSL=false`
- 浏览器：接受安全警告后继续

### 数据库丢失怎么办？

从 UFW 规则恢复：
```bash
python app.py sync
```

如 UFW 规则也丢失，需要重新创建用户和组。

### 如何升级到 v2.0？

```bash
cd /opt/ufw-okboy
git pull
venv/bin/pip install -r server/requirements.txt
systemctl restart ufw-okboy
# 首次启动自动从旧 config.yaml 迁移用户到数据库
# 迁移后所有旧用户自动加入 default-<port> 组
```

### 应该备份什么？

SQLite 数据库文件：`/var/lib/ufw-okboy/ufw-okboy.db`

```bash
cp /var/lib/ufw-okboy/ufw-okboy.db /备份路径/ufw-okboy.db.bak
```
