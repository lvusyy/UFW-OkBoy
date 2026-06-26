# UFW OkBoy

**动态防火墙白名单管理** — 授权用户登录一次，服务器自动把他们的 IP 加进 UFW 白名单；IP 变了下个心跳无感切换，规则始终整洁可追溯。

[English](README.en.md) | 中文

<p align="center">
  <img src="docs/web-client.png" alt="Web 客户端界面" width="380">
</p>

---

## 这是什么

服务器的敏感端口（管理后台、数据库、SSH、API）通常用 UFW 只放行固定 IP。但人的 IP 老在变——换 WiFi、出差、重启路由器——每次都得找管理员手动改防火墙。

**UFW OkBoy 把这件事自动化**：用户打开网页登录一次，页面每 30 秒自动「敲门」，服务器据此更新防火墙。IP 变了自动换，人走了规则自动过期清理。

## 能做什么

| 能力 | 说明 |
|------|------|
| 🌐 **网页一键连** | 浏览器打开登录即用，自动续期、自动重连，手机也能用 |
| 🔄 **IP 自动切换** | 每用户每端口仅一条规则，IP 变更自动替换，不留残余 |
| 👥 **分组授权** | 管理员建组绑端口、管理成员；用户可自助开关已授权的组 |
| 🖥️ **网页管理台** | 用户 / 分组 / 规则、审计日志、TOTP、系统防火墙规则，全在网页搞定，无需 SSH |
| 🔐 **认证安全** | HMAC-SHA256 + 时间戳（密钥不上网）、TOTP 二次验证、失败限流、操作审计 |
| 🇨🇳 **国内友好** | 离线安装包 + 镜像兜底 + 自签证书 + 公网 IP + 高位端口，**无需备案域名** |
| 🧰 **三种客户端** | 网页 / Python（`knock.py`）/ Shell（`knock.sh`，零依赖） |

## 快速开始

### 1. 装服务端（一行命令，root 执行）

```bash
# 自签证书，无需域名，装完用 IP:端口 访问（个人服 / 国内最常用）
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh | bash -s -- --self-signed -y
```

> 有备案域名？把 `--self-signed` 换成 `--domain your.server.com`，自动签 Let's Encrypt 证书。
> 装完会在输出**最末尾高亮打印** `admin` 账号和它的 token——复制好。

### 2. 开始用

浏览器打开 `https://你的服务器:端口/` → 输入 `admin` 和 token → 点 **Connect**。
页面会每 30 秒自动续期，你当前的 IP 就一直留在白名单里。想换密钥？管理台里点「更换密钥」即可，不用重装。

### 3. 加用户、加端口（管理台点几下）

登录后点 **Admin** 进管理台：建用户拿 token、建分组绑端口、把用户加进组。
然后把「服务器地址 + 用户名 + token」发给同事，他们打开网页登录就行（无界面的服务器用下面的命令行客户端）。

### 给无界面服务器装命令行客户端

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.sh \
  | bash -s -- --server https://你的服务器:端口 --user alice --secret 用户的token
```

## 国内安装（中国大陆）

GitHub/PyPI 慢或不通、域名要备案、惯用高位端口 + 自签证书——这些都做了专门处理。**最稳的是离线安装包**：

```bash
# 在能联网的机器上构建（产物自带依赖 wheels）
bash deploy/build-release.sh
# 把 dist/ufw-okboy-*.tar.gz 拷到服务器后：
tar xzf ufw-okboy-*.tar.gz && cd ufw-okboy-* && sudo bash install.sh --self-signed -y
```

在线但 GitHub 受阻时走镜像（代理会失效，最新地址查 <https://ghproxy.link/>）：

```bash
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh \
  | bash -s -- --gh-mirror https://ghfast.top --self-signed --port 8443 --ip <你的公网IP> -y
```

📖 手把手步骤 + 逐项排查见 **[国内部署专题](GUIDE.md#国内部署专题)**——装不上时先翻它。

## 常见问题

**装完 SSH / 远程连不上了？**
请确认用的是 **v2.2.1 及以上**（旧版有此隐患，已修复）；新版安装会先放行 SSH 再启用防火墙。万一被锁在外面：用云厂商**控制台 / VNC** 登录，执行 `sudo ufw allow 22/tcp && sudo ufw reload`。

**网页能打开，但端口连不上？**
九成是**云安全组**没放行该端口。UFW 和云厂商安全组是两层，**两层都要放行**。

**用自签证书，客户端报 TLS 错误？**
`knock.py` 在 `config.yaml` 设 `verify_ssl: false`；`knock.sh` 设 `INSECURE=1`（或加 `--insecure`）。HMAC 密钥永不上网，只是关掉传输层证书校验。

**忘了 / 泄露了密钥？**
管理台里对该用户点「更换密钥」（自己则点自助更换）；或在服务器执行 `python app.py revoke <用户>`——关端口 + 轮换密钥，旧凭据即时失效。

**怎么升级？**
```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/upgrade.sh | bash
```
自动备份 → 更新 → 重启 → 健康检查，失败回滚；配置 / 数据库 / 证书都保留。升级后浏览器硬刷新（Ctrl-Shift-R）。

更多问题见 **[完整指南](GUIDE.md)**。

## 文档与版本

- 📘 **[完整部署与使用指南 · GUIDE.md](GUIDE.md)** — 服务端 / Nginx / Systemd、手动安装、密钥分发、客户端、日常运维、安全机制、FAQ
- 📝 **[更新记录 · CHANGELOG.md](CHANGELOG.md)** ｜ **[GitHub Releases](https://github.com/lvusyy/UFW-OkBoy/releases)**

## 许可证

MIT
