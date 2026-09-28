# UFW OkBoy

[![CI](https://github.com/lvusyy/UFW-OkBoy/actions/workflows/ci.yml/badge.svg)](https://github.com/lvusyy/UFW-OkBoy/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/lvusyy/UFW-OkBoy?sort=semver)](https://github.com/lvusyy/UFW-OkBoy/releases)
[![Python](https://img.shields.io/badge/python-3.10%E2%80%933.14-3776AB?logo=python&logoColor=white)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**UFW 动态白名单。** 授权用户认证一次，服务器就把他当前的 IP 放行到他被授权的端口；IP 变了自动切换，长期不用自动收回，每条规则都能追溯到具体的用户和分组。

简体中文 | [English](README.en.md)

<p align="center">
  <img src="docs/web-client.png" alt="网页客户端" width="380">
</p>

## 为什么需要它

SSH、管理后台、数据库这类端口通常只对固定 IP 开放。可人的出口 IP 总在变：家宽重拨、换网络、出差。每变一次就得有人登录服务器改防火墙。

UFW OkBoy 让授权用户自己「敲门」：客户端定时发送带签名的请求，服务端验证后把请求的来源 IP 放行到该用户所在分组的端口；IP 变化时换掉旧规则，长期不敲门的用户由每日清理任务收回。

## 功能

- **按分组授权**：分组绑定一个端口和协议，用户加入分组后，敲门即为其当前 IP 放行该端口。
- **IP 自动切换**：每次敲门都按数据库对账，先放行新 IP，再删除旧 IP 和已失效分组的规则。每条规则带注释 `ufw-okboy:<用户>:<分组>`。
- **自动收回**：每日清理任务删除 7 天未敲门用户的全部规则。
- **四种客户端**：网页（每 30 秒续期）、Python `knock.py`、Shell `knock.sh`（只需 curl 和 openssl）、Windows `knock.ps1`（计划任务，系统自带 PowerShell 即可）。
- **网页管理台**：用户、分组、成员、审计日志、TOTP、系统防火墙规则，都在浏览器里管理。
- **认证与防护**：HMAC-SHA256 签名，密钥不在网络上传输；管理员写操作可要求 TOTP 二次验证；认证失败按 IP 限流，TOTP 失败按账号封顶；所有防火墙改动由跨进程锁串行执行；操作写入审计日志。
- **适应受限网络**：发布包自带 Python 依赖，可离线安装；GitHub 与 PyPI 可走镜像；自签证书加高位端口即可使用，无需域名。

## 工作原理

```text
客户端（浏览器 / knock.py / knock.sh / knock.ps1）
    │  HTTPS；Authorization: HMAC-SHA256 <用户>:<时间戳>:<签名>
    ▼
Nginx（TLS 终止，传递 X-Real-IP）
    │  http://127.0.0.1:5000
    ▼
Gunicorn + Flask（server/app.py）──── SQLite（用户、分组、成员、审计）
    │  ufw 命令（跨进程锁串行）
    ▼
UFW：allow from <客户端 IP> to any port <端口> proto <协议>   # ufw-okboy:<用户>:<分组>
```

签名为 `HMAC-SHA256(密钥, "<用户>:<时间戳>")`，时间戳与服务器时间相差超过 `signature_ttl`（默认 300 秒）即拒绝。

## 系统要求

- Linux，已安装 UFW，root 权限。
- Python 3.10 或更高。Ubuntu 22.04+、Debian 12+、Fedora 自带；RHEL 系 8/9 的默认 `python3` 较旧，安装脚本会改装 `python3.12`（或 `python3.11`）。
- 安装脚本支持 Debian/Ubuntu 与 RHEL 系（RHEL、Rocky、AlmaLinux、Fedora；ufw 来自 EPEL）。RHEL 系要先停用 firewalld，SELinux 为 enforcing 时还需额外设置，见 [GUIDE](GUIDE.md#环境要求)。

## 快速开始

### 1. 安装服务端

在线一键安装（自签证书，装完用 `https://服务器IP:端口/` 访问）：

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh \
  | sudo bash -s -- --self-signed --port 8443 -y
```

有解析到本机的域名时，把 `--self-signed` 换成 `--domain your.example.com`，会自动申请 Let's Encrypt 证书。证书的申请和续期都经过 80 端口：安装脚本会在 UFW 里放行它，云安全组也要放行。

或者用发布包安装指定版本（包内带 Python 依赖，不需要访问 PyPI）：

```bash
V=v2.4.1
curl -fsSLO https://github.com/lvusyy/UFW-OkBoy/releases/download/$V/ufw-okboy-$V.tar.gz
curl -fsSLO https://github.com/lvusyy/UFW-OkBoy/releases/download/$V/ufw-okboy-$V.tar.gz.sha256
sha256sum -c ufw-okboy-$V.tar.gz.sha256
tar xzf ufw-okboy-$V.tar.gz && cd ufw-okboy-$V
sudo bash install.sh --self-signed --port 8443 -y
```

安装结束时会在输出的**最后**打印管理员 `admin` 的密钥，只显示这一次，请立即保存。

> 云服务器还要在安全组里放行这个端口。UFW 和安全组是两层，两层都要放行。

### 2. 登录

浏览器打开 `https://服务器:端口/`，输入 `admin` 和密钥，点 **Connect**。页面每 30 秒续期一次，你当前的 IP 会一直留在白名单里。

### 3. 添加用户和分组

在管理台（**Admin**）里建用户、建分组（端口 + 协议）、把用户加进分组；新用户的密钥在创建时显示。也可以用命令行：

```bash
cd /opt/ufw-okboy/server
sudo ../venv/bin/python app.py -c config.yaml user-add alice          # 打印 alice 的密钥
sudo ../venv/bin/python app.py -c config.yaml group-add web 8080
sudo ../venv/bin/python app.py -c config.yaml user-join alice web
```

> **把 SSH（22 端口）交给它管理之前**：先确认自己能敲门成功，在另一个终端里新开一个 SSH 会话验证能登录，再关闭当前会话。否则可能把自己锁在外面。

然后把「服务器地址 + 用户名 + 密钥」交给对方，对方用网页或下面的客户端即可。

## 客户端

| 客户端 | 适用场景 | 安装 |
|--------|----------|------|
| 网页 | 有浏览器的电脑、手机 | 打开服务器地址即可 |
| `knock.py` | Linux 服务器、无界面环境 | `deploy/install-client.sh`（systemd 定时器） |
| `knock.sh` | 只有 curl + openssl 的环境 | 复制脚本，配 cron |
| `knock.ps1` | Windows | `deploy/install-client.ps1`（SYSTEM 计划任务） |

Linux（安装 `knock.py` 和 systemd 定时器，默认每 30 秒敲一次）：

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.sh \
  | sudo bash -s -- --server https://your-server:8443 --user alice --secret <密钥> --no-verify-ssl
```

Windows（以管理员身份打开 PowerShell；密钥会提示输入且不回显；服务器用自签证书时末尾加 `-NoVerifySsl`）：

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.ps1))) -Server https://your-server:8443 -User alice
```

计划任务以 SYSTEM 身份每分钟敲一次，开机即生效。要敲多台服务器，换一个 `-Server` 再运行一次；卸载加 `-Uninstall`。

`--no-verify-ssl`、`-NoVerifySsl` 关闭 TLS 证书校验，用于自签证书。关闭之后，网络路径上的中间人可以截获敲门请求，在签名有效期内（默认 300 秒）重放它，把他自己的地址加进白名单。在不可信的网络上请使用受信任的证书，例如用 `--domain` 申请的 Let's Encrypt 证书。

## 升级

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/upgrade.sh \
  | sudo bash -s -- --branch v2.4.1
```

脚本依次备份数据库、更新代码和依赖、重启服务并做健康检查，失败时自动退回旧代码。配置、证书和数据库都会保留。也可以在解压好的发布包里离线升级：`sudo bash deploy/upgrade.sh --repo-dir . -y`。如果 `/opt/ufw-okboy` 是 git 检出的仓库，请按 [GUIDE 的升级章节](GUIDE.md#升级与版本管理) 操作。升级后浏览器按 Ctrl+Shift+R 强制刷新。

## 安全

- 认证请求只携带签名，不携带密钥；新建用户或更换密钥时，新密钥经 HTTPS 返回一次。传输层依赖 HTTPS。
- 管理员启用 TOTP 后，每个管理写操作都要验证码；设置 `require_admin_totp: true` 后，没有启用 TOTP 的管理员在启用之前不能执行这些操作。
- 数据库、备份和写有密钥的配置文件都只有 root 可读。
- 已知限制（例如签名在有效期内可被重放）和漏洞报告方式见 [SECURITY.md](SECURITY.md)。请不要在公开 issue 里报告漏洞。

## 常见问题

**装完之后 SSH 连不上了？**
v2.2.1 起，安装脚本会先放行 SSH 再启用 UFW；UFW 已经启用时，不会改动 SSH 规则。万一被锁在外面，请用云厂商的控制台或 VNC 登录，执行 `sudo ufw allow 22/tcp`。

**网页能打开，端口却连不上？**
多半是云安全组没有放行该端口。

**密钥忘了或泄露了？**
在管理台里对该用户点「吊销」：关闭他的端口并更换密钥，旧密钥立即失效。自己的密钥点「更换密钥」。命令行：`sudo ../venv/bin/python app.py -c config.yaml revoke <用户>`。

**用 v2.2.1 或更早的版本装过？**
旧安装脚本会建出密钥公开的示例用户 `alice`。升级到 v2.2.2 或更高版本后，这个密钥会自动作废；之后用 `user-list` 看看 `alice` 是否还在，不需要就删掉。详见 [CHANGELOG · v2.2.2](CHANGELOG.md#v222-2026-09-27)。

更多问题见 [GUIDE.md](GUIDE.md)，国内网络环境见 [国内部署专题](GUIDE.md#国内部署专题)。

## 文档

- [GUIDE.md](GUIDE.md)：部署、配置、命令行、REST API、客户端、日常运维、安全机制
- [CHANGELOG.md](CHANGELOG.md)：版本记录与升级须知
- [SECURITY.md](SECURITY.md)：安全策略与漏洞报告
- [Releases](https://github.com/lvusyy/UFW-OkBoy/releases)：发布包与校验和

## 开发

```bash
cd server
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

真实 ufw 的集成测试（`tests/test_ufw_integration.py`）需要 root，并在独立的网络与挂载命名空间里运行，不会碰到本机防火墙；做法见 [CI 配置](.github/workflows/ci.yml)。

## 许可证

[MIT](LICENSE)
