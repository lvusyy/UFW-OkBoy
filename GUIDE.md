# UFW OkBoy 使用指南

> 动态防火墙白名单管理工具 v2.4.2：让授权用户的 IP 变更不再需要手动处理。

本指南覆盖部署、配置、网页管理台、命令行、REST API、客户端与日常运维。项目概览见 [README](README.md)，版本变化见 [CHANGELOG](CHANGELOG.md)，漏洞报告方式与已知限制见 [SECURITY](SECURITY.md)。

---

## 目录

- [这是什么](#这是什么)
- [工作原理](#工作原理)
- [一键部署](#一键部署)
- [国内部署专题](#国内部署专题)
- [快速开始](#快速开始)
- [服务端部署](#服务端部署)
- [用户组与端口管理](#用户组与端口管理)
- [网页管理台](#网页管理台)
- [CLI 管理命令](#cli-管理命令)
- [REST API](#rest-api)
- [客户端使用](#客户端使用)
- [日常管理](#日常管理)
- [安全机制](#安全机制)
- [安全加固](#安全加固)
- [升级与版本管理](#升级与版本管理)
- [常见问题](#常见问题)

---

## 这是什么

你的服务器上有一些端口（比如管理后台、数据库）只允许特定 IP 访问，通过 UFW 防火墙的白名单来控制。但用户的 IP 会变（切换网络、重启路由器、出差），每次变化都要联系管理员手动更新防火墙。

**UFW OkBoy** 解决的就是这个问题：

- 用户打开一个网页，完成一次认证
- 服务器识别用户当前的 IP，更新防火墙白名单
- 只要网页不关，每 30 秒自动「续期」一次
- 用户 IP 变了？下一次续期自动切换，无需任何操作
- 管理员在网页管理台、命令行或 REST API 中管理用户和分组，无需修改配置文件
- 每个分组对应一个端口（TCP 或 UDP），用户加入多个分组即获得多个端口的访问授权
- 管理员授予的分组，用户可以自行关闭、再重新开启；新的授权只能由管理员给出

一句话总结：**用户只需要打开网页，防火墙的事交给系统处理。**

## 工作原理

```text
用户浏览器 / 客户端脚本
      │  HTTPS；Authorization: HMAC-SHA256 <用户名>:<时间戳>:<签名>
      ▼
Nginx（TLS 终止，把客户端地址放进 X-Real-IP）
      │  http://127.0.0.1:5000
      ▼
Gunicorn + Flask（校验签名，读取用户已开启的分组）──── SQLite（用户、分组、成员资格、日志）
      │  ufw 命令（主机锁串行执行）
      ▼
UFW：先放行新 IP，再删除旧 IP 与失效分组的规则
     规则注释：ufw-okboy:<用户名>:<分组名>
```

用 `--no-nginx` 部署时没有 Nginx 这一层，Gunicorn 直接以 TLS 监听对外端口。

**关键机制：**

| 特性 | 说明 |
|------|------|
| 认证方式 | HMAC-SHA256 签名 + 时间戳，密钥不在网络上传输 |
| 数据存储 | SQLite 数据库（WAL 模式），数据库文件只有 root 可读写 |
| 用户管理 | 网页管理台、命令行、REST API，管理员权限控制，无需修改配置文件 |
| 分组 | 每个分组对应一个端口和协议，用户可以加入多个分组 |
| 分组开关 | 成员资格可以关闭、再开启，只有开启的分组生成防火墙规则 |
| 规则管理 | 每个用户在每个开启的分组上只保留一条规则（当前 IP），每次敲门都与数据库对账 |
| 规则标记 | 每条规则带注释 `ufw-okboy:用户名:分组名`，`ufw status` 一目了然 |
| 串行执行 | 敲门、管理操作、命令行和清理任务改动防火墙时共用一把主机锁（数据目录下的 `ufw.lock`） |
| 审计日志 | 管理操作记录到 `audit_log` 表，可在管理台查看 |
| 过期清理 | 每日清理任务删除 7 天未敲门用户的全部规则 |
| 防盗用 | 同一账号同一时间只绑定一个 IP，共享凭证 = 互相踢 |

## 一键部署

> **国内服务器**（GitHub/PyPI 下载慢、没有备案域名、惯用高位端口 + 自签证书）请先读 [国内部署专题](#国内部署专题)。

### 服务端一键安装

安装脚本需要 root 权限。

**自签证书模式（无需域名，用 IP 直接访问）：**

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh \
  | sudo bash -s -- --self-signed -y
```

**域名模式（自动申请 Let's Encrypt 证书）：**

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh \
  | sudo bash -s -- --domain ufw.example.com -y
```

`quick-install.sh` 下载 master 分支的最新代码，再用同样的参数运行 `deploy/deploy.sh`（参数见 [部署脚本参数](#部署脚本参数)）。要安装指定版本，用发布包。

### 从发布包安装

v2.4.1 起，GitHub Release 上的发布包自带 Python 依赖（CPython 3.10–3.14，x86_64 与 aarch64 的 wheels），安装时不访问 PyPI：

```bash
V=v2.4.2
curl -fsSLO https://github.com/lvusyy/UFW-OkBoy/releases/download/$V/ufw-okboy-$V.tar.gz
curl -fsSLO https://github.com/lvusyy/UFW-OkBoy/releases/download/$V/ufw-okboy-$V.tar.gz.sha256
sha256sum -c ufw-okboy-$V.tar.gz.sha256
tar xzf ufw-okboy-$V.tar.gz
cd ufw-okboy-$V
sudo bash install.sh --self-signed -y
```

`install.sh` 直接调用包里的 `deploy/deploy.sh`，参数相同。ufw、nginx、python3 等系统软件包仍由 apt 或 dnf/yum 安装。

### 安装脚本做了什么

一键安装和发布包最终都运行 `deploy/deploy.sh`，它依次完成：

1. 检测发行版，安装 ufw、nginx 和 python3（域名模式另装 certbot；Fedora 以外的 RHEL 系先装 EPEL）。
2. 选定 Python 3.10+：发行版自带的 `python3` 够新就用它，否则找已安装的 `python3.14`–`python3.10`；RHEL 系还会尝试安装 `python3.12`（或 `python3.11`）；仍不满足则在改动 UFW 之前报错退出。
3. UFW 尚未启用时，先放行 SSH（`sshd_config` 中配置的端口，未配置时为 22，以及 `OpenSSH` 应用配置），再启用 UFW；UFW 已启用时不改动 SSH 规则。
4. 把程序装到 `/opt/ufw-okboy`（源码目录就是安装目录时原地安装），创建虚拟环境并安装 Python 依赖：发布包自带的 wheels 优先，其次是 `--mirror` 指定的索引，连不上 pypi.org 时改用清华镜像。
5. 没有 `config.yaml` 时从 `config.example.yaml` 复制一份（默认值即可使用），已有则保留。
6. 生成证书：自签（有效期 10 年，CN/SAN 为自动探测到的公网 IP 或 `--ip` 指定的地址）或 Let's Encrypt（先在 UFW 里放行 80 端口；申请失败时退回自签）。
7. 生成 Nginx 站点配置（Debian/Ubuntu 写在 `sites-available/` 并链接到 `sites-enabled/`，RHEL 系写在 `conf.d/`），设为开机启动并重载（`--no-nginx` 时由 Gunicorn 直接提供 HTTPS）。
8. 写入 systemd 服务 `ufw-okboy.service` 与每日清理定时器 `ufw-okboy-cleanup.timer`，并重启服务。
9. 用 `ufw allow <端口>/tcp` 放行 HTTPS 端口。
10. 创建管理员 `admin`（`--admin-user` 可改名），在输出的**最后**打印它的密钥，只显示这一次；该用户已存在时不重建，也不打印密钥。

> 云服务器还要在安全组里放行这个端口：UFW 和安全组是两层，两层都要放行。

### 客户端一键安装

Linux：

```bash
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.sh \
  | sudo bash -s -- --server https://your-server:8443 --user alice --secret YOUR_SECRET
```

自动完成：

- 安装 `knock.py` 为 `/usr/local/bin/ufw-okboy-knock`
- 写入配置 `~/.config/ufw-okboy/config.yaml`（权限 600，实际路径在安装结束时打印）
- 试敲一次门
- 安装 systemd 定时器 `ufw-okboy-knock.timer`，默认每 30 秒敲门一次

参数见 [方式二：Python 客户端](#方式二python-客户端)。Windows 电脑用 PowerShell 一键安装，见 [方式四：Windows 客户端](#方式四windows-客户端)。

## 国内部署专题

> 常见的失败大多来自三处：GitHub/PyPI 访问慢或不通、域名需要备案、习惯用高位端口加自签证书。下面说明安装脚本对每一处的处理，以及需要你做的事。

### 最稳路径：发布包离线安装（推荐）

发布包自带全部 Python 依赖（CPython 3.10–3.14，x86_64 与 aarch64），装依赖时不访问 PyPI，只需下载一个压缩包。系统软件包仍由 apt/dnf 安装，下载慢时先把系统软件源换成国内镜像。

```bash
V=v2.4.2
# 第 1 步：下载发布包与校验和。GitHub 不通时在地址前加代理前缀（如下），
#         或在能访问 GitHub 的机器上下载后拷到服务器
curl -fsSLO https://ghfast.top/https://github.com/lvusyy/UFW-OkBoy/releases/download/$V/ufw-okboy-$V.tar.gz
curl -fsSLO https://ghfast.top/https://github.com/lvusyy/UFW-OkBoy/releases/download/$V/ufw-okboy-$V.tar.gz.sha256
sha256sum -c ufw-okboy-$V.tar.gz.sha256

# 第 2 步：解压并安装（自签证书 + 高位端口）
tar xzf ufw-okboy-$V.tar.gz
cd ufw-okboy-$V
sudo bash install.sh --self-signed --port 8443 -y
```

- 经代理下载时，校验和文件也来自同一个代理，只能发现传输损坏。要防篡改，请通过可信渠道（例如在能直连 GitHub 的机器上）取得 `.sha256` 文件再核对。
- 包里的 `vendor/` 就是这些 wheels。服务器的 Python 版本或 CPU 架构不在其中时，安装会退回在线索引；加 `--offline` 则直接报错。
- 也可以自己打包：在能联网的机器上执行 `bash deploy/build-release.sh`，产物在 `dist/`，见 [构建发布包](#构建发布包)。

### 在线安装（GitHub/PyPI 慢时用镜像兜底）

```bash
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh \
  | sudo bash -s -- --gh-mirror https://ghfast.top --self-signed --port 8443 --ip 203.0.113.10 -y
```

把 `203.0.113.10` 换成服务器的公网 IP。

> **注意**：GitHub 代理会不定期失效。上面的 `https://ghfast.top` 只是示例；不通时到 https://ghproxy.link/ 查当前可用的地址，同时替换开头 `curl` 的前缀和 `--gh-mirror`（两处用同一个）。经代理安装，等于信任该代理提供的代码。

- `--gh-mirror`：GitHub 代理前缀，由 `quick-install.sh` 拉代码时使用；其余参数原样传给 `deploy.sh`。
- PyPI：连不上 pypi.org 时自动改用清华镜像；也可以用 `--mirror https://pypi.tuna.tsinghua.edu.cn/simple` 显式指定。

### 关键点速查

| 关注点 | 安装脚本的处理 | 你要做的 |
|---|---|---|
| 没有备案域名 | 不带 `--domain` 时使用自签证书，通过公网 IP 访问 | 无 |
| 公网 IP 与网卡 IP 不同（云主机） | 自动探测公网 IP，写进自签证书的 CN/SAN | NAT 环境加 `--ip <公网 IP>` 更稳妥 |
| 高位端口 | `--port 8443` 可用任意端口，脚本自动 `ufw allow` | 在云控制台的安全组里也放行该端口（UFW ≠ 安全组） |
| 证书过期 | 自签证书有效期 10 年 | 无 |
| 客户端连自签证书报错 | 见下节 | 给客户端配上服务器的公钥 pin：`pin_sha256`（knock.py、knock.ps1）/ `PIN_SHA256`（knock.sh） |

### 客户端连自签证书

自签证书没法靠 CA 验证，命令行客户端改为认服务器的**公钥 pin**：服务器公钥（SubjectPublicKeyInfo）的 SHA-256，用 base64 表示，与 curl `--pinnedpubkey sha256//…` 同一格式。配上之后，客户端只接受这把公钥，连到别的服务器（包括中间人）时在发出请求之前就会停下。

服务端安装结束时会打印 pin（`Client key pin`），之后也可以随时在服务器上重新算出：

```bash
openssl x509 -in /etc/ssl/ufw-okboy/selfsigned.crt -pubkey -noout \
  | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
```

pin 要经可信的渠道拿到（服务器上的这条命令、管理员本人），不要现连服务器去取。重新运行安装脚本会续签证书但沿用原来的私钥，pin 不变；删掉 `/etc/ssl/ufw-okboy/selfsigned.key` 再运行才会换新密钥，这时要把新 pin 发给所有客户端。

- **网页端**：浏览器首次访问会提示安全警告。先核对证书指纹与服务器上的一致（在服务器上执行 `openssl x509 -in /etc/ssl/ufw-okboy/selfsigned.crt -noout -fingerprint -sha256`），再确认继续。之后若再次出现警告，说明证书变了，不要继续：在中间人伪造的页面里输入的密钥会被窃取。重新运行安装脚本续签后指纹也会变，核对新指纹即可。
- **Python 客户端 `knock.py`**：在 `config.yaml` 里加 `pin_sha256: "<pin>"`。这时 `knock.py` 直接连接服务器，不经 `HTTPS_PROXY`。
- **Shell 客户端 `knock.sh`**：在配置文件里加 `PIN_SHA256=<pin>`（需要 curl 7.49 及以上：更早的版本在部分 TLS 后端上会忽略 pin，`knock.sh` 会拒绝使用；TLS 后端不支持 sha256 pin 时 curl 报错退出，不会发出请求，见 curl 文档中的 CURLOPT_PINNEDPUBLICKEY）。
- **Windows 客户端 `knock.ps1`**：在服务器的配置文件里加 `pin_sha256: "<pin>"`。
- **Linux 一键装客户端**：加 `--pin-sha256 <pin>`，脚本会把它写进配置：

```bash
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.sh \
  | sudo bash -s -- --server https://203.0.113.10:8443 --user alice --secret YOUR_SECRET \
               --pin-sha256 <pin> --gh-mirror https://ghfast.top
```

- **Windows 一键装客户端**：同样加 `-PinSha256 <pin>`；GitHub 不通时，脚本地址和 `-GhMirror` 都走代理：

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
& ([scriptblock]::Create((irm https://ghfast.top/https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.ps1))) -Server https://203.0.113.10:8443 -User alice -PinSha256 <pin> -GhMirror https://ghfast.top
```

  代理会原样转发脚本，而 `knock.ps1` 之后以 SYSTEM 身份运行，所以只用你信任的代理。更稳的是发布包：解压后运行其中的 `deploy\install-client.ps1`，它直接用包里的 `client\knock.ps1`，不再联网下载（见 [方式四](#方式四windows-客户端)）。

配了 pin，`verify_ssl`、`INSECURE` 以及 `--no-verify-ssl`、`--insecure`、`-Insecure` 就不再起作用。也可以不配 pin 而直接关闭证书校验（`verify_ssl: false`、`INSECURE=1`，一键安装时 `--no-verify-ssl`、`-NoVerifySsl`），这样能连上，但无法识别中间人：敲门请求只带签名、不带密钥，密钥本身不会泄露，截获的签名头却能在有效期内被重放（见 [SECURITY.md](SECURITY.md) 的已知限制）。已经这样装好的客户端，按上面的方法补上 pin 即可。有域名时优先用 Let's Encrypt 证书，它不需要 pin。

### 升级（国内）

```bash
# 离线升级：在解压好的新版本发布包目录里执行
cd ufw-okboy-v2.4.2
sudo bash deploy/upgrade.sh --repo-dir . -y

# 在线升级：升级脚本和代码都经 GitHub 代理下载（当前可用地址见 https://ghproxy.link/）
curl -fsSL https://ghfast.top/https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/upgrade.sh \
  | sudo bash -s -- --gh-mirror https://ghfast.top --branch v2.4.2
```

`app.py upgrade` 只用于 git 检出的安装：查询最新版本时可以经 `config.yaml` 的 `github_mirror` 或环境变量 `UFW_OKBOY_GH_MIRROR` 走代理；更新代码用的是检出自己的 git 远端（`git pull --ff-only`），不经过这个代理。详见 [升级与版本管理](#升级与版本管理)。

## 快速开始

> 最短路径：一行命令部署服务端，用户用浏览器登录即可。

### 服务端（管理员操作）

```bash
# 方式 1：一键部署（推荐）
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/quick-install.sh \
  | sudo bash -s -- --self-signed -y

# 方式 2：把仓库检出到安装目录再部署（之后可用 app.py upgrade 升级）
sudo git clone https://github.com/lvusyy/UFW-OkBoy.git /opt/ufw-okboy
cd /opt/ufw-okboy
sudo bash deploy/deploy.sh --self-signed -y
```

安装脚本已经创建了管理员 `admin`，密钥在输出的最后打印（只显示这一次）。接着建一个分组，把自己加进去：

```bash
cd /opt/ufw-okboy/server
sudo ../venv/bin/python app.py -c config.yaml group-add web 8080     # 创建分组（8080/tcp）
sudo ../venv/bin/python app.py -c config.yaml user-join admin web    # 管理员加入分组
```

这两步也可以在 [网页管理台](#网页管理台) 里完成。要让 OkBoy 管理 SSH（22 端口），先读 [用 OkBoy 管理 SSH（22 端口）](#用-okboy-管理-ssh22-端口)。

### 客户端（用户操作）

1. 用浏览器打开 `https://<服务器地址>:<端口>/`（端口为 443 时可省略；自签证书时浏览器会警告，先按[客户端连自签证书](#客户端连自签证书)核对证书指纹再继续）
2. 输入管理员给你的**用户名**和**密钥**
3. 点击「连接」（英文界面为 **Connect**）

页面每 30 秒续期一次。勾选「记住凭据」且没有设置 PIN 时，下次打开页面自动连接；设置了 PIN 时，下次打开要先输入 PIN。详见 [网页管理台](#网页管理台)。

---

## 服务端部署

### 环境要求

| 项目 | 要求 |
|------|------|
| 操作系统 | 安装脚本支持 Ubuntu、Debian 与 RHEL 系（CentOS、RHEL、Rocky、AlmaLinux、Fedora）；RHEL 系的 ufw 来自 EPEL，Fedora 自带 |
| Python | 3.10 或更高。Ubuntu 22.04+、Debian 12+、Fedora 自带；RHEL 系 8/9 由安装脚本改装 `python3.12`（或 `python3.11`）。Ubuntu 20.04、Debian 11、CentOS 7 等只带更旧 Python 的系统，需先自行安装 Python 3.10+（含 venv 模块），否则安装脚本报错退出 |
| 防火墙 | UFW（安装脚本负责安装；未启用时先放行 SSH 再启用） |
| Web 服务器 | Nginx（安装脚本自动安装配置；`--no-nginx` 时不使用） |
| 权限 | root（操作 UFW 需要） |
| SSL 证书 | 域名模式：Let's Encrypt 自动申请；自签模式：安装脚本自动生成 |

> **RHEL 系的额外步骤**：ufw 与 firewalld 不能同时管理防火墙，安装前先停用 firewalld（`sudo systemctl disable --now firewalld`）。SELinux 为 enforcing 时，Nginx 反向代理到 `127.0.0.1:5000` 需要 `sudo setsebool -P httpd_can_network_connect 1`；对外端口不在 SELinux 的 `http_port_t` 里（默认含 80、443、8443）时，还要 `sudo semanage port -a -t http_port_t -p tcp <端口>`。

### 前置条件：UFW 防火墙配置

用 `deploy.sh` 安装时：UFW 未启用，脚本先放行 SSH 再启用；UFW 已启用，脚本不改动现有的 SSH 规则，只放行 HTTPS 端口。

手动部署，或想在安装前自己配置 UFW 时，按下面的顺序执行，避免把自己锁在服务器外面：

```bash
# 1. 先放行 SSH（端口不是 22 时换成实际端口）
sudo ufw allow 22/tcp

# 2. 放行 HTTPS 端口（客户端通过它访问）
sudo ufw allow 443/tcp

# 3. 默认拒绝入站、允许出站
sudo ufw default deny incoming
sudo ufw default allow outgoing

# 4. 启用 UFW
sudo ufw enable

# 5. 确认当前状态
sudo ufw status
```

### 使用部署脚本（推荐）

```bash
git clone https://github.com/lvusyy/UFW-OkBoy.git
cd UFW-OkBoy

# 自签模式（无需域名，用 IP:端口 访问）
sudo bash deploy/deploy.sh --self-signed -y

# 域名模式（自动申请 Let's Encrypt 证书）
sudo bash deploy/deploy.sh --domain ufw.example.com -y

# 自定义端口
sudo bash deploy/deploy.sh --self-signed --port 8443 -y

# 不使用 Nginx（Gunicorn 直接提供 HTTPS）
sudo bash deploy/deploy.sh --self-signed --no-nginx -y
```

从其他目录运行时，程序被复制到 `/opt/ufw-okboy`，以后用 `deploy/upgrade.sh` 升级；仓库本身检出在 `/opt/ufw-okboy` 时原地安装，可以用 `app.py upgrade` 或 git 升级（见 [升级与版本管理](#升级与版本管理)）。

重跑安装脚本会重新生成 Nginx 配置和 systemd 单元文件（本地改动会被覆盖），自签模式下还会重新生成证书；`config.yaml` 和数据库保留，服务会重启。升级已安装的实例请用 `upgrade.sh`。

#### 部署脚本参数

`deploy/deploy.sh` 与发布包里的 `install.sh` 参数相同：

| 参数 | 说明 |
|------|------|
| `--domain <域名>` | 用 Let's Encrypt（`certbot certonly --nginx`）为该域名申请证书，站点仍由安装脚本配置，续期后自动重载 Nginx（`--no-nginx` 时重启服务）。域名须已解析到本机，且 80 端口能从公网访问：申请和续期都要用，安装脚本会在 UFW 里放行 80 端口，云安全组需自行放行。申请失败时退回自签证书 |
| `--self-signed` | 使用自签证书，即使给了 `--domain`；不带 `--domain` 时本就是自签 |
| `--port <端口>` | 对外 HTTPS 端口，默认 443 |
| `--ip <地址>` | 自签证书和安装结束时打印的访问地址所用的公网 IP，跳过自动探测（NAT 云主机建议指定） |
| `--no-nginx` | 不配置 Nginx，由 Gunicorn 直接在 `0.0.0.0:<端口>` 上提供 HTTPS |
| `--mirror <URL>` | PyPI 索引地址；不指定且连不上 pypi.org 时改用清华镜像 |
| `--offline` | 只用发布包 `vendor/` 里的 wheels 安装 Python 依赖，不联网；没有 wheels 或装不全时报错 |
| `--admin-user <名称>` | 安装结束时创建的管理员用户名，默认 `admin` |
| `--app-dir <路径>` | 安装目录，默认 `/opt/ufw-okboy` |
| `-y`, `--yes` | 为脚本化调用保留；安装过程不会提问 |
| `-h`, `--help` | 显示脚本说明 |

`quick-install.sh` 另有 `--gh-mirror <前缀>`（拉代码时使用的 GitHub 代理，也可用环境变量 `UFW_OKBOY_GH_MIRROR`），其余参数原样传给 `deploy.sh`。

### 只安装程序：install-server.sh

`deploy/install-server.sh` 只安装程序、Python 依赖和 systemd 单元文件：不装 Nginx、不配证书、不启用 UFW，也不启动服务、不创建管理员。适合已有反向代理、想自己完成其余配置的情况。Debian/Ubuntu 上 UFW 需要预先安装；RHEL 系缺 ufw 时脚本会先装 EPEL 再装 ufw。

```text
sudo bash deploy/install-server.sh [--mirror <PyPI 索引>] [--offline] [--app-dir <目录>]
```

装完按脚本打印的后续步骤操作：创建管理员、配置 Nginx（见 [手动部署](#手动部署)）、`systemctl enable --now ufw-okboy` 与 `systemctl enable --now ufw-okboy-cleanup.timer`。用 `--app-dir` 装到别的目录时，单元文件里的路径会随之改写。

### 手动部署

```bash
# 1. 安装依赖（Python 需 3.10+）
sudo apt install python3 python3-venv ufw nginx      # Ubuntu/Debian
# RHEL 系：先装 EPEL（提供 ufw）；默认 python3 低于 3.10 时安装 python3.12，
#          并在第 3 步改用 python3.12 创建虚拟环境

# 2. 获取代码
sudo git clone https://github.com/lvusyy/UFW-OkBoy.git /opt/ufw-okboy
cd /opt/ufw-okboy

# 3. 创建虚拟环境并安装 Python 依赖
sudo python3 -m venv venv
sudo venv/bin/pip install -r server/requirements.txt

# 4. 创建日志目录（数据目录 /var/lib/ufw-okboy 在首次打开数据库时自动创建，权限 700）
sudo mkdir -p /var/log/ufw-okboy

# 5. 配置（默认值即可使用）
cd server
sudo cp config.example.yaml config.yaml

# 6. 创建管理员（同时初始化数据库），记下打印的密钥
sudo ../venv/bin/python app.py -c config.yaml user-add admin --admin

# 7. 安装 systemd 单元并启动
sudo cp ../deploy/ufw-okboy.service ../deploy/ufw-okboy-cleanup.service \
        ../deploy/ufw-okboy-cleanup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ufw-okboy
sudo systemctl enable --now ufw-okboy-cleanup.timer

# 8. 配置 Nginx 与证书（见下方说明），并放行 HTTPS 端口
sudo ufw allow 443/tcp
```

Nginx：`nginx/ufw-okboy.conf` 是示例站点配置，需要修改 `server_name` 和证书路径（用 certbot 申请 Let's Encrypt 证书，或用 openssl 生成自签证书）。

- 示例里的 `limit_req zone=okboy` 依赖 `http` 块中的 `limit_req_zone $binary_remote_addr zone=okboy:10m rate=3r/s;`（示例注释还建议加 `limit_req_status 429;`），缺了这一行 `nginx -t` 会报错；不需要限流就删掉 `limit_req` 那一行。
- `/api/` 必须像示例那样传递 `X-Real-IP` / `X-Forwarded-For`，否则服务端取不到客户端地址，敲门返回 400。

### 验证部署

```bash
# 服务状态
systemctl status ufw-okboy

# 健康检查（端口换成实际端口；自签证书需加 -k）
curl -k https://127.0.0.1:443/health
# 返回：{"ok":true,"service":"ufw-okboy"}

# Nginx 模式下也可以直接访问后端
curl http://127.0.0.1:5000/health

# 查看数据库中的表（需要 sqlite3 命令行工具）
sudo sqlite3 /var/lib/ufw-okboy/ufw-okboy.db ".tables"
```

`.tables` 应列出 7 张表：`audit_log`、`failed_attempts`、`groups`、`operation_log`、`schema_version`、`user_group_membership`、`users`。最后用浏览器打开 `https://<服务器地址>:<端口>/`，应看到登录页。

### 安装后的文件布局

| 路径 | 内容 |
|------|------|
| `/opt/ufw-okboy/server/` | 程序与 `config.yaml` |
| `/opt/ufw-okboy/venv/` | Python 虚拟环境 |
| `/opt/ufw-okboy/VERSION` | 版本号 |
| `/var/lib/ufw-okboy/ufw-okboy.db` | SQLite 数据库（0600；另有 `-wal`、`-shm` 文件） |
| `/var/lib/ufw-okboy/backups/` | `app.py backup` 的备份 |
| `/var/lib/ufw-okboy/*.lock` | 进程间锁文件：`ufw.lock`、`totp.lock`、`db.lock` |
| `/var/log/ufw-okboy/` | Gunicorn 的 `access.log` 与 `error.log` |
| `/etc/ssl/ufw-okboy/` | 自签证书与私钥 |
| `/etc/nginx/sites-available/ufw-okboy.conf` | 安装脚本生成的 Nginx 站点配置（链接到 `/etc/nginx/sites-enabled/`；RHEL 系为 `/etc/nginx/conf.d/ufw-okboy.conf`） |
| `/etc/systemd/system/ufw-okboy.service` | 服务单元 |
| `/etc/systemd/system/ufw-okboy-cleanup.service`、`.timer` | 每日清理任务 |

数据库、备份和锁文件的位置由 `db_path`、`backup_dir` 决定，上表为默认值。

### 配置文件参考

配置文件为 `/opt/ufw-okboy/server/config.yaml`，从 `config.example.yaml` 复制而来，默认值即可使用。服务只在启动时读取它，修改后执行 `sudo systemctl restart ufw-okboy`；命令行每次运行时读取。没写的项取下表的默认值。

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `signature_ttl` | `300` | 签名有效期（秒）：请求时间戳与服务器时间相差超过它即拒绝。客户端时钟偏差大时调大 |
| `rule_prefix` | `ufw-okboy` | UFW 规则注释前缀，用来识别本工具管理的规则。已有规则时不要修改，否则旧前缀的规则不再被识别和清理 |
| `trusted_proxies` | `["127.0.0.1", "::1"]` | 只有直连来源在此列表中时，才用 `X-Real-IP`（或 `X-Forwarded-For` 的最右一项）作为客户端地址，否则以直连地址为准。反向代理不在本机时加上它的地址 |
| `throttle_max_failures` | `10` | 同一来源 IP 在 `throttle_window` 内的失败次数达到此值后，其 `/api/` 请求返回 429；同时也是每个管理员账号 TOTP 验证码错误次数的上限。`0` 关闭这两项 |
| `throttle_window` | `300` | 上面两项的统计窗口（秒） |
| `require_admin_totp` | `false` | 为 `true` 时，未启用 TOTP 的管理员在启用之前不能执行需要二次验证的操作 |
| `totp_replay_protection` | `true` | 每个 TOTP 验证码只能用一次；为 `false` 时同一验证码在有效窗口内可重复使用 |
| `github_mirror` | 空 | `app.py upgrade` 查询最新版本时使用的 GitHub 代理前缀；环境变量 `UFW_OKBOY_GH_MIRROR` 优先 |
| `anomaly_window` | `3600` | IP 变更异常检测的统计窗口（秒） |
| `anomaly_max_changes` | `5` | 窗口内 IP 变更次数（首次登记也算一次）达到此值时记录告警，并在敲门响应里返回 `warning` |
| `allowed_ports` | 不设置 | 端口白名单：设置后，管理控制台和管理 API 只能用列表中的端口新建分组（命令行 `group-add` 不受限制）；不设置或为空则不限制 |
| `db_path` | `/var/lib/ufw-okboy/ufw-okboy.db` | SQLite 数据库路径，锁文件放在同一目录 |
| `backup_dir` | `/var/lib/ufw-okboy/backups` | `app.py backup` 的默认输出目录 |
| `backup_keep` | `7` | 保留最近几份备份，`0` 表示全部保留 |
| `listen_host` | `127.0.0.1` | 只有 `app.py serve`（Flask 开发服务器）使用 |
| `listen_port` | `5000` | 只有 `app.py serve` 使用 |

systemd 服务由 Gunicorn 按单元文件里的 `--bind` 监听：Nginx 模式为 `127.0.0.1:5000`，`--no-nginx` 模式为 `0.0.0.0:<端口>`。修改 `listen_host`、`listen_port` 不会改变它。

以下配置项沿用 v1 的旧格式，只在**新建数据库**时导入一次，之后不再读取：

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `users` | 不设置 | 旧版的用户列表（`用户名: {secret: ...}`）。`CHANGE_ME` 开头的示例密钥不会生效，这样的用户会被分配随机密钥。写了用户的配置文件在加载时被收紧为 0600 |
| `protected_ports` | 不设置 | 旧版的端口列表：每个端口建成一个 `default-<端口>` 分组，并把 `users` 里的用户全部加入 |
| `proto` | `tcp` | 上面这些 `default-<端口>` 分组的协议。之后每条规则都使用各自分组的协议 |
| `state_file` | `/var/lib/ufw-okboy/state.json` | v1 的 JSON 状态文件，从中导入各用户的当前 IP 与最后敲门时间 |

---

## 用户组与端口管理

用户、分组和成员资格保存在数据库里，通过网页管理台、命令行或 REST API 管理，不需要改配置文件。

### 概念说明

| 概念 | 说明 |
|------|------|
| **管理员** | `is_admin=1` 的用户，可以使用管理控制台和管理 API（在服务器上以 root 运行的命令行不区分用户） |
| **分组** | 绑定一个端口和协议（`tcp` 或 `udp`），例如 `web` 分组对应 8080/tcp。同一端口加协议只能属于一个分组 |
| **成员资格** | 用户加入分组后，敲门时其当前 IP 会在该分组的端口上被放行 |
| **开关（`enabled`）** | 成员资格可以关闭、再开启，只有开启的分组生成规则。用户只能开关自己已有的成员资格，新的授权由管理员给出 |

用户名和分组名为 1–64 个字符，只能包含字母、数字、`_`、`.`、`-`。管理控制台建的分组都是 TCP；UDP 分组用命令行（`--proto udp`）或 API（`"proto": "udp"`）创建。设置了 `allowed_ports` 时，管理控制台和 API 只能用白名单里的端口建分组（见 [配置文件参考](#配置文件参考)）。

### 典型使用场景

```text
管理员创建分组：
  group-add web 8080             → Web 管理后台（8080/tcp）
  group-add db 3306              → 数据库（3306/tcp）
  group-add dns 53 --proto udp   → UDP 服务

用户加入分组：
  user-join alice web            → alice 可以访问 8080
  user-join alice db             → alice 同时可以访问 3306
  user-join bob web              → bob 只能访问 8080

关闭 / 重新开启某个成员资格（路径里是数字 ID）：
  PATCH /api/me/membership/<分组 ID>           {"enabled": false}    用户本人
  PATCH /api/membership/<用户 ID>/<分组 ID>    {"enabled": false}    用户本人或管理员
  → 关闭：立即删除该成员资格在所有地址上的规则
  → 重新开启：用户已有当前 IP 时立即加回规则
```

用户 ID、分组 ID 可以用 `user-list`、`group-list` 或 `GET /api/me/groups` 查到。

### 多组多端口授权

用户加入多个分组时，其 IP 同时在所有开启的分组端口上被放行。例如 alice 加入 web（8080/tcp）和 db（3306/tcp），当前 IP 为 198.51.100.3，OkBoy 执行的命令相当于：

```bash
ufw allow from 198.51.100.3 to any port 8080 proto tcp comment 'ufw-okboy:alice:web'
ufw allow from 198.51.100.3 to any port 3306 proto tcp comment 'ufw-okboy:alice:db'
```

### IP 变更时的规则切换

alice 的 IP 从 `198.51.100.3` 变为 `203.0.113.7` 后，她的下一次敲门在主机锁内依次执行：

```text
1. 为新 IP 补上缺少的规则（先加后删，访问不中断）：
   ufw allow from 203.0.113.7 to any port 8080 proto tcp comment ufw-okboy:alice:web
   ufw allow from 203.0.113.7 to any port 3306 proto tcp comment ufw-okboy:alice:db
2. 重新列出规则（ufw status numbered），找出 alice 名下 IP 不是 203.0.113.7、
   或分组已不再开启的规则
3. 按编号从大到小逐条删除：ufw --force delete <编号>
4. 按注释查找并删除仍留在旧 IP 198.51.100.3 上的规则（兜底）
```

- 从大编号往小删：删掉一条后，编号更小的规则不会移位，不会删错别的规则。
- IP 没变的心跳也执行第 1–3 步，所以缺失或残留的规则会在下一次敲门时自动修复。
- 单条规则添加或删除失败只记日志；规则列不出来或时间用尽时，本次敲门返回 503，不记录新地址，下次敲门重做。

### 主机已有同一来源的规则时

ufw 对同一个来源地址、端口和协议只保留一条规则。服务器上已有一条不是 OkBoy 创建的规则，且来源、端口、协议与要加的规则相同（任何动作，包括 DENY，也包括带 `log` 的规则）时，OkBoy 不再添加，保留这条主机规则，并在服务日志里记一条警告。这样 OkBoy 不会把主机的 DENY 改成 ALLOW，之后吊销、清理这个用户时也不会删到主机规则。

### 用 OkBoy 管理 SSH（22 端口）

> **警告**：把 SSH 交给 OkBoy 管理后，只有敲过门的 IP 能连 SSH，操作不当会把自己锁在服务器外面。整个过程中**保持当前 SSH 会话不要关闭**，并准备好云控制台或 VNC 等带外登录方式。

1. 建 `ssh` 分组并把自己加进去（SSH 不在 22 端口时用实际端口）：

   ```bash
   cd /opt/ufw-okboy/server
   sudo ../venv/bin/python app.py -c config.yaml group-add ssh 22
   sudo ../venv/bin/python app.py -c config.yaml user-join admin ssh
   ```

2. 敲门（在网页上登录，或运行客户端），确认已有你当前 IP 的规则：`sudo ufw status | grep ufw-okboy:admin:ssh`。
3. 在另一个终端新建一个 SSH 连接，确认能登录。
4. 确认无误后，再删除对所有来源开放的 SSH 规则，例如 `22/tcp ALLOW IN Anywhere`、`OpenSSH ALLOW IN Anywhere` 以及对应的 `(v6)` 规则：用 `sudo ufw status numbered` 查编号，`sudo ufw delete <编号>` 逐条删除，每删一条都重新列出（编号会变化）；也可以在管理控制台的「系统防火墙规则」面板里删除。删完再新建一个 SSH 连接验证。

清理任务会删除 7 天没有敲门的用户的全部规则，SSH 分组的规则也不例外。请保持至少一个客户端在定时敲门（例如 `knock.py` 的 systemd 定时器）。

---

## 网页管理台

在浏览器里打开服务器地址（`https://<服务器地址>:<端口>/`）看到的页面，既是用户的网页客户端，也是管理员的管理控制台。页面顶部的「中文 / EN」按钮切换界面语言，默认跟随浏览器语言。

### 登录与凭据保存

登录页有四项：用户名、密钥、「记住凭据」（默认勾选）和可选的 PIN 码。凭据在第一次敲门之后才保存，认证失败时不保存，所以输错的密钥不会被存下来。

| 登录时的选择 | 浏览器里保存的内容 | 下次打开页面 |
|------|------|------|
| 勾选「记住凭据」，不填 PIN | 用户名和密钥（明文，存于 localStorage） | 自动连接 |
| 勾选「记住凭据」，填了 PIN | 用 PIN 加密的用户名和密钥（PBKDF2-SHA256 迭代 60 万次派生密钥，AES-GCM 加密） | 先输入 PIN 解锁，再自动连接 |
| 不勾选「记住凭据」 | 不保存 | 重新输入用户名和密钥 |

- PIN 只在浏览器本地用来解密，不发给服务器。连续输错 5 次需等 30 秒（这只是页面上的限制）。
- 忘记 PIN：在 PIN 页面点「取消」，用用户名和密钥重新登录，并填一个新的 PIN。
- 「断开连接」会清除浏览器里保存的凭据（明文和加密的都清除）。
- 认证失败（密钥错误或已被吊销、签名过期）时，页面清除保存的凭据并回到登录页。签名过期通常是本机时钟与服务器相差超过 `signature_ttl`（默认 300 秒）。

### 仪表盘

连接后显示连接状态、用户名、下次心跳倒计时、已注册 IP 和活动日志。页面每 30 秒敲门一次；切回这个标签页时，如果距上次敲门已超过 30 秒，会立即敲门。

- 「立即心跳」：马上敲门一次。
- 「管理后台」：只对管理员显示，进入管理控制台。
- 「断开连接」：停止敲门并清除保存的凭据。已放行的规则不会立即删除，保留到被清理为止。

服务端检测到疑似共享凭据（见 [异常检测](#异常检测)）时，状态栏显示「警告：检测到异常」，活动日志里有服务端返回的说明。

### 进入管理控制台

管理控制台要求 PIN：

- 设置过 PIN、本次还没解锁：先输入 PIN。
- 从没设置过 PIN：页面要求设置一个，并用它把当前凭据加密保存在浏览器里（即使登录时没有勾选「记住凭据」），同时删除明文副本。
- 本次已经用 PIN 解锁过（例如打开页面时输入过）：直接进入。

「锁定」清除内存中的解锁状态并回到仪表盘，再次进入需要重新输入 PIN；「返回仪表盘」不锁定。PIN 只保护这台浏览器里保存的凭据，服务端并不知道它；保护管理操作的是 TOTP（见 [管理员二次验证](#管理员二次验证totp)）。

### 管理控制台的面板

| 面板 | 功能 |
|------|------|
| 用户 | 搜索、分页（每页 8 个）；新建用户（可勾选「管理员」），生成的密钥只显示一次，可点「复制」。每个用户有「管理分组」（勾选即授权并开启，取消勾选即移出分组）、「设为管理员」/「取消管理员」、「吊销」、「删除」。自己那一行没有「删除」和管理员切换，「吊销」换成「更换密钥」 |
| 分组 | 搜索、分页；新建分组（名称 + 端口，协议为 TCP）；「删除」同时删除其成员的规则 |
| 审计日志 | 最近 50 条管理操作，「刷新」重新加载 |
| 我的分组授权 | 列出你自己的成员资格（开启的和关闭的），勾选要为你的 IP 开放的分组后点「保存授权」。每次打开时第一个分组默认勾选，其余按当前状态。只能开关已有的成员资格 |
| 双因素认证（TOTP） | 「注册 / 重新注册」（已启用时需要当前验证码）、「激活」、「禁用」，见 [管理员二次验证](#管理员二次验证totp) |
| 系统防火墙规则 | 位于「高级（高风险）」分区。点「显示防火墙规则」列出全部 UFW 规则（包括不是 OkBoy 创建的），标出 `[okboy]`、疑似 SSH 的规则（`⚠️SSH`）和对所有来源开放的 SSH 规则。删除依次经过：确认 → 疑似 SSH 时再次确认 → 启用了 TOTP 时输入验证码；服务端核对该编号仍是你看到的那条规则，列表已变化则拒绝并刷新。每次删除都写入审计日志 |

启用 TOTP 后，新建和删除用户、分组，修改他人的成员资格，设置或取消管理员，吊销（含更换自己的密钥），删除系统规则时，页面会弹框要求输入 6 位验证码。

「更换密钥」与吊销走同一个接口：旧密钥立即失效，你的防火墙规则被删除、当前 IP 被清空，页面随即改用新密钥，下一次敲门（30 秒内）恢复访问。新密钥只显示一次，请同步更新你的其他客户端。用 PIN 加密保存的凭据不会随之更新，下次打开页面解锁后会因密钥失效回到登录页，用新密钥重新登录即可。

---

## CLI 管理命令

管理命令都在服务器上以 root 运行，并使用安装目录里的虚拟环境（系统自带的 Python 没有 Flask 和 PyYAML）：

```text
cd /opt/ufw-okboy/server
sudo ../venv/bin/python app.py -c config.yaml <命令> [参数]
```

`-c`/`--config` 写在命令之前，默认是 `app.py` 同目录的 `config.yaml`。命令行改动防火墙时与服务共用主机锁，不会与正在进行的敲门交错。

### 命令一览

| 命令 | 说明 |
|------|------|
| `user-add <用户名> [--admin]` | 创建用户并打印随机生成的密钥（64 位十六进制）；`--admin` 设为管理员。用户名已存在时报错并以非 0 退出 |
| `user-del <用户名>` | 删除该用户在所有地址上的规则，再删除用户 |
| `user-list` | 列出用户：ID、用户名、是否管理员、当前 IP、最后敲门时间 |
| `admin-add <用户名>` | 设为管理员（取消管理员用管理控制台或 API） |
| `revoke <用户名> [--no-rotate]` | 吊销：更换密钥并打印新密钥，删除其全部规则，清除当前 IP，成员资格保留。`--no-rotate` 不换密钥 |
| `group-add <名称> <端口> [--proto udp]` | 创建分组，协议默认 `tcp`；端口加协议已被其他分组占用，或分组名已存在时拒绝 |
| `group-del <名称>` | 删除该分组所有成员的规则，再删除分组 |
| `group-list` | 列出分组：ID、名称、端口、协议 |
| `user-join <用户名> <分组>` | 加入分组（已关闭的成员资格会重新开启）；用户有当前 IP 时立即放行 |
| `user-leave <用户名> <分组>` | 删除该成员资格在所有地址上的规则，再移出分组 |
| `list` | 列出配置文件里的旧版用户、数据库用户及其当前 IP，以及 `ufw status` 中注释含 `ufw-okboy` 的规则 |
| `cleanup [--max-age <天数>]` | 删除超过指定天数（默认 7）未敲门的用户的全部规则，并清除其当前 IP |
| `sync` | 按 UFW 中的规则回填数据库里已有用户的当前 IP，并按其开启的分组对账 |
| `backup [--dir <目录>]` | 在线备份数据库，附 `.sha256` 校验和，按 `backup_keep` 滚动保留 |
| `restore <备份文件>` | 从备份恢复数据库（先停止服务） |
| `upgrade --check` | 查询 GitHub 上的最新版本，只提示 |
| `upgrade --force [-y]` | 升级 git 检出的安装，见 [git 检出的安装](#git-检出的安装) |
| `serve [--debug]` | 用 Flask 开发服务器运行，监听 `listen_host:listen_port`，仅用于测试。默认地址与 Nginx 模式下的服务相同，需先停止服务或修改 `listen_port` |
| `gen-secret [<用户名>]` | 只打印一个随机密钥和旧版 `users:` 配置片段，不写数据库；日常用不到 |
| `-V`, `--version` | 显示版本 |

命令行没有取消管理员、关闭成员资格、查看某个用户所在分组的命令，这些操作用管理控制台或 REST API。

### 用户管理

```bash
cd /opt/ufw-okboy/server

# 创建用户（自动生成密钥）
sudo ../venv/bin/python app.py -c config.yaml user-add alice
# Created user 'alice' with secret: <64 位十六进制密钥>

# 创建管理员
sudo ../venv/bin/python app.py -c config.yaml user-add ops --admin

# 列出用户（最后敲门时间为服务器本地时间）
sudo ../venv/bin/python app.py -c config.yaml user-list
#   ID  Username              Admin  Current IP        Last Knock
#    1  admin                 Yes    203.0.113.5       2026-09-28 14:30:05
#    2  alice                 No     198.51.100.3      2026-09-28 14:29:41
#    3  ops                   Yes    (none)            never

# 设为管理员
sudo ../venv/bin/python app.py -c config.yaml admin-add alice

# 删除用户（先删除其全部 UFW 规则）
sudo ../venv/bin/python app.py -c config.yaml user-del bob
```

### 分组管理

```bash
cd /opt/ufw-okboy/server

# 创建分组（绑定端口，协议默认 tcp）
sudo ../venv/bin/python app.py -c config.yaml group-add web 8080
sudo ../venv/bin/python app.py -c config.yaml group-add db 3306
sudo ../venv/bin/python app.py -c config.yaml group-add dns 53 --proto udp

# 列出分组
sudo ../venv/bin/python app.py -c config.yaml group-list
#   ID  Name                   Port  Proto
#    2  db                     3306  tcp
#    3  dns                      53  udp
#    1  web                    8080  tcp

# 删除分组（先删除所有成员在该分组上的 UFW 规则）
sudo ../venv/bin/python app.py -c config.yaml group-del dns
```

### 成员管理

```bash
cd /opt/ufw-okboy/server

# 加入分组（用户在线时立即放行）
sudo ../venv/bin/python app.py -c config.yaml user-join alice web

# 移出分组（同时删除规则）
sudo ../venv/bin/python app.py -c config.yaml user-leave alice web
```

### 维护命令

```bash
cd /opt/ufw-okboy/server
sudo ../venv/bin/python app.py -c config.yaml list                   # 用户与本工具的规则
sudo ../venv/bin/python app.py -c config.yaml cleanup --max-age 7    # 清理 7 天未敲门的用户
sudo ../venv/bin/python app.py -c config.yaml sync                   # 从 UFW 规则回填当前 IP
sudo ../venv/bin/python app.py -c config.yaml backup                 # 在线备份数据库
```

`sync` 只更新数据库里已有的用户：把规则里的地址记为当前 IP、最后敲门时间记为当前时间，再按其开启的分组对账（补上缺少的规则，删除已关闭分组和其他地址上的规则）。规则里出现数据库中没有的用户名时只记警告并跳过。它不能重建丢失的用户和分组：数据库丢失时先从备份恢复（见 [数据备份与恢复](#数据备份与恢复)），再运行 `sync`。

---

## REST API

所有接口都在 `https://<服务器地址>:<端口>` 下，请求和响应都是 JSON。

### 通用约定

- **认证**：除 `/health` 外，每个请求都带 `Authorization: HMAC-SHA256 <用户名>:<时间戳>:<签名>`，与客户端敲门相同（见 [认证原理](#认证原理)）。管理接口还要求该用户是管理员。
- **请求体**：带请求体时一律加上 `Content-Type: application/json`。部分接口没有这个头就读不到请求体：成员资格开关返回 400，设置管理员时 `is_admin` 按默认值 `true` 处理，请求体里的 `totp_code` 也读不到。
- **响应**：成功时 `ok` 为 `true`；失败时为 `{"ok": false, "error": "<原因>"}`，部分错误带额外字段（`totp_required`、`totp_enroll_required`、`stale`、`ssh_warning`）。未知路径、方法不对等框架层错误另带 `code`（HTTP 状态码）；未处理的异常返回 500 `{"ok": false, "error": "Internal server error"}`。
- **Nginx 限流**：启用了 Nginx 的 `limit_req` 时，超限请求由 Nginx 直接返回 HTML 错误页（默认 503，或按 `limit_req_status` 的设置）。

| 状态码 | 含义 |
|------|------|
| 400 | 参数错误；敲门时取不到有效的客户端 IP |
| 401 | 缺少认证头、格式错误、签名过期或不正确（用户不存在与签名错误都返回 `Invalid credentials`） |
| 403 | 需要管理员权限；需要 TOTP 验证码（`totp_required`）或需要先启用 TOTP（`totp_enroll_required`）；试图开启从未授权的分组 |
| 404 | 用户、分组、成员资格或规则不存在 |
| 409 | 用户名、分组名或端口加协议重复；删除系统规则时列表已变化（`stale`）或需要确认 SSH（`ssh_warning`） |
| 429 | 来源 IP 的失败次数过多；或该账号的 TOTP 错误次数过多 |
| 500 | 防火墙操作失败，可重试（删除用户、分组或成员资格时，数据库记录会保留到规则删掉为止） |
| 503 | 防火墙繁忙：等待主机锁超过 20 秒，或本次敲门没能完成，稍后重试 |

### 签名示例

用 shell 生成认证头（算法与 `knock.sh` 相同）：

```bash
U=admin
SECRET='YOUR_SECRET'
TS=$(date +%s)
SIG=$(printf '%s' "$U:$TS" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $NF}')
AUTH="HMAC-SHA256 $U:$TS:$SIG"

curl -s -H "Authorization: $AUTH" https://your-server:8443/api/status
```

`$AUTH` 在 `signature_ttl`（默认 300 秒）内有效，过期后重新生成。服务器用自签证书时 `curl` 加 `-k`。`openssl -hmac` 会让密钥出现在本机的进程参数里，多用户机器上请换一种方式计算签名。

### 客户端接口

任何用户都可以调用，只作用于自己：

| 方法与路径 | 请求体 | 说明 |
|------|------|------|
| `POST /api/knock` | 无 | 敲门：为当前来源 IP 放行自己开启的分组，删除旧 IP 与失效分组的规则 |
| `GET /api/status` | 无 | 自己的登记状态 |
| `GET /api/me/groups` | 无 | 自己的成员资格（开启的和关闭的） |
| `PATCH /api/me/membership/<分组 ID>` | `{"enabled": false}` | 关闭（`false`）或重新开启（`true`）自己的成员资格 |
| `PATCH /api/membership/<用户 ID>/<分组 ID>` | `{"enabled": false}` | 同上，按用户 ID 指定；管理员可以修改他人的（需要二次验证） |
| `GET /health` | 无 | 健康检查，不需要认证，返回 `{"ok":true,"service":"ufw-okboy"}` |

敲门成功的响应：

```json
{"ok": true, "ip": "203.0.113.7", "changed": true, "old_ip": "198.51.100.3",
 "groups": ["db", "web"], "message": "Firewall rules updated"}
```

IP 没变时为 `{"ok": true, "ip": "...", "changed": false, "message": "IP unchanged, heartbeat recorded"}`；触发异常检测时另有 `warning` 字段。取不到有效的客户端 IP（缺少代理头、回环地址等）返回 400；防火墙繁忙返回 503 `Firewall busy; retry shortly`，此时不记录新地址，稍后重试即可。

`/api/status` 的字段：

| 字段 | 说明 |
|------|------|
| `username`、`is_admin`、`totp_enabled` | 用户名、是否管理员、是否已启用 TOTP |
| `enabled_groups` | 开启的分组，每项含 `name`、`port`、`proto` |
| `ip`、`last_knock` | 当前登记的 IP、最后敲门时间（Unix 时间戳） |
| `ip_changes_recent` | 最近 24 小时的 IP 变更次数（含首次登记） |

`/api/me/groups` 返回 `groups` 数组，每项含 `id`、`name`、`port`、`proto`、`enabled`（`1` 或 `0`）。

开关成员资格的规则：只能开关已有的成员资格（管理员本人也一样），开启从未授权的分组返回 403 并写入审计日志，关闭不存在的成员资格返回 404；关闭时立即删除该成员资格在所有地址上的规则，开启时若用户有当前 IP 则立即放行。新的授权走管理接口。

### 管理接口

调用者必须是管理员，否则返回 403，并计入来源 IP 的失败次数。「二次验证」为「是」的接口见 [TOTP 二次验证](#totp-二次验证)。路径中的 `<id>` 是用户或分组的数字 ID。

| 方法与路径 | 请求体 | 二次验证 | 说明 |
|------|------|------|------|
| `GET /api/admin/users` | 无 | | 用户列表（不含密钥与 TOTP 种子） |
| `POST /api/admin/users` | `{"username": "bob", "is_admin": false}` | 是 | 建用户，返回 201 与 `secret`；也可以用 `secret` 字段自带密钥（不接受 `CHANGE_ME` 开头的示例值） |
| `DELETE /api/admin/users/<id>` | 无 | 是 | 删除用户，先删除其全部规则 |
| `POST /api/admin/users/<id>/revoke` | `{"rotate_secret": true}` | 是 | 吊销：删除全部规则、清除当前 IP；默认更换密钥并返回新 `secret`。规则删除失败时仍更换密钥，保留当前 IP 并返回 `warning` |
| `POST /api/admin/users/<id>/admin` | `{"is_admin": false}` | 是 | 设置（`true`，默认）或取消（`false`）管理员 |
| `GET /api/admin/users/<id>/groups` | 无 | | 全部分组，带该用户的 `is_member`、`enabled` |
| `POST /api/admin/users/<id>/groups` | `{"group_id": 1, "enabled": true}` | 是 | 加入分组，或修改已有成员资格的开关，返回 201。开启时用户有当前 IP 则立即放行；`"enabled": false` 时删除该成员资格的规则 |
| `POST /api/admin/memberships/remove` | `{"username": "alice", "group_name": "web"}` | 是 | 移出分组，先删除规则 |
| `GET /api/admin/groups` | 无 | | 分组列表 |
| `POST /api/admin/groups` | `{"name": "web", "port": 8080, "proto": "tcp"}` | 是 | 建分组，`proto` 为 `tcp`（默认）或 `udp`，受 `allowed_ports` 限制；返回 201 |
| `DELETE /api/admin/groups/<id>` | 无 | 是 | 删除分组，先删除其成员的规则 |
| `GET /api/admin/audit?limit=100` | 无 | | 审计日志，新的在前；`limit` 默认 100，范围 1–1000 |
| `POST /api/admin/totp/enroll` | 重新注册时 `{"totp_code": "123456"}` | | 开始注册，返回 `secret` 与 `otpauth_uri`；新验证器确认之前，原来的继续有效 |
| `POST /api/admin/totp/activate` | `{"totp_code": "123456"}` | | 用新验证器的验证码确认并启用 |
| `DELETE /api/admin/totp` | 已启用时 `{"totp_code": "123456"}` | | 关闭自己的 TOTP |
| `GET /api/admin/ufw/rules` | 无 | | 全部 UFW 规则（只读），见 [系统防火墙规则接口](#系统防火墙规则接口) |
| `POST /api/admin/ufw/delete` | `{"number": 3, "expect": {...}}` | 是 | 按编号删除任意 UFW 规则（高风险），见 [系统防火墙规则接口](#系统防火墙规则接口) |

### TOTP 二次验证

适用于上表「二次验证」为「是」的接口，以及管理员修改他人成员资格的 `PATCH /api/membership/<用户 ID>/<分组 ID>`：

- 调用者已启用 TOTP：必须带当前的 6 位验证码，放在请求头 `X-TOTP-Code` 或请求体字段 `totp_code` 里；缺少或错误返回 403 `{"totp_required": true}`。
- 调用者未启用 TOTP：`require_admin_totp: true` 时返回 403 `{"totp_enroll_required": true}`，否则直接执行。
- 开启重放保护时每个验证码只能用一次；同一账号的错误次数达到上限后返回 429（见 [管理员二次验证](#管理员二次验证totp)）。
- `totp/enroll`（重新注册）同样接受请求头或请求体；`totp/activate` 和 `DELETE /api/admin/totp` 只读请求体里的 `totp_code`。

### 系统防火墙规则接口

`GET /api/admin/ufw/rules` 返回 `rules` 数组，每条规则的字段：

| 字段 | 说明 |
|------|------|
| `number` | `ufw status numbered` 中的编号 |
| `to`、`action`、`from`、`comment` | 目标、动作（如 `ALLOW IN`）、来源、注释 |
| `is_okboy` | 注释以 `rule_prefix` 开头 |
| `looks_like_ssh` | 端口是 sshd 的端口（读取 `sshd_config` 与 `sshd_config.d/*.conf`，默认 22），或目标、注释里含 `ssh` |
| `is_open` | 动作为 ALLOW 且来源为 Anywhere |

UFW 未启用时列表为空。

`POST /api/admin/ufw/delete` 按当前编号删除一条规则，依次检查：

1. `expect`（可选，建议提供）：你看到的那条规则的 `to`、`action`、`from`、`comment`。该编号现在是另一条规则时返回 409 `{"stale": true}`，不删除。
2. 疑似 SSH 的规则需要 `"confirm_ssh": true`，否则返回 409 `{"ssh_warning": true, "rule": {...}}`。
3. 二次验证（启用了 TOTP 时）。

编号不存在返回 404。成功时返回 `{"ok": true, "deleted": <编号>, "rules": [...]}`（删除后编号会变化，以返回的列表为准），并写入审计日志。

### 示例

```bash
S=https://your-server:8443     # 服务器地址；$AUTH 的生成见「签名示例」

# 用户列表
curl -s -H "Authorization: $AUTH" "$S/api/admin/users"

# 建用户
curl -s -X POST -H "Authorization: $AUTH" -H "Content-Type: application/json" \
  -d '{"username":"bob","is_admin":false}' "$S/api/admin/users"

# 建 UDP 分组
curl -s -X POST -H "Authorization: $AUTH" -H "Content-Type: application/json" \
  -d '{"name":"dns","port":53,"proto":"udp"}' "$S/api/admin/groups"

# 把用户 2 加入分组 1
curl -s -X POST -H "Authorization: $AUTH" -H "Content-Type: application/json" \
  -d '{"group_id":1,"enabled":true}' "$S/api/admin/users/2/groups"

# 启用 TOTP 后删除用户 3（验证码放在请求头里）
curl -s -X DELETE -H "Authorization: $AUTH" -H "X-TOTP-Code: 123456" "$S/api/admin/users/3"

# 用户自己关闭分组 1（$AUTH 用该用户自己的凭据生成）
curl -s -X PATCH -H "Authorization: $AUTH" -H "Content-Type: application/json" \
  -d '{"enabled":false}' "$S/api/me/membership/1"
```

---

## 客户端使用

提供四种客户端，适应不同场景：

| 方式 | 适用场景 | 技术要求 |
|------|----------|----------|
| 网页客户端 | 日常使用，手机、电脑均可 | 只需浏览器 |
| Python 客户端 `knock.py` | 无界面的 Linux 服务器 | Python 3（PyYAML 可选） |
| Shell 客户端 `knock.sh` | 极简环境 | 只需 curl 和 openssl |
| Windows 客户端 `knock.ps1` | Windows 电脑常驻自动敲门 | 系统自带的 PowerShell |

### 方式一：网页客户端（推荐）

1. 用浏览器打开 `https://<服务器地址>:<端口>/`
2. 输入管理员提供的**用户名**和**密钥**
3. 按需保留「记住凭据」的勾选，可选填 PIN 码
4. 点击「连接」

连接成功后页面显示连接状态（绿色指示灯和「已连接」）、已注册 IP、下次心跳倒计时和活动日志，每 30 秒自动续期。凭据与 PIN 的保存方式、管理员功能见 [网页管理台](#网页管理台)。

### 方式二：Python 客户端

```bash
# 一键安装（推荐）：knock.py + systemd 定时器
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.sh \
  | sudo bash -s -- --server https://your-server:8443 --user alice --secret YOUR_SECRET
```

`install-client.sh` 的参数：

| 参数 | 说明 |
|------|------|
| `--server <URL>` | 服务器地址，例如 `https://your-server:8443` |
| `--user <用户名>` | 用户名 |
| `--secret <密钥>` | 密钥 |
| `--interval <秒>` | 敲门间隔，默认 30 |
| `--pin-sha256 <pin>` | 服务器的公钥 pin（服务器用自签证书时），写入 `pin_sha256`，见 [客户端连自签证书](#客户端连自签证书)。为同一台服务器重新运行时保留已有的 pin，传 `''` 去掉；旧配置里的 pin 无法沿用（读不出或属于另一台服务器）时中止 |
| `--no-verify-ssl` | 不校验证书，写入 `verify_ssl: false`（不推荐：无法识别中间人） |
| `--gh-mirror <前缀>` | 从 GitHub 下载 `knock.py` 时使用的代理前缀（也可用环境变量 `UFW_OKBOY_GH_MIRROR`） |
| `--yes` | 非交互：缺少必填参数时直接报错，不提示输入 |

装好后：`knock.py` 在 `/usr/local/bin/ufw-okboy-knock`；配置在 `~/.config/ufw-okboy/config.yaml`（实际路径在安装结束时打印）；定时器为 `ufw-okboy-knock.timer`。脚本要写入 `/usr/local/bin`，通常像上面那样用 root 运行，这时装为系统定时器；以对该目录有写权限的普通用户运行时，装为用户定时器（用 `systemctl --user` 管理）。

手动安装与使用：

```bash
# 把客户端和配置模板拷到客户端机器
ssh user@client-machine 'mkdir -p ~/ufw-okboy'
scp client/knock.py client/config.example.yaml user@client-machine:~/ufw-okboy/

# 在客户端机器上
cd ~/ufw-okboy
cp config.example.yaml config.yaml
chmod 600 config.yaml
# 编辑 config.yaml：server_url、username、secret；服务器用自签证书时填 pin_sha256
pip install pyyaml    # 可选：没有 PyYAML 时使用内置的简易解析器

python3 knock.py                          # 敲门一次（默认读取当前目录的 config.yaml）
python3 knock.py status                   # 查看登记状态
python3 knock.py -c /path/to/config.yaml  # 指定配置文件
python3 knock.py --watch 30               # 每 30 秒敲门一次，Ctrl-C 停止
python3 knock.py --no-verify-ssl          # 不校验证书（不推荐；配了 pin_sha256 时不起作用）
```

单次运行时打印服务器返回的 JSON，成功时退出码为 0，失败为 1；`--watch` 模式每次输出一行结果。

### 方式三：Shell 客户端

零依赖，只需 `curl` 和 `openssl`。把 `client/knock.sh` 拷到客户端机器后：

```bash
sudo install -m 755 knock.sh /usr/local/bin/ufw-okboy-knock.sh

# 配置（默认路径 ~/.config/ufw-okboy/config，也可用环境变量 KNOCK_CONFIG 指定）
mkdir -p ~/.config/ufw-okboy
cat > ~/.config/ufw-okboy/config << 'EOF'
SERVER_URL=https://your-server:8443
USERNAME=alice
SECRET=你的密钥
# PIN_SHA256=服务器的公钥 pin
EOF
chmod 600 ~/.config/ufw-okboy/config

# 使用
ufw-okboy-knock.sh                 # 敲门
ufw-okboy-knock.sh status          # 查看状态
ufw-okboy-knock.sh --insecure      # 或 -k：本次不校验证书（配了 PIN_SHA256 时不起作用）

# cron 定时（每 2 分钟）
crontab -e
# */2 * * * * /usr/local/bin/ufw-okboy-knock.sh >/dev/null 2>&1
```

- 配置文件会被当作 shell 脚本 `source`，只写上面这几行。服务器用自签证书时取消 `PIN_SHA256` 的注释并填上 pin（curl 的要求见 [客户端连自签证书](#客户端连自签证书)）；另有 `INSECURE=1`（或 `INSECURE=true`）表示不校验证书，不推荐。
- 脚本打印服务器返回的 JSON。连不上服务器时退出码非 0；服务器返回错误时退出码仍为 0，以 JSON 中的 `ok` 为准。
- `deploy/knock.service` 与 `deploy/knock.timer` 是对应的 systemd 示例：以 root 每 2 分钟运行一次 `/usr/local/bin/ufw-okboy-knock.sh`。
- `knock.sh` 用 `openssl -hmac` 计算签名，密钥会出现在本机的进程参数里；多用户机器上请改用 `knock.py`。

### 方式四：Windows 客户端

用系统自带的 PowerShell（Windows PowerShell 5.1 或 PowerShell 7），不需要 Python。以**管理员身份**打开 PowerShell：

```powershell
# 一键安装（推荐）：密钥会提示输入（不回显）；自签证书的服务器加 -PinSha256 <服务器公钥 pin>
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/install-client.ps1))) -Server https://your-server:8443 -User alice

# 再加一台服务器：换个 -Server 再运行一遍（每台一个配置文件，由同一个计划任务依次敲门）
# 卸载（删除计划任务和全部文件）：把第二行 -Server 之后的参数换成 -Uninstall

# 发布包：解压后在包目录里运行（直接用包里的 client\knock.ps1，不联网下载）
powershell -ExecutionPolicy Bypass -File .\deploy\install-client.ps1 -Server https://your-server:8443 -User alice
```

`install-client.ps1` 的参数：

| 参数 | 说明 |
|------|------|
| `-Server <URL>` | 服务器地址（`https://主机[:端口]`） |
| `-User <用户名>` | 用户名 |
| `-Secret <密钥>` | 密钥；省略时提示输入，不回显，也不会留在 PowerShell 历史里 |
| `-IntervalMinutes <分钟>` | 敲门间隔，1–1440，默认 1。计划任务只有一个，每次运行安装脚本都按本次的值重新注册 |
| `-PinSha256 <pin>` | 服务器的公钥 pin（服务器用自签证书时），写入 `pin_sha256`，见 [客户端连自签证书](#客户端连自签证书)。为同一台服务器重新运行时保留已有的 pin，传 `''` 去掉；旧配置里的 pin 读不出时中止 |
| `-NoVerifySsl` | 不校验证书，写入 `verify_ssl: false`（不推荐：无法识别中间人） |
| `-GhMirror <前缀>` | 从 GitHub 下载 `knock.ps1` 时使用的代理前缀（也可用环境变量 `UFW_OKBOY_GH_MIRROR`） |
| `-Uninstall` | 删除计划任务和整个安装目录 |

用同一个 `-Server` 再运行一次，可以修改该服务器的用户名或密钥。

装好后：

| 项 | 位置 / 说明 |
|------|------|
| 客户端脚本 | `C:\Program Files\UFW-OkBoy\knock.ps1` |
| 配置 | `C:\Program Files\UFW-OkBoy\servers\<主机>[_<端口>].yaml`，格式与 `knock.py` 的 `config.yaml` 相同 |
| 计划任务 | `UFW-OkBoy Knock`，以 SYSTEM 身份每分钟运行一次（安装时用 `-IntervalMinutes` 调整），开机即生效，不用登录 |
| 最近一次结果 | `C:\Program Files\UFW-OkBoy\last-run.log` |

整个 `C:\Program Files\UFW-OkBoy` 只有 SYSTEM 和管理员能访问（里面有密钥，脚本又以 SYSTEM 身份运行），所以下面的命令和查看日志都要在管理员 PowerShell 里执行。

```powershell
# 手动敲门 / 查看状态（管理员 PowerShell）
powershell -ExecutionPolicy Bypass -File 'C:\Program Files\UFW-OkBoy\knock.ps1'
powershell -ExecutionPolicy Bypass -File 'C:\Program Files\UFW-OkBoy\knock.ps1' status

# 不装计划任务，只用脚本（任意 knock.py 格式的配置文件）
powershell -ExecutionPolicy Bypass -File .\client\knock.ps1 -Config .\config.yaml
```

`knock.ps1` 的第一个位置参数为 `knock`（默认）或 `status`；`-Config` 指定配置文件或目录（目录时使用其中全部 `*.yaml`，默认是脚本旁边的 `servers` 目录）；`-Insecure` 不校验证书（配置里有 `pin_sha256` 时不起作用）。任一服务器失败时退出码为 1。

### 自签证书注意事项

使用自签证书部署时，客户端用服务器的公钥 pin 认服务器（pin 从哪里来、为什么不直接关闭校验，见 [客户端连自签证书](#客户端连自签证书)）：

- **Python 客户端**：`config.yaml` 中加 `pin_sha256: "<pin>"`
- **Shell 客户端**：配置文件中加 `PIN_SHA256=<pin>`
- **Windows 客户端**：一键安装时加 `-PinSha256 <pin>`（写入 `pin_sha256`）
- **网页客户端**：浏览器显示安全警告；核对证书指纹与服务器上的一致后再继续（见[客户端连自签证书](#客户端连自签证书)），证书变了就不要继续

---

## 日常管理

以下服务器端命令都在 `/opt/ufw-okboy/server` 下以 root 执行。

### 查看当前状态

```bash
cd /opt/ufw-okboy/server
sudo ../venv/bin/python app.py -c config.yaml list
```

输出示意（列宽以实际为准）：

```text
=== Configured Users ===

=== DB Users (not in config) ===
  alice                 IP: 198.51.100.3
  admin                 IP: 203.0.113.5

=== UFW Rules (managed) ===
  22/tcp                     ALLOW       Anywhere                   # SSH (auto-allowed by ufw-okboy installer)
  8080/tcp                   ALLOW       203.0.113.5                # ufw-okboy:admin:web
  8080/tcp                   ALLOW       198.51.100.3               # ufw-okboy:alice:web
  3306/tcp                   ALLOW       198.51.100.3               # ufw-okboy:alice:db
  22/tcp (v6)                ALLOW       Anywhere (v6)              # SSH (auto-allowed by ufw-okboy installer)
```

- `Configured Users` 只列配置文件里旧版 `users:` 下的用户，通常为空；数据库里的用户列在 `DB Users` 下（没有 IP 时显示 `N/A`，顺序不固定）。
- 规则取自 `ufw status`，动作列是 `ALLOW`；注释里含 `ufw-okboy` 的规则都会列出，包括安装脚本放行 SSH 时加的规则。
- 最后敲门时间用 `user-list` 查看。

### 添加新用户

在管理控制台的「用户」面板里新建，或：

```bash
cd /opt/ufw-okboy/server
sudo ../venv/bin/python app.py -c config.yaml user-add bob
# 记下输出的密钥，经安全渠道交给用户
```

### 创建新端口组并加入用户

```bash
cd /opt/ufw-okboy/server
sudo ../venv/bin/python app.py -c config.yaml group-add db 3306
sudo ../venv/bin/python app.py -c config.yaml user-join alice db
```

### 撤销用户访问

```bash
cd /opt/ufw-okboy/server

# 方式 1：让用户离开某个分组
sudo ../venv/bin/python app.py -c config.yaml user-leave alice web

# 方式 2：吊销（关闭全部端口并更换密钥，保留用户和成员资格）
sudo ../venv/bin/python app.py -c config.yaml revoke alice

# 方式 3：删除用户（删除其全部规则）
sudo ../venv/bin/python app.py -c config.yaml user-del alice
```

用户也可以用 API 自己关闭某个分组（`$AUTH` 的生成见 [签名示例](#签名示例)）：

```bash
curl -X PATCH -H "Authorization: $AUTH" -H "Content-Type: application/json" \
  -d '{"enabled":false}' https://your-server:8443/api/me/membership/1
```

### 更换用户密钥

用 `revoke`：换一个随机密钥（旧密钥立即失效），同时关闭该用户的全部端口、清除当前 IP，成员资格保留。用户用新密钥敲门后恢复访问。

```bash
cd /opt/ufw-okboy/server
sudo ../venv/bin/python app.py -c config.yaml revoke alice
# Revoked 'alice'. Ports closed, runtime state cleared.
# New secret (deliver to the user out-of-band): <新密钥>
```

在管理控制台里：别人那一行点「吊销」，自己那一行点「更换密钥」。只想断开、不换密钥时加 `--no-rotate`。

### 查看审计日志

- 管理控制台的「审计日志」面板：最近 50 条。
- API：`GET /api/admin/audit?limit=100`（见 [管理接口](#管理接口)）。
- 直接查数据库（`created_at` 为 UTC 时间）：

```bash
sudo sqlite3 /var/lib/ufw-okboy/ufw-okboy.db \
  "SELECT created_at, actor, action, target, detail FROM audit_log ORDER BY id DESC LIMIT 20;"
```

### 清理过期规则

```bash
cd /opt/ufw-okboy/server
# 手动清理：删除超过 7 天未敲门的用户的全部规则
sudo ../venv/bin/python app.py -c config.yaml cleanup --max-age 7

# 定时清理由 systemd 定时器每天执行一次
systemctl status ufw-okboy-cleanup.timer
journalctl -u ufw-okboy-cleanup -n 20 --no-pager
```

被清理的用户下一次敲门时规则自动恢复。天数写在 `ufw-okboy-cleanup.service` 的 `ExecStart` 里（`--max-age 7`）；要修改，用 `sudo systemctl edit ufw-okboy-cleanup.service` 写一个 drop-in 覆盖 `ExecStart`（先写一行空的 `ExecStart=`，再写新的命令）。直接改单元文件会在重跑安装脚本时被覆盖。

### 故障排查

**日志在哪里：**

| 日志 | 查看方式 |
|------|----------|
| 应用告警（敲门认证失败、限流、异常检测、ufw 执行失败等） | `journalctl -u ufw-okboy` |
| Gunicorn 自身的日志与访问日志 | `/var/log/ufw-okboy/error.log`、`/var/log/ufw-okboy/access.log` |
| 清理任务 | `journalctl -u ufw-okboy-cleanup` |
| Nginx | `/var/log/nginx/ufw-okboy-access.log`、`/var/log/nginx/ufw-okboy-error.log` |

**服务无法启动：**

```bash
journalctl -u ufw-okboy -n 50 --no-pager
```

**用户反馈连接失败：**

```bash
curl -k https://127.0.0.1:443/health        # 经 Nginx（端口换成实际端口）
curl http://127.0.0.1:5000/health           # 直接访问后端（Nginx 模式）
journalctl -u ufw-okboy -n 50 --no-pager
```

**数据库问题：**

```bash
sudo sqlite3 /var/lib/ufw-okboy/ufw-okboy.db ".schema"    # 查看表结构
```

数据库损坏或丢失时从备份恢复，见 [数据备份与恢复](#数据备份与恢复)。

---

## 安全机制

### 认证原理

客户端用密钥对「用户名:时间戳」计算 HMAC-SHA256，把结果放进请求头，密钥不在网络上传输：

```text
签名 = HMAC-SHA256(密钥, "用户名:时间戳")         # 小写十六进制
Authorization: HMAC-SHA256 用户名:时间戳:签名
```

- **密钥不在网络上传输**：截获请求只能得到签名，得不到密钥。
- **时间戳限定有效期**：与服务器时间相差超过 `signature_ttl`（默认 300 秒）的签名被拒绝。有效期内截获的请求头可以被重放，所以传输必须走 HTTPS（见 [已知限制](#已知限制)）。
- **不暴露用户是否存在**：用户不存在与签名错误都返回 `Invalid credentials`。
- **失败记录**：每次认证失败写入 `failed_attempts` 表，用于按 IP 限流（见 [请求限流](#请求限流)）。

### 防凭证共享

同一账号同一时间只绑定一个 IP。Alice 把凭证分享给 Bob 后：

1. Bob 连接 → 防火墙更新为 Bob 的 IP
2. Alice 立刻失去访问权限
3. Alice 续期 → 又把 Bob 踢掉
4. 两人不断互相踢，谁都无法稳定使用

**结论：共享凭证 = 自损。**

### 同一出口地址的多个用户

ufw 对同一个来源地址和端口只保留一条规则。同一分组的两个用户在同一个出口地址（NAT）后面时，两人共用这一条规则，规则的注释记的是最后敲门的那个人。删除、吊销或禁用这个人，会连带关掉另一个人的访问，直到对方下一次敲门（客户端会定时续期）时重新加上。这只影响可用性，不会多放行任何地址。

### 异常检测

同一用户在 `anomaly_window`（默认 3600 秒）内的 IP 变更次数达到 `anomaly_max_changes`（默认 5 次，首次登记也算一次）时，服务端在敲门响应里加上 `warning`（网页上显示「警告：检测到异常」），并写一条 `ANOMALY` 日志。这只是提示，敲门照常生效。

```bash
journalctl -u ufw-okboy | grep ANOMALY
```

### 审计日志

管理操作写入 `audit_log` 表（`actor`、`action`、`target`、`detail`、`created_at`），包括：建删用户与分组、成员资格变更（含用户自助开关）、吊销、设置管理员、TOTP 的注册、激活与关闭、删除系统规则，以及二次验证失败、越权开启分组、端口不在白名单等被拒绝的尝试。命令行的增删改操作也会记录，`actor` 为 `cli`。查看方法见 [查看审计日志](#查看审计日志)。

### 安全最佳实践

| 建议 | 说明 |
|------|------|
| 一人一号 | 不要多人共用同一个账号 |
| 及时换密钥 | 怀疑泄露时立即吊销（`revoke`），旧密钥即刻失效 |
| 启用 TOTP | 管理员启用二次验证，必要时设 `require_admin_totp: true` |
| 保护配置文件 | `config.yaml` 权限设为 600（写了旧版用户密钥时程序会自动收紧） |
| 启用自动清理 | 让不活跃用户的规则自动过期 |
| 定期备份 | 用 `app.py backup`，不要直接复制数据库文件 |
| 监控审计日志 | 定期查看管理控制台的审计日志 |
| 必须用 HTTPS | 不要在 HTTP 下使用 |
| 优先用域名 + Let's Encrypt | 浏览器无警告，客户端也不需要关闭证书校验 |

### 已知限制

设计上的取舍（签名可在有效期内重放、同一出口地址共用规则、经镜像安装等于信任镜像、`knock.sh` 的密钥出现在进程参数里）与漏洞报告方式见 [SECURITY.md](SECURITY.md)。

---

## 安全加固

### 请求限流

同一来源 IP 在 `throttle_window`（默认 300 秒）内的失败次数达到 `throttle_max_failures`（默认 10）后，它的 `/api/` 请求一律返回 **429**，直到失败记录超出窗口。计入的失败包括签名缺失、错误或过期，非管理员调用管理接口，TOTP 验证码错误；限流拒绝本身不计入。按 IP 而不按用户名限流，避免别人用你的用户名故意输错把你锁住。`throttle_max_failures: 0` 关闭限流。

安装脚本生成的 Nginx 配置里，`limit_req` 是注释掉的；示例配置 `nginx/ufw-okboy.conf` 启用了它（需要在 `http` 块里定义 `limit_req_zone`，见 [手动部署](#手动部署)），可作为额外一层。

> 只有直连来源属于 `trusted_proxies`（默认本机）时，服务端才从 `X-Real-IP`（或 `X-Forwarded-For` 的最右一项）读取客户端地址，客户端无法伪造 IP 进白名单。读到的必须是单个 IP：`any`、网段、主机名、回环地址都被拒绝。反向代理不在本机时，把它的地址加进 `trusted_proxies`。

### 吊销与强制重新认证

```bash
cd /opt/ufw-okboy/server
# 吊销：更换密钥（旧凭据立即失效）、关闭其全部端口、清除当前 IP
sudo ../venv/bin/python app.py -c config.yaml revoke alice
# 只断开，保留原密钥（用户的客户端下次敲门即恢复访问）
sudo ../venv/bin/python app.py -c config.yaml revoke alice --no-rotate
```

也可以在管理控制台点该用户的「吊销」；新密钥只显示一次，请经安全渠道交给用户。吊销先换密钥、再删规则：即使删除规则失败，旧密钥也已作废，这时会给出警告并保留当前 IP，便于再次吊销。

### 管理员二次验证（TOTP）

启用 TOTP 的管理员执行以下操作时，必须提供当前的 6 位动态码（RFC 6238，兼容 Google Authenticator、Authy 等验证器）：

- 新建、删除用户；设置、取消管理员；吊销（含更换自己的密钥）
- 新建、删除分组
- 为用户加入、移出分组，修改他人的成员资格开关
- 删除系统防火墙规则

启用方法：管理控制台「双因素认证（TOTP）」面板 →「注册 / 重新注册」→ 把显示的密钥或 `otpauth://` URI 加入验证器 → 输入 6 位验证码，点「激活」。

- 重新注册需要当前验证码；新验证器激活之前，原来的继续有效。
- 禁用需要当前验证码。
- 服务器与手机的时间误差需在约 30 秒以内（前后各容忍一个 30 秒周期）。
- `require_admin_totp: true` 时，未启用 TOTP 的管理员在启用之前不能执行上述操作。
- 命令行不经过 TOTP（它在服务器上以 root 运行）；API 用请求头 `X-TOTP-Code` 或请求体字段 `totp_code` 提供验证码（见 [TOTP 二次验证](#totp-二次验证)）。

> **重放保护**（`totp_replay_protection`，默认开启）：每个验证码只能用一次，激活时输入的那个也算，所以激活后紧接着的操作要等下一个验证码。需要在同一个 30 秒周期内连续执行多个敏感操作时，可设为 `false`。
>
> **错误次数上限**：同一账号在 `throttle_window` 内输错（含重放）验证码的次数达到 `throttle_max_failures` 后，该账号的所有 TOTP 校验返回 429，直到旧记录超出窗口。这个上限跨 IP、跨接口计算；错误的验证码同时计入来源 IP 的限流。

### 数据备份与恢复

```bash
cd /opt/ufw-okboy/server

# 在线备份：写到 backup_dir，附 .sha256，按 backup_keep 保留最近几份
sudo ../venv/bin/python app.py -c config.yaml backup
# Backup written: /var/lib/ufw-okboy/backups/ufw-okboy-20260928-143005-123456.db
#   sha256: <校验和>

# 从备份恢复：先停服务
sudo systemctl stop ufw-okboy
sudo ../venv/bin/python app.py -c config.yaml restore /var/lib/ufw-okboy/backups/ufw-okboy-20260928-143005-123456.db
sudo systemctl start ufw-okboy
```

- 备份用 SQLite 的在线备份 API，服务运行中也能得到一致的副本，文件权限 0600。备份里有明文密钥，请妥善保管。
- 恢复前会检查：来源不能是当前数据库本身；服务和清理任务都已停止，且没有其他进程打开数据库；有 `.sha256` 时核对校验和（不一致即中止，没有时只警告）。随后把当前数据库（连同 `-wal`）另存为 `ufw-okboy.db.pre-restore-<时间>`，再用备份替换。
- 恢复较早的备份后，可以运行 `sync`，按 UFW 中现有的规则回填用户的当前 IP。
- **不要直接 `cp` 数据库文件**：WAL 模式下可能拷到不完整的状态，务必用 `backup` 命令。

---

## 升级与版本管理

版本号记录在 `VERSION` 文件里。升级需要手动触发，root 服务不会自己联网拉代码。

### 选择升级方式

| 安装方式 | 升级方法 |
|------|------|
| 一键安装、发布包安装，或从其他目录运行 `deploy.sh`（安装目录不是 git 检出） | [一键升级脚本](#一键升级脚本upgradesh) `deploy/upgrade.sh` |
| 在 `/opt/ufw-okboy` 的 git 检出里运行 `deploy.sh` | [git 检出的安装](#git-检出的安装)：`app.py upgrade --force`，或手动用 git 更新 |
| 服务器访问不了 GitHub | 在解压好的新版本发布包里运行 `sudo bash deploy/upgrade.sh --repo-dir . -y` |

升级后浏览器按 Ctrl+Shift+R 强制刷新，加载新界面。

### 一键升级脚本（upgrade.sh）

```bash
# 升级到 master 分支的最新代码
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/upgrade.sh | sudo bash

# 升级到指定版本（分支或发布标签）
curl -fsSL https://raw.githubusercontent.com/lvusyy/UFW-OkBoy/master/deploy/upgrade.sh \
  | sudo bash -s -- --branch v2.4.2

# 用解压好的发布包离线升级
cd ufw-okboy-v2.4.2
sudo bash deploy/upgrade.sh --repo-dir . -y
```

脚本依次：

1. 用当前（旧）版本的 `app.py backup` 备份数据库（写到 `backup_dir`）。
2. 取得目标版本的代码：`git clone --depth 1 --branch <分支或标签>`，失败时改为下载源码包；给了 `--repo-dir` 则直接用该目录。
3. 把当前的 `server/` 复制为 `server.bak-<时间>` 作为回滚点，再复制新的程序文件和 `VERSION`（`config.yaml` 不动）。
4. 安装新增的 Python 依赖（`--repo-dir` 目录里有 `vendor/` 时优先离线安装）。
5. `ufw-okboy.service`、`ufw-okboy-cleanup.service` 没有设置 `UMask=0077` 时（v2.4.0 之前生成的单元），添加 drop-in `/etc/systemd/system/<单元>.d/50-umask.conf`。
6. 重启服务；数据库迁移在启动时自动执行。
7. 健康检查：按服务单元里 Gunicorn 的 `--bind` 地址访问 `/health`（单元带 `--certfile`，即 `--no-nginx` 安装时走 HTTPS），最多 6 次，每次间隔 2 秒。
8. 成功：保留最近 3 个代码快照。失败：退回旧代码并重启服务，并打印恢复数据库备份的命令（停服务、`restore`、再启动）。数据库不会自动恢复：恢复会撤销备份之后的所有改动，是否恢复由你决定。

`config.yaml`、Nginx 配置、证书和数据库都会保留；systemd 单元文件本身不改动（只可能加上第 5 步的 drop-in）。

| 参数 | 说明 |
|------|------|
| `--app-dir <路径>` | 安装目录，默认 `/opt/ufw-okboy` |
| `--service <名称>` | systemd 服务名，默认 `ufw-okboy` |
| `--branch <分支或标签>` | 目标分支或发布标签，默认 `master` |
| `--repo-dir <目录>` | 使用本地的源码目录或解压好的发布包，不再下载 |
| `--gh-mirror <前缀>` | 下载代码时使用的 GitHub 代理前缀（也可用环境变量 `UFW_OKBOY_GH_MIRROR`） |
| `--mirror <URL>` | PyPI 索引地址；不指定且连不上 pypi.org 时改用清华镜像 |
| `--offline` | 只用 `--repo-dir` 目录里 `vendor/` 的 wheels 安装依赖，不联网 |
| `-y`, `--yes` | 为脚本化调用保留；脚本不会提问 |
| `-h`, `--help` | 显示脚本说明 |

### 查看当前版本

```bash
cd /opt/ufw-okboy/server
sudo ../venv/bin/python app.py -c config.yaml --version    # 输出如：UFW OkBoy 2.4.2
cat /opt/ufw-okboy/VERSION
```

### 检查新版本

```bash
cd /opt/ufw-okboy/server
sudo ../venv/bin/python app.py -c config.yaml upgrade --check
```

查询 GitHub 上的最新 release，打印当前版本和最新版本；只提示，不拉代码、不改动服务，可以放进定时任务。GitHub 不通时可经 `config.yaml` 的 `github_mirror` 或环境变量 `UFW_OKBOY_GH_MIRROR` 走代理。

### git 检出的安装

`/opt/ufw-okboy` 是 git 检出时，可以用内置的升级命令：

```bash
cd /opt/ufw-okboy/server
sudo ../venv/bin/python app.py -c config.yaml upgrade --force       # 需要输入 yes 确认
sudo ../venv/bin/python app.py -c config.yaml upgrade --force -y    # 不确认
```

流程：查询最新版本（查不到时中止）→ 用 SQLite 在线备份把数据库存为 `<db_path>.pre-upgrade-<当前版本>-<时间戳>` → `git pull --ff-only`（用检出自己的远端和当前分支；失败时什么都不改）→ 执行数据库迁移 → `systemctl restart ufw-okboy` → 访问 `http://127.0.0.1:5000/health` → 失败时把代码退回升级前的提交（`git reset --hard`）并重启服务。数据库不会自动恢复：恢复备份会撤销升级期间的吊销、删除等改动，需要时按提示手动恢复。

注意：

- 不是 git 检出的安装会提示改用 `deploy/upgrade.sh`，并以非 0 退出。
- 健康检查固定访问 `http://127.0.0.1:5000/health`：`--no-nginx` 安装的 git 检出会被误判为失败而回滚，这种安装请手动更新（见下）。
- 检出停在标签上（detached HEAD）时 `git pull` 会失败，同样手动更新。
- 这条路径不经过 `upgrade.sh`，不会自动添加 `UMask=0077`。单元里没有这一项时（v2.4.0 之前生成的单元），手动添加同样的 drop-in，再执行 `sudo systemctl daemon-reload && sudo systemctl restart ufw-okboy`：

```ini
# /etc/systemd/system/ufw-okboy.service.d/50-umask.conf
# （ufw-okboy-cleanup.service 同样放在 ufw-okboy-cleanup.service.d/ 下）
[Service]
UMask=0077
```

手动更新：

```bash
cd /opt/ufw-okboy/server
sudo ../venv/bin/python app.py -c config.yaml backup
cd /opt/ufw-okboy
sudo git fetch --tags
sudo git checkout v2.4.2                              # 或在分支上执行 sudo git pull --ff-only
sudo venv/bin/pip install -r server/requirements.txt
sudo systemctl restart ufw-okboy                      # 数据库迁移在启动时执行
```

> **安全说明**：代码来自 GitHub（或你指定的代理），没有签名校验；经代理安装或升级，等于信任该代理。数据库迁移只增加列和索引（v5 会把公开的示例密钥换成随机值），不删除数据。

### 从 v1.x 升级

v1.x 用 `config.yaml` 里的 `users:` 和 `state.json` 保存用户与状态。v2 起首次启动时新建数据库，并一次性导入：

- `users:` 里的用户（`CHANGE_ME` 开头的示例密钥会换成随机值）
- `state.json` 里各用户的当前 IP 和最后敲门时间
- `protected_ports:` 的每个端口建成 `default-<端口>` 分组，并把导入的用户全部加入

这些配置项只在新建数据库时读取，之后不再生效。

### 版本化数据库迁移

数据库里的 `schema_version` 表记录已执行的迁移，服务启动时按顺序执行尚未执行的迁移。当前为 v6：

| 版本 | 内容 |
|------|------|
| 1 | 基线：6 张数据表 |
| 2 | `users` 增加 TOTP 列 |
| 3 | `users.totp_last_counter`（TOTP 重放保护） |
| 4 | `groups` 的 `(port, proto)` 唯一索引（已有重复数据时跳过） |
| 5 | 把公开的 `CHANGE_ME` 示例密钥换成随机值 |
| 6 | `users.totp_pending_secret`（重新注册 TOTP 时，确认前原验证器继续有效） |

从 v2.0（没有 `schema_version` 表）升级上来的数据库只记录基线 v1，不会重新导入用户。

### 构建发布包

```bash
bash deploy/build-release.sh                 # 版本号取自 VERSION，输出到 dist/
bash deploy/build-release.sh v2.4.2 out      # 指定版本号和输出目录
```

产物为 `ufw-okboy-v<版本>.tar.gz`（解压为同名目录）和 `.sha256` 校验和文件。包内有服务端、客户端、部署脚本（含 `install.sh`）、Nginx 示例和文档，以及 CPython 3.10–3.14（x86_64、aarch64）的依赖 wheels（`vendor/`，下载 wheels 需要 pip 和网络）。某个组合的 wheels 下载失败时只警告，设置 `REQUIRE_WHEELS=1` 则构建失败。GitHub Release 由发布流程用同一个脚本构建，通常不需要自己打包。

---

## 常见问题

### 我的 IP 变了怎么办？

什么都不用做。网页客户端在下一次续期（30 秒内）自动更新；Python、Shell、Windows 客户端在下一个周期更新。

### 关掉网页后怎么办？

规则不会立即删除，会保留到被清理为止（默认 7 天未敲门）。再次打开网页即可恢复。

### 如何只允许用户访问特定端口？

用分组。为每个端口建一个分组，让用户只加入需要的分组：

```bash
cd /opt/ufw-okboy/server
sudo ../venv/bin/python app.py -c config.yaml group-add web 8080
sudo ../venv/bin/python app.py -c config.yaml group-add db 3306
sudo ../venv/bin/python app.py -c config.yaml user-join alice web    # alice 只能访问 8080
sudo ../venv/bin/python app.py -c config.yaml user-join bob db       # bob 只能访问 3306
```

### 如何临时关闭某个端口的访问？

- **管理员**：在管理控制台的「管理分组」里取消勾选（移出分组），或用 `user-leave`。只想暂时关闭、保留授权时，用 API 把成员资格设为关闭：`PATCH /api/membership/<用户 ID>/<分组 ID>`，或 `POST /api/admin/users/<用户 ID>/groups` 带 `"enabled": false`。
- **用户自己**：用 API 关闭，之后可以自己重新开启。网页上的「我的分组授权」面板只在管理控制台里，普通用户看不到。

```bash
curl -X PATCH -H "Authorization: $AUTH" -H "Content-Type: application/json" \
  -d '{"enabled":false}' https://your-server:8443/api/me/membership/2
```

### 自签证书如何使用？

部署时加 `--self-signed`（不带 `--domain` 时本就是自签）。客户端用服务器的公钥 pin 认服务器，做法见 [自签证书注意事项](#自签证书注意事项)。国内自签 + IP + 高位端口的完整做法见 [国内部署专题](#国内部署专题)。

### 安装时卡在下载 / 下载失败？（国内常见）

- **拉代码卡住**（GitHub）：用 `--gh-mirror <可用代理>`，或直接用 [发布包](#最稳路径发布包离线安装推荐)（最稳）。
- **装 Python 依赖卡住**（PyPI）：连不上 pypi.org 时脚本自动改用清华镜像；也可以用 `--mirror <镜像>` 指定，或用发布包（自带 wheels，不访问 PyPI）。
- **装系统软件包卡住**（apt/dnf）：请先把系统换成国内镜像源；这一步由系统包管理器负责，安装脚本不修改软件源配置。

### 网页能打开，但客户端敲门失败？

- 多半是**自签证书**没配好：给客户端配上服务器的公钥 pin（`knock.py`、`knock.ps1` 的 `pin_sha256`，`knock.sh` 的 `PIN_SHA256`），见 [客户端连自签证书](#客户端连自签证书)。`knock.py`、`knock.ps1` 报 pin 不符时，信息里会带上这次连接对方出示的 pin（`knock.sh` 只有 curl 的错误）：它可能来自中间人，要以服务器上算出的为准，不要照抄。
- 返回 `Signature expired`：客户端时钟与服务器相差超过 `signature_ttl`（默认 300 秒），请校准时间（例如启用 NTP）。
- 手动验证：`python3 knock.py -c config.yaml status`，看返回的具体错误。

### 网页/客户端完全连不上服务器？

按顺序排查：

1. **云安全组**：在云控制台放行你的端口（如 8443/tcp）。这是最常见的原因，UFW 放行 ≠ 安全组放行。
2. **公网 IP**：确认访问的是公网 IP；NAT 云主机重装时加 `--ip <公网 IP>`，让证书 SAN 与访问地址一致。
3. **服务状态**：`systemctl status ufw-okboy` 与 `journalctl -u ufw-okboy -n 50`。
4. **本机自检**：`curl -k https://127.0.0.1:<端口>/health` 应返回 `{"ok":true,"service":"ufw-okboy"}`。

### 敲门返回 400「Cannot determine real client IP」？

服务端没取到有效的客户端地址：Nginx 没有传递 `X-Real-IP` / `X-Forwarded-For`，或请求来自服务器本机（回环地址不能放行）。检查 Nginx 的 `/api/` 配置（见 [手动部署](#手动部署)），并从另一台机器敲门。

### 敲门返回 503「Firewall busy; retry shortly」？

服务端这次没能完成防火墙操作：等待主机锁超过 20 秒（例如清理任务或其他命令正在占用），或列不出 UFW 规则、命令超时。客户端下一次敲门会自动重试。持续出现时，确认 `sudo ufw status` 显示 active（UFW 未启用时规则列不出来，敲门会一直失败），并查看 `journalctl -u ufw-okboy`。

### 装完之后 SSH 连不上了？

v2.2.1 起，安装脚本会先放行 SSH 再启用 UFW；UFW 已经启用时不改动 SSH 规则。如果把 SSH 交给了 OkBoy 管理，客户端停止敲门超过 7 天后规则会被清理。被锁在外面时，用云厂商的控制台或 VNC 登录，执行 `sudo ufw allow 22/tcp`，再按 [用 OkBoy 管理 SSH（22 端口）](#用-okboy-管理-ssh22-端口) 重新设置。

### 数据库丢失怎么办？

从备份恢复，然后运行 `sync`，按 UFW 中现有的规则回填用户的当前 IP：

```bash
cd /opt/ufw-okboy/server
sudo systemctl stop ufw-okboy
sudo ../venv/bin/python app.py -c config.yaml restore /var/lib/ufw-okboy/backups/ufw-okboy-20260928-143005-123456.db
sudo systemctl start ufw-okboy
sudo ../venv/bin/python app.py -c config.yaml sync
```

`sync` 不能重建用户和分组。没有备份时，服务启动会新建一个空数据库：用 `user-add <名称> --admin` 重建管理员，再重建用户和分组。原有的 `ufw-okboy:` 规则可以按注释手动删除（`sudo ufw status numbered` 查编号）；重建了同名用户的，其旧规则会在该用户下次敲门、被吊销或被清理时删除。

### 应该备份什么？

- 数据库：用 `app.py backup`（见 [数据备份与恢复](#数据备份与恢复)），不要直接复制 `ufw-okboy.db`。备份里有明文密钥，请妥善保管。
- 配置文件：`/opt/ufw-okboy/server/config.yaml`。
- 证书：自签证书在 `/etc/ssl/ufw-okboy/`；Let's Encrypt 证书在 `/etc/letsencrypt/`。
