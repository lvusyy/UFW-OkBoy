# 安全策略 / Security Policy

[English](#english) | 中文

## 支持的版本

安全修复只进最新的次版本。报告问题前请先确认在最新版本上仍能复现。

| 版本 | 安全修复 |
|------|----------|
| 2.4.x | ✅ |
| < 2.4 | ❌ 请升级（见 [CHANGELOG](CHANGELOG.md)） |

## 报告漏洞

**请不要在公开 issue 里报告漏洞。** 请通过 GitHub 私密漏洞报告提交：
[Security → Report a vulnerability](https://github.com/lvusyy/UFW-OkBoy/security/advisories/new)

请尽量写明：

- 受影响的版本（`app.py --version`）和部署方式（Nginx 反代或直连、自签或 Let's Encrypt）；
- 复现步骤；
- 影响：例如能让哪些来源被放行、能读到或改动什么。

确认后会在私密通告里跟进，修复随新版本发布，并在 CHANGELOG 里说明。

## 已知限制

以下是已公开的设计取舍，不按漏洞处理：

- 签名只覆盖「用户名 + 时间戳」：截获的请求头在 `signature_ttl`（默认 300 秒）内可以重放，传输层依赖 HTTPS 保护。要消除这一点需要改客户端协议。
- 同一分组的两个用户在同一个出口地址后面时共用一条 ufw 规则：删除、吊销或禁用其中一人，会连带关掉另一人的访问，直到对方下一次敲门。只影响可用性，不会多放行。
- 客户端关闭证书校验（使用自签证书时常见）后，网络路径上的中间人可以截获请求，并在 `signature_ttl` 内重放。
- 经 GitHub 镜像执行一键安装脚本，等于信任该镜像。
- `knock.sh` 用 `openssl -hmac` 计算签名时，密钥会出现在本机的进程参数里；多用户机器上请改用 `knock.py`。

---

## English

### Supported versions

Security fixes go into the latest minor release only. Please check that an issue still reproduces on the latest release before reporting it.

| Version | Security fixes |
|---------|----------------|
| 2.4.x | ✅ |
| < 2.4 | ❌ please upgrade (see [CHANGELOG](CHANGELOG.md)) |

### Reporting a vulnerability

**Please do not report vulnerabilities in public issues.** Use GitHub private vulnerability reporting:
[Security → Report a vulnerability](https://github.com/lvusyy/UFW-OkBoy/security/advisories/new)

Please include the affected version (`app.py --version`), how it is deployed (behind Nginx or direct, self-signed or Let's Encrypt), steps to reproduce, and the impact (for example which sources end up allowed, or what can be read or changed). Reports are followed up in the private advisory; fixes ship in a release and are described in the CHANGELOG.

### Known limitations

These are documented design trade-offs, not treated as vulnerabilities:

- The signature covers only the username and the timestamp: captured request headers can be replayed within `signature_ttl` (300 seconds by default); the transport relies on HTTPS. Removing this needs a client protocol change.
- Two users of the same group behind the same egress address share one ufw rule: deleting, revoking or disabling one of them also closes access for the other until their next knock. This affects availability only; it never allows more.
- With certificate verification turned off in a client (common with self-signed certificates), a man in the middle can capture requests and replay them within `signature_ttl`.
- Running the one-line installer through a GitHub mirror means trusting that mirror.
- `knock.sh` computes the signature with `openssl -hmac`, which puts the secret in the local process arguments; on multi-user machines use `knock.py` instead.
