# longx-cert

[Longx](https://github.com/mjason/longx) 的证书工具：用 ACME 的 DNS-01 验证向 Let's Encrypt 申请 TLS 证书，
支持 [lego](https://github.com/go-acme/lego) 的全部 DNS 服务商（腾讯云 DNSPod、阿里云、Cloudflare、华为云……共 222 家）。
DNS 验证只要求在你域名的公网 DNS 里放一条 TXT 记录，所以局域网里的 Longx 也能拿到浏览器认可的证书。

Longx 在第一次开启 HTTPS 时从这里的 Release 下载它（按版本和 sha256 固定，和 obscura 一样），平时不需要手动装。

## 用法

全部是 JSON，stdout 只输出一个 JSON 文档，lego 的日志以 JSON 行写到 stderr。

    longx-cert --version
    longx-cert providers                 # 服务商列表：代号、名字、别名、需要的环境变量
    longx-cert obtain < request.json     # 申请一次；成功 {"ok": true, …}，失败 {"ok": false, "error": …}，退出码 1

请求：

```json
{
  "directory": "letsencrypt",
  "domains": ["lx.example.com"],
  "provider": "tencentcloud",
  "env": {"TENCENTCLOUD_SECRET_ID": "…", "TENCENTCLOUD_SECRET_KEY": "…"},
  "account": null
}
```

- `directory`：`letsencrypt`（默认）、`letsencrypt-staging`，或任意 ACME 目录的 https 地址。
- `env`：服务商的变量，名字和 lego 文档一致，只在这次运行里设置。
- `account`：上次结果里的 `account`，续期时带上，不带就注册一个新账号；换了 CA 的账号不会被拿去用。
- 可选：`email`、`key_type`（`EC256` 默认 / `EC384` / `RSA2048` / `RSA3072` / `RSA4096`）、`resolvers`、
  `propagation_check`（`false` 跳过传播检查，改为等 `propagation_wait_s` 秒）、`timeout_s`（默认 600）。

结果：`certificate`（叶子证书加证书链）、`private_key`、`issuer`、`domains`、`not_before`、`not_after`、`serial`、
`cert_url`、`account`。

## 开发

    go test ./...        # 装了 pebble 时会跑一次完整的申请和续期
    go generate ./...    # 升级 lego 后重新生成服务商列表

pebble 是 Let's Encrypt 的测试 CA：

    go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1
    go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@v2.10.1

打 `v*` 标签就发布：Linux / macOS / Windows 的 amd64 和 arm64，`longx-cert-<os>-<arch>.tar.gz`（Windows 是 `.zip`），
附 `SHA256SUMS`。Longx 固定版本和每个包的 sha256。

MIT。
