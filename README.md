# Banner 指纹识别系统

使用 Go 标准库实现的被动 Banner 识别系统，包含独立 server、独立 client、外部 JSON 指纹规则、多阶段 Docker 镜像和 Docker Compose。输入是一批已经采集的 `ip`、`port`、`banner`，输出协议、软件、版本、操作系统提示和置信度；系统不会连接输入中的目标地址或扫描网络。

## 一键运行

准备 Docker Engine / Docker Desktop 和 Docker Compose v2，在项目目录执行：

```console
docker compose up
```

首次运行自动构建 server 和 client 镜像。server 加载并校验规则后提供健康检查；Compose 等待 server 真正健康再启动 client。client 读取 `samples/banners.json`，访问 `http://server:8080/fingerprint`，在标准输出打印 20 条格式化 JSON 结果，然后以状态码 0 退出。server 保持运行；client 退出是批处理完成的正常行为。

本机接口为 `http://127.0.0.1:8080`。需要后台运行时：

```console
docker compose up --build -d
docker compose logs client
docker compose ps -a
docker compose down
```

如果 8080 已被占用，可设置 `BANNER_PORT`，如 PowerShell 中 `$env:BANNER_PORT = "18080"` 后执行启动命令。client 始终使用容器内的 8080，不依赖宿主机映射端口。首次构建需要取得 Go 基础镜像；最终镜像运行时不需要下载依赖或联网访问外部服务。

修改 `samples/banners.json` 后可以再次运行 client，无需重建镜像：

```console
docker compose run --rm client
```

规则和样例文件通过只读绑定挂载提供给服务，同时最终镜像也带有默认文件，可以独立运行。修改 `rules/fingerprints.json` 后执行 `docker compose restart server`；规则在启动时加载，不进行热更新。

## API 和输入格式

`GET /health` 返回 `200` 和 `{"status":"ok"}`。只有规则加载成功、服务开始监听后，这个请求才会成功；错误的规则或正则使启动直接失败，避免带着失效规则对外服务。

`POST /fingerprint` 接受标准 JSON 数组，推荐 `Content-Type: application/json`。例如：

```json
[
  {"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"},
  {"ip":"1.2.3.5","port":80,"banner":"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"},
  {"ip":"1.2.3.23","port":12345,"banner":"QUIT\r\n"}
]
```

在 Linux / macOS 中直接提交文件：

```console
curl -sS http://127.0.0.1:8080/health
curl -sS -H 'Content-Type: application/json' --data-binary @samples/banners.json http://127.0.0.1:8080/fingerprint
```

在 Windows PowerShell 中可以使用 `curl.exe` 执行相同命令，避免 `curl` 的旧版 PowerShell 别名行为。

返回数组与输入等长、顺序一致，所有结果都有七个字段：

```json
[
  {"ip":"1.2.3.4","port":22,"protocol":"SSH","product":"OpenSSH","version":"8.9p1","os_hint":"Ubuntu","confidence":0.95},
  {"ip":"1.2.3.5","port":80,"protocol":"HTTP","product":"nginx","version":"1.24.0","os_hint":"","confidence":0.9},
  {"ip":"1.2.3.23","port":12345,"protocol":"unknown","product":"","version":"","os_hint":"","confidence":0}
]
```

字段缺乏证据时返回空字符串；未知 Banner 是成功识别请求中的 `unknown` 结果，不是接口错误。端口仅作为输入信息保留，不能凭 22、80、3306 等端口猜测协议。443 / 8443 上的明文 HTTP Banner 仍返回 `HTTP`，无法从明文响应推断传输层是否使用 TLS。

二进制 Banner 使用 JSON 的 `\u0000` 等合法转义，或者使用扩展字段 `banner_base64` 传输原始字节：

```json
[{"ip":"1.2.3.19","port":9999,"banner_base64":"FgMBAKUBAACh"}]
```

`banner` 和非空 `banner_base64` 不可同时使用。题目展示的 `\x00` / `\xa5` 是字节说明方式，并非合法 JSON 转义；样例中的 MySQL 使用合法 JSON 空字节转义，TLS 使用 Base64 保存精确字节。仅有截断的 TLS 字节头不足以确认 TLS 完整记录，因此返回 `unknown`。

请求约束与错误语义：

| 情况 | 响应 |
| --- | --- |
| 有效请求、空数组、未命中规则 | 200；结果数组，空数组返回 `[]` |
| 非法 JSON、额外未知字段、非数组 / `null`、无效 IP / 端口、非法 Base64 | 400；`{"error":"..."}` |
| 请求超过 8 MiB 或批次超过 10,000 条 | 413；JSON 错误 |
| 单条 Banner 解码后超过 64 KiB | 400；JSON 错误 |
| 非 JSON Content-Type | 415；JSON 错误 |
| 方法不支持 | 405，并返回 `Allow` |
| 已有 4 个识别请求执行中 | 503，附带 `Retry-After: 1` |

整个批次先校验再识别，避免无效记录导致部分成功结果。IPv4 和 IPv6 均受支持。服务设置 HTTP 读写、请求头和空闲超时，并限制正文、批次、单条长度和请求并发；健康检查不占用识别请求名额。日志仅记录批次数量和耗时，不输出原始 Banner。

## 识别机制与边界

引擎按协议证据识别，再从协议对应的软件字段提取产品、版本和系统提示。HTTP 只使用响应状态行和响应头，防止把 HTML 正文中的 `Server: nginx` 当成服务端软件。SSH 按 SSH identification line 识别；MySQL 使用二进制 HandshakeV10 包头、协议字节和 NUL 结尾版本字段；Redis 使用明确的 RESP 响应或 INFO 信息；FTP 使用服务欢迎语和产品标志。

| 类别 | 可识别信息 |
| --- | --- |
| SSH | SSH 2.0 / 1.99，OpenSSH 等软件及版本，Ubuntu / Debian 等明示系统线索 |
| HTTP | HTTP 响应、nginx / Apache / Jetty / Microsoft-IIS 产品及版本，头部明示系统线索 |
| MySQL | MySQL HandshakeV10 的版本；MariaDB 区分按软件版本字符串证据处理 |
| Redis | `+PONG`、明确的 `-ERR` / `-NOAUTH` 回复和 INFO 版本线索 |
| FTP | ProFTPD / vsFTPd / Pure-FTPd 软件，存在时提取版本 |
| 其他 | `unknown`，不把常见端口或任意数字当成版本证据 |

`confidence` 是规则给出的启发式可信度，不是经过数据集校准的概率。带有明确产品和版本的常见规则通常为 0.85–0.95；仅凭 Redis 回复等协议特征的信息较少，使用更低值；未命中为 0。`os_hint` 只从 Banner 的明示线索提取，不把产品名称自动等同于服务器操作系统。

样例 MySQL 握手是扫描中截取的前缀，其包头声明的包长度大于已提供字节。引擎允许在版本字段完整且 NUL 终止时提取版本，而不要求后续握手字段全部到齐。截断到版本字符串中间、缺失 NUL 或格式不符合握手特征时不据此猜版本。

Banner 可以伪造，也可能来自反向代理；HTTP `Server` 头只能说明对方主动暴露的信息。系统不会主动补充探测、推断隐藏版本或给出 CVE 匹配，空字段明确表示证据不足。

## 规则扩展

文本软件指纹与 Go 程序解耦，保存在 `rules/fingerprints.json`。启动时编译正则并校验规则；识别时复用只读规则。增加软件规则后不需要改 Go 识别业务代码，按现有文件中的结构添加对应协议、匹配表达式、捕获组和置信度即可。协议结构解析（如 MySQL 二进制握手）保留在代码中，软件识别模式和版本提取表达式位于规则文件。

顶层 `schema_version` 为 1，`rules` 为按顺序匹配的规则数组，`os_hints` 为系统提示规则数组。产品规则示例：

```json
{
  "name": "http-haproxy",
  "protocol": "HTTP",
  "target": "http_server",
  "pattern": "(?i)^HAProxy(?:/([0-9][A-Za-z0-9._+-]*))?(?:[ \\t]|$)",
  "product": "HAProxy",
  "version_group": 1,
  "confidence": 0.9
}
```

把这条规则插入 `http-generic` 之前；同一协议首个命中规则决定输出。`version_group` 使用从 1 开始的捕获组索引，0 表示不提取版本；`confidence` 必须在 `(0,1]` 内。`http_server` 仅匹配响应头中的 Server 值，`ssh_software` 匹配 SSH identification 的软件部分，`mysql_version` 匹配握手中抽取的版本串，`banner` 匹配已确认协议的 Banner（HTTP 仅响应头部分）。重复名称、不合法协议 / target、错误正则或越界捕获组会导致启动失败。

规则使用 Go 的 RE2 正则，避免回溯型正则的指数级耗时。扩展前应增加一个正例和一个容易误报的反例，运行测试，并确认规则顺序与已有模式没有歧义。规则更新后重启 server 使其生效。

## 部署设计

client 通过 Compose 服务名 `server` 访问服务，二者共享仅用于本应用的 internal 网络。只有 server 的端口映射到宿主机的 `127.0.0.1`，client 没有端口映射。`depends_on: condition: service_healthy` 等待真实 HTTP 健康检查，不使用固定 sleep 作为启动顺序控制。健康检查由 server 可执行文件自身发起，最终镜像不需要 shell、curl 或 wget。[Compose 启动依赖说明](https://docs.docker.com/compose/how-tos/startup-order/)

Dockerfile 在固定 Go 1.27.2 编译镜像内设置 `CGO_ENABLED=0`，使用 `-trimpath` 和 `-ldflags="-s -w"` 构建静态程序；两个最终 target 都使用 `scratch`，仅包含对应二进制和必要数据。容器以 UID / GID 65532 运行，根文件系统只读，删除全部 Linux capabilities，禁止获得新权限，限制进程数、CPU 和内存。程序直接作为 PID 1 接收退出信号，server 有优雅关闭逻辑，无需 shell 入口或辅助进程。

这里提供的是便于离线克隆验证的单机部署基线：基础编译镜像和 CI 使用相同的 Go 1.27.2 补丁版本，`go.mod` 保持 Go 1.23 最低兼容版本，本地验证环境为 Go 1.23.5。对外开放接口、TLS 终止、认证、审计和高可用属于部署环境责任，默认仅提供本机入口。

## 本地开发与验证

安装 Go 1.23 或更新版本，无第三方 Go 依赖：

```console
go test ./...
go test -race ./...
go vet ./...
go run ./cmd/server --listen :8080 --rules rules/fingerprints.json
```

在另一个终端运行独立 client：

```console
go run ./cmd/client --input samples/banners.json --server http://127.0.0.1:8080 --timeout 30s
```

`--timeout` 为请求总超时；client 遇到本地文件错误、服务错误或非 2xx 响应时返回非零状态码，结果以 JSON 打印到 stdout，错误到 stderr。Windows 的 Go race 检测需要可用的 C 编译器；CI 使用 Linux 执行 `go test -race ./...`。

GitHub Actions 自动运行 race 测试、`go vet`、Compose 配置检查，并实际构建和启动 server、运行 client，验证批量输出和未知结果。首次推送后的实际执行状态以 Actions 页面为准。

交付前在本机 Go 1.23.5 环境实际通过 `go test -timeout 30s ./...`、`go vet ./...`、格式检查、Linux amd64 静态交叉编译和 Compose 配置校验。独立编译的 server、内置健康检查与 client 已完成真实 HTTP 调用，20 条样例的完整输出保存在 `samples/results.expected.json`；集成测试逐字段核对题目展示的前 7 条结果，并检查数组顺序及两条 unknown。Windows 本机的 race 可执行文件遇到现有 C 工具链运行错误，Linux race 由 CI 验证。

主要目录：

```text
cmd/server/             HTTP server 和自身健康检查入口
cmd/client/             文件读取与 HTTP 批量提交入口
internal/fingerprint/   协议解析、规则加载、产品识别与测试
internal/httpapi/       HTTP 校验、限制、响应及测试
rules/fingerprints.json 外部指纹规则
samples/banners.json    题目 20 条样例的合法 JSON 表达
Dockerfile              Go 编译和两个 scratch 运行 target
compose.yaml            健康依赖、网络隔离和运行约束
.github/workflows/      持续验证
```

协议依据：[SSH identification，RFC 4253 §4.2](https://www.rfc-editor.org/rfc/rfc4253.html#section-4.2)、[MySQL HandshakeV10](https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html)。实现测试还包含样例以外的协议变体、格式错误和容易混淆的输入，避免只对固定样例做字符串匹配。
