# WinRM 客户端加密上线检查

本检查用于在上线前确认 pypsrp 客户端的加密行为：哪种 `auth` × `encryption` ×
HTTP/HTTPS 组合会发出**包装（wrap）后的 SOAP**，哪种组合会在客户端**直接报错**，
避免凭据或 SOAP 正文被明文发出。

## 链路保护 vs 消息级保护

pypsrp 有两层相互独立的保护，不要混淆：

- **链路保护（TLS / HTTPS，`ssl=True`，端口 5986）**：由 TLS 加密整条连接。
  对 `basic`、`certificate` 这类没有会话安全上下文的认证方式，这是**唯一**
  可用的保密手段。证书校验由 `cert_validation` 控制，上线时不要关闭。
- **消息级保护（message encryption / wrap）**：pypsrp 用认证阶段建立的会话
  密钥（NTLM / Kerberos / Negotiate / CredSSP）对 SOAP 正文本身加密，以
  `multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted"`
  （或 Kerberos / CredSSP 变体）的 Content-Type 发出。即使 TLS 被终结在中间
  设备（负载均衡、反向代理）上，正文仍然密文。

只有 `credssp`、`kerberos`、`negotiate`、`ntlm` 能建立消息级加密所需的会话
上下文；`basic`、`certificate` 不能。

## 组合矩阵

| 传输 | encryption | basic / certificate | credssp / kerberos / negotiate / ntlm |
|---|---|---|---|
| HTTPS | `auto`（默认） | 明文 SOAP（TLS 保护） | 明文 SOAP（TLS 保护） |
| HTTPS | `never` | 明文 SOAP（TLS 保护） | 明文 SOAP（TLS 保护） |
| HTTPS | `always` | **ValueError，直接报错** | 包装后 SOAP |
| HTTP | `auto`（默认） | **ValueError，直接报错** | 包装后 SOAP |
| HTTP | `always` | **ValueError，直接报错** | 包装后 SOAP |
| HTTP | `never` | 明文 SOAP（**完全无保护，禁止上线**） | 明文 SOAP（**完全无保护，禁止上线**） |

报错在 `_TransportHTTP` 构造时抛出（`ValueError: Cannot use message
encryption with auth ...`），任何网络请求发出之前即失败。

包装组合的实际发送序列（由请求替身捕获确认）：

1. 先发一个 **body 为空的 POST**，让认证处理器完成 401 质询/响应握手；
2. 再发包装后的消息，Content-Type 为
   `multipart/encrypted;protocol="...";boundary="Encrypted Boundary"`，
   正文为加密后的 MIME 分段；
3. 若包装后的发送因超时失败，pypsrp 会作废加密状态，**重新执行第 1 步的
   认证 POST**，再重新包装并重发消息。

协议 token 按认证上下文选择：Negotiate/NTLM → `HTTP-SPNEGO-session-encrypted`，
纯 Kerberos → `HTTP-Kerberos-session-encrypted`，CredSSP →
`HTTP-CredSSP-session-encrypted`。

## 必须始终 wrap 的服务：可复现配置

对要求"任何情况下都必须消息级加密"的服务（例如 TLS 在 LB 上终结、或合规
要求端到端加密），客户端固定使用：

```python
from pypsrp.wsman import WSMan

with WSMan(
    server,
    port=5986,               # 或 ssl=False + 5985，wrap 行为相同
    auth="negotiate",        # 或 kerberos / ntlm / credssp
    username="user",
    password="pass",
    encryption="always",     # 关键：HTTPS 下默认 auto 不会 wrap
    cert_validation=True,
) as wsman:
    ...
```

要点：

- `encryption="always"` 在 HTTPS 下也会强制 wrap（默认 `auto` 在 HTTPS 下不
  wrap），在 HTTP 下与 `auto` 行为一致；
- 该配置对 `basic` / `certificate` 会直接报错，等于内置了上线防护；
- 服务端需允许加密消息：WinRM 服务的 `AllowUnencrypted` 保持默认 `false`
  （`winrm get winrm/config/service` 确认），否则明文组合才会被服务端接受，
  客户端检查就失去了最后一道对照。

## 运行检查

矩阵测试不需要真实 Windows 主机，用请求替身捕获每个请求的 Content-Type
与正文，并模拟认证握手后的重发分支：

```sh
python -m pytest tests/tests_pypsrp/test_encryption_matrix.py -v
```

覆盖：6 种认证 × 3 种 encryption × HTTP/HTTPS 共 36 种组合，外加
Kerberos/CredSSP 协议 token、HTTPS+always 强制 wrap、超时后重新认证并重发
等分支。上线前全部通过即可。
