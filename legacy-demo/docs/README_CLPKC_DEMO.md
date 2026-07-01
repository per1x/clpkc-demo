# CL-PKC Demo Workspace

本工作区按职责分成四层目录：

- `modules/`: 三个独立模块
- `scripts/`: 一键构建与联调脚本
- `docs/`: 协议与说明文档
- `logs/`: 运行日志

共享协议说明见 [CLPKC_PROTOCOL.md](/config/codex/clpkc-demo/docs/CLPKC_PROTOCOL.md)。

## 一键运行

在一台 Linux 机器上执行：

```bash
bash ./scripts/check-deps.sh
bash ./scripts/run-demo.sh
```

脚本会自动完成：

1. 生成 KGC 开发证书
2. 编译 Java 与 C++ 三个项目
3. 启动 KGC
4. 启动 Cloud Platform
5. 启动 Charging Pile
6. 输出三端日志并校验会话密钥

联调结束后，脚本会询问你是否关闭 `KGC` 和 `Cloud` 进程。

- 输入 `Y` 或直接回车：关闭进程
- 输入 `n`：保留进程，方便你继续手工测试

如果你想在非交互环境中控制这个行为，可以设置：

```bash
export AUTO_STOP_SERVICES=true
bash ./scripts/run-demo.sh
```

或：

```bash
export AUTO_STOP_SERVICES=false
bash ./scripts/run-demo.sh
```

## 环境要求

最低要求：

- Linux
- JDK 17 或更高，且包含 `javac` 与 `keytool`
- `bash`
- `cmake >= 3.16`
- `g++` 或 `clang++`，支持 C++17
- OpenSSL 运行库与开发头文件

Debian/Ubuntu 推荐安装：

```bash
sudo apt-get update
sudo apt-get install -y openjdk-17-jdk cmake build-essential libssl-dev
```

CentOS/RHEL/Rocky 推荐安装：

```bash
sudo dnf install -y java-17-openjdk-devel cmake gcc-c++ openssl-devel
```

## OpenSSL 路径兼容

C++ 项目的 [build.sh](/config/codex/clpkc-demo/modules/charging-pile-cpp/build.sh) 会优先自动探测：

- `/usr/include`
- `/usr/local/include`
- `/usr/include/node`

以及常见的 `libssl.so` / `libcrypto.so` 安装路径。

如果你的 Linux 发行版把 OpenSSL 装在自定义目录下，可以显式指定：

```bash
export OPENSSL_INCLUDE_DIR=/opt/openssl/include
export OPENSSL_SSL_LIBRARY=/opt/openssl/lib/libssl.so
export OPENSSL_CRYPTO_LIBRARY=/opt/openssl/lib/libcrypto.so
bash ./scripts/run-demo.sh
```

## 单独运行

只构建：

```bash
bash ./scripts/check-deps.sh
bash ./scripts/build-all.sh
```

如果你只想先确认当前机器缺什么依赖、版本是多少，可以单独执行：

```bash
bash ./scripts/check-deps.sh
```

这个脚本会输出：

- `java` / `javac` / `keytool` 版本
- `cmake` 和 C++ 编译器版本
- `openssl` 运行时版本
- `libssl`、`libcrypto`、OpenSSL 头文件的实际路径

手动启动顺序：

```bash
cd modules/kgc-java && bash ./gen-dev-cert.sh && bash ./run.sh
cd modules/cloud-platform-java && bash ./run.sh
cd modules/charging-pile-cpp && bash ./run.sh
```

## 目录说明

- [modules/kgc-java](/config/codex/clpkc-demo/modules/kgc-java): Java HTTPS KGC 服务
- [modules/cloud-platform-java](/config/codex/clpkc-demo/modules/cloud-platform-java): Java 云平台，含 TCP Server 与 HTTPS Client
- [modules/charging-pile-cpp](/config/codex/clpkc-demo/modules/charging-pile-cpp): C++ 充电桩客户端
- [scripts](/config/codex/clpkc-demo/scripts): 顶层一键脚本
- [docs](/config/codex/clpkc-demo/docs): 协议与部署说明
- [logs](/config/codex/clpkc-demo/logs): 运行日志目录

## 服务接口文档

### 1. KGC 服务接口

服务角色：

- 负责生成系统主密钥和主公钥
- 根据 `id + publicKey` 生成部分私钥

监听方式：

- HTTPS
- 默认地址：`https://localhost:8443`

接口一：查询系统参数

- 方法：`GET`
- 路径：`/api/system-params`

响应示例：

```json
{"curve":"secp256r1","masterPublicKey":"<hex>"}
```

接口二：申请部分私钥

- 方法：`POST`
- 路径：`/api/partial-key`
- 请求头：`Content-Type: application/json`

请求体示例：

```json
{"id":"pile-001","publicKey":"04..."}
```

响应体示例：

```json
{"curve":"secp256r1","partialPrivate":"<hex>","masterPublicKey":"<hex>"}
```

### 2. Cloud 服务接口

服务角色：

- 作为 HTTPS Client 调用 KGC
- 作为 TCP Socket Server 接受充电桩连接
- 完成 HMAC 认证、部分私钥转发、签名验签和会话密钥协商

监听方式：

- TCP Socket
- 默认地址：`127.0.0.1:9000`

Socket 报文采用：

- UTF-8 编码
- 一行一个 JSON

交互步骤一：挑战报文

Cloud -> Pile

```json
{"type":"challenge","nonce":"<hex>"}
```

交互步骤二：HMAC 认证报文

Pile -> Cloud

```json
{"type":"hmac","id":"pile-001","publicKey":"<hex>","mac":"<hex>"}
```

交互步骤三：认证通过报文

Cloud -> Pile

```json
{"type":"auth_ok","id":"cloud-001","publicKey":"<hex>"}
```

交互步骤四：部分私钥申请

Pile -> Cloud

```json
{"type":"partial_key_request","id":"pile-001","publicKey":"<hex>"}
```

交互步骤五：部分私钥返回

Cloud -> Pile

```json
{"type":"partial_key_response","curve":"secp256r1","partialPrivate":"<hex>","masterPublicKey":"<hex>"}
```

交互步骤六：发起带签名的 ECDH

Pile -> Cloud

```json
{"type":"ka_request","id":"pile-001","publicKey":"<hex>","ra":"<hex>","t":"<iso8601>","sig":"<hex>"}
```

交互步骤七：返回带签名的 ECDH 响应

Cloud -> Pile

```json
{"type":"ka_response","id":"cloud-001","publicKey":"<hex>","rb":"<hex>","t":"<iso8601>","sig":"<hex>"}
```

### 3. Charging Pile 客户端接口行为

服务角色：

- 作为 TCP Socket Client 连接 Cloud
- 完成 HMAC 应答
- 通过 Cloud 向 KGC 申请部分私钥
- 发起带签名的 ECDH 协商并验证 Cloud 签名

默认连接目标：

- `127.0.0.1:9000`

默认身份标识：

- `pile-001`

客户端会按固定顺序发送三类核心报文：

1. `hmac`
2. `partial_key_request`
3. `ka_request`

更多字段定义和签名输入规则见 [CLPKC_PROTOCOL.md](/config/codex/clpkc-demo/docs/CLPKC_PROTOCOL.md)。

## 产物与日志

执行 `scripts/run-demo.sh` 后会在 `logs/` 目录生成：

- `kgc.log`
- `cloud.log`
- `pile.log`

这些文件可用于排查联调问题。

建议按下面顺序阅读日志：

1. `logs/kgc.log`
   这里能看到 KGC 是否真的收到 HTTPS 请求，以及是否实际生成了部分私钥。
2. `logs/cloud.log`
   这里能看到 Cloud 是否真的收到了 TCP 连接、是否做了 HMAC 校验、是否通过 HTTPS 转发到 KGC、是否完成了验签和会话密钥派生。
3. `logs/pile.log`
   这里能看到充电桩是否真的连上了 Cloud、是否完成 HMAC 认证、是否收到了部分私钥、是否验过 Cloud 的签名、最终会话密钥是多少。

## 可移植性说明

为了方便在其他 Linux 环境直接运行，这个 Demo 避免依赖 IDE、容器和系统服务：

- Java 端使用 JDK 自带 `javac` 和 `com.sun.net.httpserver.HttpsServer`
- C++ 端使用 `cmake + OpenSSL`
- 各项目源码互相独立，不做源码级依赖
- 顶层脚本只依赖常见 POSIX 工具和 `bash`

如果你的环境禁止监听本地端口、禁止 TLS 自签证书、或缺少 OpenSSL 开发包，则需要先放开这些限制。
