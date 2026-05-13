# CL-PKC Demo

一个基于证书less公钥密码学（Certificateless Public Key Cryptography, CL-PKC）的三端联调 Demo。

## 项目结构

```
clpkc-demo/
├── modules/              # 三个独立模块
│   ├── kgc-java/         # Key Generation Center（Java HTTPS 服务）
│   ├── cloud-platform-java/  # Cloud Platform（Java TCP + HTTPS Client）
│   └── charging-pile-cpp/    # Charging Pile（C++ TCP Client）
├── scripts/              # 一键构建与联调脚本
├── docs/                 # 协议与说明文档
└── logs/                 # 运行日志
```

## 快速开始

在 Linux 环境下一键运行：

```bash
bash ./scripts/check-deps.sh
bash ./scripts/run-demo.sh
```

脚本会自动完成证书生成、编译、启动三端服务、输出日志并校验会话密钥。

## 核心技术栈

- **曲线**: secp256r1
- **哈希**: SHA-256
- **HMAC**: HmacSHA256
- **加密**: AES-256-GCM（ECIES 混合加密）
- **EC 点编码**: SEC1 未压缩格式

## 安全增强：ECIES 部分私钥加密

KGC 下发部分私钥 `d_i` 时，不再明文传输，而是使用申请方传入的静态公钥 `P_i` 进行 ECIES 加密：

1. KGC 生成临时密钥对 `(r, R = rG)`
2. 计算共享点 `S = r · P_i`
3. 派生 AES-256-GCM 密钥：`k = SHA-256(x(S))`
4. 加密 `d_i` 后返回：`R(65B) || IV(12B) || ciphertext(32B) || tag(16B)`

申请方（Cloud 或 Pile）使用自身私钥 `x_i` 解密：`S = x_i · R`。

## 文档

- [CLPKC_PROTOCOL.md](clpkc-demo/docs/CLPKC_PROTOCOL.md) — 协议与消息格式说明
- [README_CLPKC_DEMO.md](clpkc-demo/docs/README_CLPKC_DEMO.md) — 详细部署与运行指南

## 环境要求

- Linux
- JDK 17+
- CMake >= 3.16
- g++ / clang++ (C++17)
- OpenSSL 开发库

详见 [README_CLPKC_DEMO.md](clpkc-demo/docs/README_CLPKC_DEMO.md)。
