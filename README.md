# SoftSKF

SoftSKF 是一个基于本地文件的软件 SKF 库，导出 `include/skf/skf.h` 中的全部
79 个 `SKF_*` 接口。它用于开发、测试、离线软令牌和低安全等级部署。

## 1. 构建

依赖：

- OpenSSL 3.x（SM2/SM3/SM4、RSA、X.509、AES-GCM、HKDF、PBKDF2）
- SQLite 3.x 运行库（`libsqlite3.so.0`）
- pthread

`sqlite3.h` 已放在 `third_party/sqlite3/`（SQLite 公共领域许可），避免依赖
`libsqlite3-dev` 的头文件安装。如果发行版提供 `libsqlite3.so` 开发链接，也可以把
`SQLITE_LIB` 改成 `-lsqlite3`。

```bash
make
```

产物：

```text
libsoftskf.so
softskf-init
tests/softskf_test
tests/softskf_admin_test
```

## 2. 初始化软令牌

```bash
export SOFTSKF_HOME=/tmp/softskf
./softskf-init \
  --auth-key 0123456789abcdef \
  --app KEDA \
  --admin-pin 123456 \
  --user-pin 123456
```

这会创建：

```text
$SOFTSKF_HOME/softskf0/token.db
$SOFTSKF_HOME/softskf0/token.key
```

`token.key` 是本地存储密钥，权限为 `0600`。设备认证密钥、应用 PIN 包装后的
应用密钥和文件/私钥密文都在 `token.db` 中。

生产环境不要使用示例里的 PIN，也不要提交真实设备认证密钥。

## 3. 测试

```bash
make test
```

覆盖：

- 设备枚举、连接、设备信息、标签、锁、热插拔取消
- 设备认证、修改设备认证密钥
- 应用创建/打开/删除、PIN 校验/修改/解锁/重试锁定
- 文件创建/写/读/删除
- SM4 ECB/CBC/CFB128/OFB、CBC-MAC、SM3 摘要、随机数
- SM2 密钥生成、签名/验签、加密/解密、会话密钥、密钥协商
- RSA 密钥生成、签名/验签、会话密钥、外部 RSA 运算
- ECC/RSA 密钥导入、X.509 证书导入/导出
- `SM1`/`SSF33` 返回 `SAR_NOTSUPPORTYETERR`

`make check` 会额外运行仓库内的 `tests/skf_all` 和 `tests/skf_imports_test`：

```bash
make check
```

## 4. 与硬件 UKey 交叉验证

`tests/hw_cross_test.c` 会同时加载厂商硬件库和 `libsoftskf.so`，对可确定性比较的
接口逐项比对；签名/加密类接口做双向交叉验证（硬件结果由软库验证，软库结果由硬件
验证）。

硬件库通过 `SG_IO` 访问 `/dev/sdd`，需要 root 或 `CAP_SYS_RAWIO`：

```bash
# 1. 初始化一个和硬件 KEDA 同 PIN 的软令牌
export SOFTSKF_HOME=/tmp/softskf-xval
./softskf-init --auth-key 0123456789abcdef \
  --app KEDA --admin-pin 123456 --user-pin 123456

# 2. 构建并运行交叉验证（需要 root）
make hw-cross
sudo env SOFTSKF_HOME=/tmp/softskf-xval ./tests/hw_cross_test \
  /path/to/vendor/libskf.so ./libsoftskf.so
```

也可以只设置厂商库路径：

```bash
sudo env SOFTSKF_HOME=/tmp/softskf-xval \
  VENDOR_SKF_LIB=/path/to/vendor/libskf.so ./tests/hw_cross_test
```

在本机 CCM3302 + KEDA/123456 上的结果：

```text
Summary: PASS=26 FAIL=0 DIFF=1 NA=1
```

- PASS：SM4-ECB/CBC/OFB 密文逐字节一致，且双向 cross-decrypt 成功；
- PASS：SM4 CBC-MAC 输出一致（厂商 MAC 需要 `PaddingType=1`）；
- PASS：SM3/SHA1/SHA256 摘要一致；
- PASS：SKF_EnumApplication / GetPINInfo / VerifyPIN、设备信息、随机数、LockDev/UnlockDev；
- PASS：硬件 SM2 签名 -> 软库验证；软库 SM2 签名 -> 硬件验证；
- PASS：ExtECCSign 双向验证；ExtECCEncrypt 双向加解密；
- PASS：软库 RSA 签名 -> 硬件 RSA 验证；
- DIFF：SM1 硬件支持，软库按评审决定返回 `SAR_NOTSUPPORTYETERR`（预期差异）；
- NA：SM4-CFB128 厂商库返回 `SAR_NOTSUPPORTYETERR`，无法比较。

硬件 KEDA 容器在本机 `SKF_GetContainerType` 返回 2，但
`SKF_ExportPublicKey` 返回 256 位 ECC 公钥；交叉验证程序以公钥 blob 的实际
类型为准，不依赖 `GetContainerType` 的厂商私有语义。

## 5. 存储与密钥分层

每个软令牌是一个目录：

```text
$SOFTSKF_HOME/softskf0/
  token.db      SQLite，WAL 模式
  token.key     32 字节本地存储密钥，0600
```

密钥层次：

- `token.key` 包装设备认证密钥 `DAK`；
- 设备认证通过后，`DAK` 可用于设备管理；
- 每个应用生成随机 `AK`，分别用 admin PIN 和 user PIN 派生的
  PBKDF2-HMAC-SHA256 密钥包装；
- 文件内容和容器私钥用 `HKDF(AK, "file"/"container-priv", id)` 派生的
  AES-256-GCM 密钥加密。

这样：

- 只有 `token.db` + `token.key`，不知道应用 PIN，不能解出应用私钥；
- 只有应用 PIN，没有 `token.key`，可以正常使用该应用；
- 复制整个令牌目录到别的机器仍然可用（同一 PIN），但不能伪造签名。

## 6. 明确不支持的能力

- `SM1`/`SSF33`：规范未公开，直接返回 `SAR_NOTSUPPORTYETERR`，不做 SM4 映射。
- `SKF_Transmit`：不实现厂商私有 APDU，返回 `SAR_NOTSUPPORTYETERR`。
- 硬件级密钥保护：软 SKF 不能防本机 root/调试器读取内存或替换 `libsoftskf.so`。
- 可信时钟、单调计数器、防克隆、防物理拆解。
- Windows：当前版本只构建 Linux；SQLite/OpenSSL 可跨平台，事件/锁需要适配。

## 7. 兼容性说明

- SM4 CFB 当前支持 CFB128；`FeedBitLen` 为 1/8 时返回
  `SAR_NOTSUPPORTYETERR`，不会静默按 CFB128 处理。
- `SKF_EncryptUpdate`/`SKF_DecryptUpdate` 会缓冲输入，直到
  `SKF_EncryptFinal`/`SKF_DecryptFinal` 才输出；这与现有硬件库的行为一致。
- `SKF_EncryptFinal` 在 `PaddingType=0` 且输入不是 16 字节整数倍时，会补零到
  块边界（与现有 native 实现一致）。
- ECC 签名按 `e=digest` 处理，签名 blob 的 `r`/`s` 右对齐在 64 字节字段中。
- RSA 签名使用 PKCS#1 v1.5 + 原始 32 字节 digest（不加 DigestInfo）。
- ECC `ENVELOPEDKEYBLOB` 支持 native 扩展：`ECCCipherBlob.CipherLen=0` 时，
  `cbEncryptedPriKey[0..31]` 直接作为 SM2 私钥标量。
- RSA `SKF_ImportRSAKeyPair` 支持直接 `RSAPRIVATEKEYBLOB`、DER 私钥，以及
  容器已有 RSA 私钥时的标准信封导入。

## 8. 文件布局

```text
softskf/
  Makefile
  README.md
  SOFT_SKF_DESIGN.md
  HW_CROSS_REPORT.md
  include/
    sgd.h
    skf/skf.h
  src/
    softskf.c           # 全部 SKF API 与存储/密码实现
    softskf_init.c      # 初始化 CLI
    softskf_init.h
  tests/
    softskf_test.c
    softskf_admin_test.c
    skf_all.c
    skf_imports_test.c
    hw_cross_test.c
  third_party/sqlite3/
    sqlite3.h
```
