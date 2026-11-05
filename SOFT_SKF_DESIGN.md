# SoftSKF 设计文档（评审稿）

> 目标：实现一个不依赖硬件、基于本地文件的软件 SKF 库，导出与 `include/skf/skf.h` 一致的 ABI，供开发、测试、离线部署和软 License 场景使用。
>
> 本文是设计文档。首版实现位于本目录，构建和测试说明见 `README.md`；文末保留评审决策点和实现状态。

---

## 1. 目标与范围

### 1.1 目标

- 实现 `skf.h` 中全部 79 个 `SKF_*` 接口（`SKF_ECCDecrypt` 按条件编译导出）。
- 设备、应用、PIN、文件、容器、证书、ECC、RSA、对称、MAC、摘要、随机数、事件、锁全部可用。
- 数据持久化在本地目录/本地数据库，进程重启后状态保持。
- 同一套代码可在 Linux x86-64 / arm64 上编译，后续可扩展到 Windows。
- 尽可能复用成熟开源密码库，不自己实现密码算法。
- 提供与硬件 UKey 接近的 API 语义，便于应用在“软令牌/硬令牌”之间切换。

### 1.2 非目标

- **不提供硬件级密钥保护**。软件 SKF 无法阻止 root/管理员/调试器读取进程内存或替换库文件。
- **不实现 SM1/SSF33 的密码算法**。两者规范未公开，相关算法标识一律返回 `SAR_NOTSUPPORTYETERR`；不做 SM4 映射，也不加载外部 provider。
- 不提供可信时钟、单调计数器、防物理拆解、防克隆。
- 不实现 `SKF_Transmit` 的厂商私有 APDU；返回 `SAR_NOTSUPPORTYETERR`，与厂商库行为一致。
- 不承诺与某一家硬件 UKey 的私有文件布局/固件行为完全一致；只保证 SKF API 语义和常见调用习惯。

### 1.3 安全边界

软件 SKF 的安全目标应明确为：

- 防止**离线复制文件**后直接读取私钥；
- 防止**直接篡改**数据库/文件后伪造对象；
- 防止**错误 PIN/设备认证**无限重试；
- 防止**普通用户**越权访问其他应用/容器。

不能防止：

- 本机 root/管理员读取进程内存、ptrace、替换 `libsoftskf.so`；
- 攻击者拿到设备认证密钥和 PIN 后离线解密；
- 回滚整个令牌目录到旧备份；
- 客户端被完全 patch。

> 如果目标是生产级 License 防伪，建议仍然使用硬件 UKey；软 SKF 更适合开发、测试、离线备份和低安全等级场景。

---

## 2. 总体架构

```text
+------------------------------------------------------+
|  应用 / skf_all / skf_imports_test                    |
+---------------------------+--------------------------+
                            | SKF ABI
+---------------------------v--------------------------+
|  libsoftskf.so                                       |
|  ├─ device.c      设备枚举/连接/信息/标签/事件/锁      |
|  ├─ auth.c        设备认证/设备密钥/重试锁             |
|  ├─ app.c         应用/PIN/安全状态                    |
|  ├─ file.c        应用文件对象                         |
|  ├─ container.c   容器/密钥/证书                       |
|  ├─ ecc.c         SM2 密钥/签名/加密/ECDH/信封         |
|  ├─ rsa.c         RSA 密钥/签名/加密/信封              |
|  ├─ sym.c         SM4/ZUC 句柄与流式加解密             |
|  ├─ mac.c         CBC-MAC/CMAC                         |
|  ├─ hash.c        SM3/SHA1/SHA256                      |
|  ├─ store.c       SQLite/文件存储、事务、加密           |
|  ├─ kdf.c         HKDF/PBKDF2/Argon2id                 |
|  └─ util.c        句柄、错误码、内存清零、路径安全       |
+---------------------------+--------------------------+
                            |
+---------------------------v--------------------------+
|  本地令牌目录                                             |
|  ${SOFTSKF_HOME:-~/.softskf}/softskf0/token.db           |
|  ${SOFTSKF_HOME}/softskf0/blobs/...                       |
+------------------------------------------------------+
```

### 2.1 设备模型

- 一个软令牌 = 一个本地目录，例如 `~/.softskf/softskf0`。
- `SKF_EnumDev` 扫描 `SOFTSKF_HOME` 下的子目录，读取 `token.meta` 或 `token.db`，返回 `softskf0`、`softskf1` …。
- `SKF_ConnectDev("softskf0")` 打开对应目录。
- `SKF_GetDevState`：目录存在且数据库可读返回 1，否则 0。
- 支持环境变量 `SOFTSKF_HOME` 指向测试/部署目录。

### 2.2 存储引擎选择

**推荐：每个令牌一个 SQLite 数据库 `token.db`，大文件内容可放 BLOB 或外置 `blobs/`。**

理由：

- 事务/回滚/崩溃恢复成熟，避免自己实现多文件原子更新；
- WAL 模式支持多进程读写；
- 单文件便于备份/复制/测试；
- 文件、容器、PIN、密钥都是结构化对象，关系模型更自然；
- SQLite 是 Public Domain，稳定、依赖小。

如果不希望引入 SQLite，可退化为“目录 + TLV 文件 + `flock` + `rename` 原子写”，但实现复杂度和数据损坏风险更高。本文按 SQLite 方案设计。

---

## 3. 本地存储格式

### 3.1 目录结构

```text
${SOFTSKF_HOME}/
  softskf0/
    token.db          # SQLite，WAL 模式
    token.lock        # flock 锁文件
    blobs/            # 可选：大文件内容
      00000001.blob
```

### 3.2 数据库表（建议）

```sql
-- 设备级
CREATE TABLE token (
  id                 INTEGER PRIMARY KEY,
  format_version     INTEGER NOT NULL,
  name               TEXT NOT NULL UNIQUE,     -- softskf0
  serial             TEXT NOT NULL UNIQUE,
  label              TEXT NOT NULL,
  created_at         INTEGER NOT NULL,
  total_space        INTEGER NOT NULL,
  free_space         INTEGER NOT NULL,         -- 或运行时计算
  auth_salt          BLOB NOT NULL,
  auth_wrapped_mk    BLOB NOT NULL,            -- AEAD(MK, KEK(device auth key))
  auth_nonce         BLOB NOT NULL,
  auth_tag           BLOB NOT NULL,
  auth_retry         INTEGER NOT NULL DEFAULT 0,
  auth_max_retry     INTEGER NOT NULL DEFAULT 15,
  auth_locked        INTEGER NOT NULL DEFAULT 0,
  meta_mac           BLOB NOT NULL
);

-- 应用
CREATE TABLE app (
  id                 INTEGER PRIMARY KEY,
  name               TEXT NOT NULL,
  app_id             INTEGER NOT NULL,
  admin_verifier     BLOB NOT NULL,            -- HMAC(K_admin, "verify")
  admin_salt         BLOB NOT NULL,
  admin_kdf_params   BLOB NOT NULL,
  admin_wrapped_ak   BLOB NOT NULL,            -- AEAD(AK, K_admin)
  admin_nonce        BLOB NOT NULL,
  admin_tag          BLOB NOT NULL,
  admin_retry        INTEGER NOT NULL DEFAULT 0,
  admin_locked       INTEGER NOT NULL DEFAULT 0,
  user_verifier      BLOB NOT NULL,
  user_salt          BLOB NOT NULL,
  user_kdf_params    BLOB NOT NULL,
  user_wrapped_ak    BLOB NOT NULL,
  user_nonce         BLOB NOT NULL,
  user_tag           BLOB NOT NULL,
  user_retry         INTEGER NOT NULL DEFAULT 0,
  user_locked        INTEGER NOT NULL DEFAULT 0,
  default_pin        INTEGER NOT NULL DEFAULT 1,
  rights             INTEGER NOT NULL,
  created_at         INTEGER NOT NULL,
  UNIQUE(id, name)
);

-- 应用文件
CREATE TABLE file (
  id                 INTEGER PRIMARY KEY,
  app_id             INTEGER NOT NULL REFERENCES app(id) ON DELETE CASCADE,
  name               TEXT NOT NULL,
  size               INTEGER NOT NULL,
  read_rights        INTEGER NOT NULL,
  write_rights       INTEGER NOT NULL,
  content_nonce      BLOB,
  content_tag        BLOB,
  content            BLOB,                     -- AEAD(AK) 后的密文
  created_at         INTEGER NOT NULL,
  modified_at        INTEGER NOT NULL,
  UNIQUE(app_id, name)
);

-- 容器
CREATE TABLE container (
  id                 INTEGER PRIMARY KEY,
  app_id             INTEGER NOT NULL REFERENCES app(id) ON DELETE CASCADE,
  name               TEXT NOT NULL,
  ctn_id             INTEGER NOT NULL,
  type               INTEGER NOT NULL,         -- 1=ECC, 2=RSA, 0=未生成
  alg_id             INTEGER NOT NULL,
  bits               INTEGER NOT NULL,
  pub_blob           BLOB,                     -- 公开密钥 blob
  priv_nonce         BLOB,
  priv_tag           BLOB,
  priv_blob          BLOB,                     -- AEAD(AK) 后的私钥
  sign_cert          BLOB,                     -- 可选，DER
  enc_cert           BLOB,
  created_at         INTEGER NOT NULL,
  UNIQUE(app_id, name)
);
```

### 3.3 加密与完整性

#### 设备主密钥 MK

- 初始化时生成 32 字节随机 `MK`。
- 用设备认证密钥 `DAK` 派生 KEK：

```text
KEK = HKDF-SHA256(DAK, salt, info="SoftSKF device MK v1")
auth_wrapped_mk = AES-256-GCM(KEK, nonce, MK, AAD="token")
```

- `SKF_DevAuth` 用 DAK 解包 MK；失败返回错误并增加重试计数。
- `SKF_ChangeDevAuthKey` 要求已认证，重新用新 DAK 包装 MK；新密钥长度 1..16，**拒绝 0 长度**。
- MK 只用于设备级管理对象，不用于应用私钥。

#### 应用密钥 AK

- 每个应用生成 32 字节随机 `AK`。
- `AK` 分别用 admin PIN 和 user PIN 派生密钥包装两份：

```text
K_pin = Argon2id(PIN, salt, params)       // 推荐 libsodium
  或 PBKDF2-HMAC-SHA256(PIN, salt, 600000)
pin_verifier = HMAC-SHA256(K_pin, "SoftSKF PIN verify")
wrapped_ak   = AES-256-GCM(HKDF(K_pin, "wrap"), nonce, AK, AAD=app_id)
```

- 用户登录只需要解包 user 副本；管理员登录解包 admin 副本。
- `SKF_UnblockPIN` 用 admin 副本解出 AK，再用新 user PIN 重新包装 user 副本，**不需要重新加密容器私钥**。
- 应用私钥、文件内容用 `AK` 派生的对象密钥加密：

```text
object_key = HKDF-SHA256(AK, info="object" || object_type || object_id)
ciphertext = AES-256-GCM(object_key, nonce, plaintext, AAD=object_id)
```

- 这样应用私钥/文件在未登录时是密文；设备认证密钥不能解密应用数据（除非同时知道应用 PIN）。
- 应用 PIN 错误只影响该应用；设备认证错误只影响设备级管理。

#### 公开元数据

- 标签、应用名、容器名、文件大小等可以明文存储，便于 `Enum*` 在未登录时使用。
- 关键字段的完整性由 AEAD 标签/数据库事务保证；公开字段被篡改至多是 DoS，不泄露私钥。
- 可选：对 token/app 关键行做 HMAC-SHA256（密钥来自 MK/AK），但未认证时无法验证，所以不把它作为唯一防线。

#### 内存安全

- 所有 PIN、DAK、MK、AK、私钥使用后 `OPENSSL_cleanse`/`explicit_bzero`。
- 可选 `mlock` 锁定敏感内存；`prctl(PR_SET_DUMPABLE, 0)` 降低 core dump 风险。
- 不在日志中输出 PIN/密钥/明文。

---

## 4. PIN、设备认证与锁定

### 4.1 设备认证

```text
SKF_DevAuth(dev, key16, 16)
  - 长度必须 16
  - 尝试解包 MK
  - 成功：dev_authed=1, 清零 auth_retry
  - 失败：auth_retry++，返回 SAR_PIN_INCORRECT / SAR_UNKNOWNERR
  - auth_retry >= max：auth_locked=1，返回 SAR_PIN_LOCKED
```

为兼容原厂库，`SKF_DevAuth` 在锁定状态优先返回 `SAR_UNKNOWNERR`；native 可选 `SAR_PIN_LOCKED`。设计默认按原厂映射，文档中注明。

### 4.2 应用 PIN

- `SKF_VerifyPIN(app, USER_TYPE/ADMIN_TYPE, pin, retry)`：
  - 读取对应 verifier/salt，派生 K_pin，常量时间比较；
  - 成功：解包 AK，设置 user_logged/admin_logged；
  - 失败：retry++，返回 `SAR_PIN_INCORRECT` 并写回剩余次数；
  - 达到上限：`SAR_PIN_LOCKED`。
- `SKF_ChangePIN(app, type, oldpin, newpin, retry)`：
  - 解包对应 AK 副本；
  - 新 PIN 生成新 salt/verifier，重新包装对应 AK 副本；
  - 事务提交；旧 PIN 校验失败按重试处理。
- `SKF_UnblockPIN(app, ADMIN_TYPE, adminpin, newuserpin, retry)`：
  - 管理员 PIN 解包 admin AK；
  - 用新 user PIN 重新包装 user AK；
  - 清零 user_retry/user_locked；
  - 管理员 PIN 失败按 admin 重试处理。
- `SKF_GetPINInfo`：返回 max=6（可配置）、remain、default 标志。
- `SKF_ClearSecureState`：清零 user_logged/admin_logged/AK，不重置 PIN 重试计数、不解设备锁。

### 4.3 重试计数与软件限制

- 重试计数存数据库；攻击者如果能直接改数据库，可以重置计数。软件 SKF 无法防住本机 root。
- 可选：把计数放到 OS keyring/TPM；默认不依赖。
- 设备认证锁定后，提供**离线维护 CLI** `softskf-admin reset-auth`（需要文件系统权限）作为软令牌的恢复手段；该命令不属于 SKF API，文档中说明其风险。

---

## 5. 密码算法与开源库选型

### 5.1 推荐依赖

| 库 | 版本 | License | 用途 |
| --- | --- | --- | --- |
| OpenSSL | 3.0+ | Apache-2.0 | SM2/SM3/SM4、RSA、X.509、AES-GCM、HKDF、PBKDF2、随机数 |
| SQLite | 3.40+ | Public Domain | 本地事务存储 |
| libsodium（可选） | 1.0.19+ | ISC | Argon2id PIN KDF |
| GmSSL（可选） | 3.2+ | Apache-2.0 | ZUC/ZUC-256、SM9（如需要） |

说明：

- OpenSSL 3.x 原生支持 SM2/SM3/SM4，作为主密码库。
- GmSSL 3.2 支持 SM2/SM3/SM4/SM9/ZUC，但 **SM1/SSF33 没有公开规范**，GmSSL 不包含其软件实现。因此软 SKF 不实现 SM1/SSF33，相关算法标识直接返回 `SAR_NOTSUPPORTYETERR`。
- 不做 SM1→SM4 映射，也不加载外部 SM1 provider；避免“调用成功但密文错误”或引入未授权代码。
- libsodium 只用于 Argon2id；如果不希望增加依赖，可用 OpenSSL PBKDF2-HMAC-SHA256（60 万次以上）。

### 5.2 算法支持矩阵

| SKF 算法 | 支持 | 实现 |
| --- | --- | --- |
| `SGD_SM4_ECB/CBC/CFB/OFB` | 是 | OpenSSL EVP SM4 |
| `SGD_SM4_MAC` | 是 | CBC-MAC（默认），可选 CMAC |
| `SGD_SM3` | 是 | OpenSSL SM3 |
| `SGD_SHA1` / `SGD_SHA256` | 是 | OpenSSL |
| `SGD_SM2` / `SGD_SM2_1/2/3` | 是 | OpenSSL EC + SM3；签名按 e=digest 兼容硬件 |
| `SGD_RSA` | 是 | OpenSSL RSA；1024/2048/3072/4096 |
| `SGD_SM1_*` | 否 | 返回 `SAR_NOTSUPPORTYETERR`；不做 SM4 映射 |
| `SGD_SSF33_*` | 否 | 返回 `SAR_NOTSUPPORTYETERR` |
| `SGD_ZUC_EEA3/EIA3` | 可选 | 编译时启用 GmSSL；默认 `SAR_NOTSUPPORTYETERR` |
| 随机数 | 是 | `getrandom()` + OpenSSL `RAND_bytes` |
| X.509 | 是 | OpenSSL X509 |

### 5.3 SM1 与 SSF33 的处理

**结论：本期不实现 SM1 和 SSF33，相关算法标识直接返回 `SAR_NOTSUPPORTYETERR`。**

理由：

- SM1/SSF33 的算法规范未公开，公开开源库没有合法、可验证的软件实现；
- 不做 SM1→SM4 映射：映射会“调用成功但密文错误”，比明确不支持更危险；
- 不引入外部 SM1 provider：本期不增加插件加载、信任链和授权审计的复杂度；
- 不把来源不明的 GitHub 代码打包进产品。

行为约定：

| 接口 | 行为 |
| --- | --- |
| `SKF_SetSymmKey(..., SGD_SM1_*, ...)` | 返回 `SAR_NOTSUPPORTYETERR`，不创建句柄 |
| `SKF_SetSymmKey(..., SGD_SSF33_*, ...)` | 返回 `SAR_NOTSUPPORTYETERR`，不创建句柄 |
| `SKF_ImportSessionKey(..., SGD_SM1_*, ...)` | 返回 `SAR_NOTSUPPORTYETERR` |
| `SKF_GetDevInfo` | `AlgSymCap` 不包含 SM1/SSF33 位；`DevAuthAlgId` 固定为 `SGD_SM4_ECB` |
| `SKF_EncryptInit`/`SKF_MacInit` | 不会收到 SM1 句柄，因为 `SKF_SetSymmKey` 已拒绝 |

测试要求：

- `skf_all` 将 `SKF_SetSymmKey(SGD_SM1_ECB)` 标记为 `EXPECT_UNSUPPORTED`，返回 `SAR_NOTSUPPORTYETERR` 即通过；
- 不允许出现“SM1 调用成功”或“SM1 结果与 SM4 相同”的测试；
- 如果未来需要 SM1，必须单独评审，引入有明确授权的实现，并补充官方测试向量；本期不预留 provider 框架。

---

## 6. SKF 语义细节

### 6.1 设备

- `SKF_EnumDev` 返回 `softskf0\0softskf1\0\0`，`*size` 包含末尾额外 NUL，与原厂列表习惯一致。
- `SKF_GetDevInfo`：
  - `Manufacturer="SoftSKF"`, `Issuer="SoftSKF"`, `Label` 来自 token；
  - `SerialNumber` 16 位十六进制；
  - `Version`/`HWVersion`/`FirmwareVersion` 固定或配置；
  - `AlgSymCap`/`AlgAsymCap`/`AlgHashCap` 反映实际支持；
  - `DevAuthAlgId=SGD_SM4_ECB`；不使用 SM1 做设备认证；
  - `TotalSpace`/`FreeSpace` 按配额计算；
  - `MaxBufferSize` 可配置（默认 64 KiB）。
- `SKF_SetLabel`：长度 ≤31，事务更新，返回 `SAR_OK`。
- `SKF_LockDev`：进程内 `pthread_mutex_timedlock`；`UnlockDev` 释放。
- `SKF_WaitForDevEvent`：Linux 用 inotify 监听 `SOFTSKF_HOME` 子目录创建/删除；没有 inotify 时 50 ms 轮询；`Cancel` 置位并返回 `SAR_NOT_EVENTERR`。
- `SKF_Transmit`：返回 `SAR_NOTSUPPORTYETERR`。

### 6.2 应用/PIN

- `SKF_CreateApplication`/`SKF_DeleteApplication` 需要 `dev_authed`。
- `SKF_OpenApplication` 只需要应用存在，不需要 PIN。
- `SKF_EnumApplication` 返回应用名列表（以 `\0` 分隔，末尾额外 NUL）。
- `SKF_GetPINInfo` 不需要登录，返回 max/remain/default。
- `SKF_VerifyPIN` 成功后才允许私钥操作、文件内容读写、容器密钥操作。
- `SKF_ChangePIN`/`SKF_UnblockPIN` 见第 4 节。
- `SKF_ClearSecureState` 清登录态。

### 6.3 文件

- `SKF_CreateFile(app, name, size, read_rights, write_rights)`：需要 user 或 admin 登录；名称 ≤31；大小 ≤配额；`size` 是固定上限。
- `SKF_WriteFile(app, name, offset, data, len)`：`offset+len <= size`，否则 `SAR_INDATAERR`/`SAR_WRITEFILEERR`；内容 AEAD 加密。
- `SKF_ReadFile`：按 offset/len 返回；未登录返回 `SAR_USER_NOT_LOGGED_IN`。
- `SKF_GetFileInfo`/`SKF_EnumFiles`：应用打开即可，名称/大小公开；内容不返回。
- `SKF_DeleteFile`：需要写权限。
- 文件内容只有 `AK` 可解；未登录时数据库里是密文。

### 6.4 容器

- `SKF_CreateContainer`：需要 user 登录；创建空容器（`type=0`）。
- `SKF_GenECCKeyPair`：SM2，生成私钥并用 AK 加密；设置 `type=1`。
- `SKF_GenRSAKeyPair`：RSA，支持 1024/2048/3072/4096；设置 `type=2`。
- `SKF_OpenContainer`/`CloseContainer`/`EnumContainer`/`DeleteContainer`/`GetContainerType`。
- 容器数量上限默认 16（可配置），超过返回 `SAR_REACH_MAX_CONTAINER_COUNT`。
- `SKF_ExportPublicKey`：ECC 返回 `ECCPUBLICKEYBLOB`（BitLen=256，X/Y 右对齐 64 字节字段）；RSA 返回 `RSAPUBLICKEYBLOB`。
- `SKF_ExportCertificate`/`ImportCertificate`：证书 DER 存 `container.sign_cert`/`enc_cert`；导入时解析 X.509，并校验公钥与容器密钥匹配；失败返回 `SAR_OBJERR`。

### 6.5 ECC

- `SKF_ECCSignData`：输入 32 字节 digest；按 **e=digest** 做 SM2 签名（与硬件 `80 56 01` 行为一致），输出 `ECCSIGNATUREBLOB`（r/s 右对齐在 64 字节字段）。
- `SKF_ECCVerify`：按 e=digest 验证。
- `SKF_ExtECCSign`/`ExtECCVerify`：外部私钥/公钥 blob，软件 SM2。
- `SKF_ExtECCEncrypt`：标准 SM2 加密，填充 `ECCCIPHERBLOB`：
  - `XCoordinate+32`/`YCoordinate+32` = C1；
  - `Cipher` = C2；
  - `HASH` = C3；
  - `CipherLen` = 明文长度。
- `SKF_ExtECCDecrypt`：SM2 解密，校验 C3。
- `SKF_ECCExportSessionKey`：生成 16 字节会话密钥，用 `SKF_ExtECCEncrypt` 封装，返回会话密钥句柄。
- `SKF_GenerateAgreementDataWithECC`/`AndKey`/`GenerateKeyWithECC`：SM2 ECDH + SM3 KDF；需要已导入/生成的 ECC 私钥容器。
- `SKF_ImportECCKeyPair`：
  - 标准 `ENVELOPEDKEYBLOB`：容器私钥解 SM2 会话密钥，再用会话密钥解 `cbEncryptedPriKey`；
  - 软扩展：`ECCCipherBlob.CipherLen=0` 时，`cbEncryptedPriKey[0..31]` 直接作为私钥标量（仅 native/soft 兼容，文档标注）。

### 6.6 RSA

- `SKF_GenRSAKeyPair`：支持 1024/2048/3072/4096；私钥 AK 加密；公钥 blob。
- `SKF_RSASignData`：按硬件语义做 **PKCS#1 v1.5 type 1 填充 + 原始 digest**（不使用 DigestInfo），输出模长字节。
- `SKF_RSAVerify`：公钥解密 + PKCS#1 type 1 检查 + 与 digest 比较。
- `SKF_RSAExportSessionKey`：生成 16 字节会话密钥，PKCS#1 v1.5 加密到 RSA 公钥，返回句柄。
- `SKF_ImportRSAKeyPair`：支持标准 wrapped-key 和软扩展明文 `RSAPRIVATEKEYBLOB`。
- `SKF_GenExtRSAKey`/`ExtRSAPubKeyOperation`/`ExtRSAPriKeyOperation`：软件 RSA，外部 key blob。

### 6.7 对称/MAC/摘要

- `SKF_SetSymmKey`：接受 SM4 16 字节；`SGD_SM1_*`/`SGD_SSF33_*` 返回 `SAR_NOTSUPPORTYETERR`，不创建句柄。
- `SKF_EncryptInit`：解析 `BLOCKCIPHERPARAM`：
  - ECB 忽略 IV；
  - CBC/CFB/OFB 使用 IV；
  - CFB 支持 CFB128（默认）；`FeedBitLen=1/8` 首版返回 `SAR_NOTSUPPORTYETERR`，不会静默按 CFB128 处理；
  - `PaddingType`：0=无填充，1=PKCS#7；其他返回 `SAR_INVALIDPARAMERR`。
- `SKF_Encrypt`/`Decrypt` 一次性；`Update`/`Final` 流式；最终块做填充/去填充。
- `SKF_MacInit`/`Mac`/`MacUpdate`/`MacFinal`：默认 SM4 CBC-MAC（零 IV），输出 16 字节；可按 `pulMacLen` 截断。MAC 算法语义需与目标应用确认；可配置 CMAC。
- `SKF_DigestInit`/`Digest`/`Update`/`Final`：SM3/SHA1/SHA256。
- `SKF_CloseHandle`：按句柄类型清理；重复关闭返回 `SAR_INVALIDHANDLEERR`。

### 6.8 随机数

- `SKF_GenRandom`：优先 `getrandom()`，失败回退 `RAND_bytes`；长度 0 返回 `SAR_OK`；失败 `SAR_GENRANDERR`。

---

## 7. 接口覆盖清单

> 全部接口均导出；SM1/SSF33 不在支持范围，返回 `SAR_NOTSUPPORTYETERR`，不是缺函数。

| 组 | 接口 | 说明 |
| --- | --- | --- |
| 设备 | `SKF_EnumDev`, `SKF_ConnectDev`, `SKF_DisConnectDev`, `SKF_GetDevState`, `SKF_GetDevInfo`, `SKF_GenRandom`, `SKF_SetLabel`, `SKF_LockDev`, `SKF_UnlockDev`, `SKF_WaitForDevEvent`, `SKF_CancelWaitForDevEvent`, `SKF_Transmit` | 全部实现；`Transmit` 返回不支持 |
| 设备认证 | `SKF_DevAuth`, `SKF_ChangeDevAuthKey` | 实现；0 长度密钥拒绝 |
| 应用 | `SKF_EnumApplication`, `SKF_OpenApplication`, `SKF_CloseApplication`, `SKF_CreateApplication`, `SKF_DeleteApplication` | 实现；创建/删除需 DevAuth |
| PIN | `SKF_VerifyPIN`, `SKF_ChangePIN`, `SKF_UnblockPIN`, `SKF_GetPINInfo`, `SKF_ClearSecureState` | 实现；重试/锁定 |
| 文件 | `SKF_EnumFiles`, `SKF_CreateFile`, `SKF_DeleteFile`, `SKF_ReadFile`, `SKF_WriteFile`, `SKF_GetFileInfo` | 实现；内容 AEAD |
| 容器 | `SKF_EnumContainer`, `SKF_OpenContainer`, `SKF_CloseContainer`, `SKF_CreateContainer`, `SKF_DeleteContainer`, `SKF_GetContainerType` | 实现 |
| 证书 | `SKF_ImportCertificate`, `SKF_ExportCertificate` | 实现；X.509 校验 |
| ECC | `SKF_GenECCKeyPair`, `SKF_ExportPublicKey`, `SKF_ECCSignData`, `SKF_ECCVerify`, `SKF_ECCExportSessionKey`, `SKF_ECCDecrypt`（条件）, `SKF_ExtECCEncrypt`, `SKF_ExtECCDecrypt`, `SKF_ExtECCSign`, `SKF_ExtECCVerify`, `SKF_GenerateAgreementDataWithECC`, `SKF_GenerateAgreementDataAndKeyWithECC`, `SKF_GenerateKeyWithECC` | 实现；SM2 |
| RSA | `SKF_GenRSAKeyPair`, `SKF_RSASignData`, `SKF_RSAVerify`, `SKF_RSAExportSessionKey`, `SKF_ImportRSAKeyPair`, `SKF_GenExtRSAKey`, `SKF_ExtRSAPubKeyOperation`, `SKF_ExtRSAPriKeyOperation` | 实现 |
| 导入 | `SKF_ImportECCKeyPair`, `SKF_ImportRSAKeyPair`, `SKF_ImportSessionKey` | 实现；标准信封 + 软扩展 |
| 对称 | `SKF_SetSymmKey`, `SKF_EncryptInit`, `SKF_Encrypt`, `SKF_EncryptUpdate`, `SKF_EncryptFinal`, `SKF_DecryptInit`, `SKF_Decrypt`, `SKF_DecryptUpdate`, `SKF_DecryptFinal` | 实现；SM4；SM1/SSF33 返回不支持 |
| MAC | `SKF_MacInit`, `SKF_Mac`, `SKF_MacUpdate`, `SKF_MacFinal` | 实现 |
| 摘要 | `SKF_DigestInit`, `SKF_Digest`, `SKF_DigestUpdate`, `SKF_DigestFinal` | 实现 |
| 句柄 | `SKF_CloseHandle` | 实现 |

---

## 8. 并发、原子性与错误处理

### 8.1 并发

- 进程内：每个 `DEV_CTX` 一个 `pthread_mutex_t`，`SKF_LockDev` 做真实加锁；所有 API 对同一设备可选自动加锁（建议自动串行化，避免调用方忘记）。
- 跨进程：SQLite WAL + `token.lock` 上的 `flock`；写事务使用 `BEGIN IMMEDIATE`，冲突重试。
- 文件内容写入放在事务内；大 BLOB 也走 SQLite，避免多文件不一致。

### 8.2 原子性

- 所有修改在单个 SQLite 事务中提交。
- 失败回滚；不留下半成品应用/容器/文件。
- `SKF_CreateApplication`/`CreateContainer` 失败时删除已创建对象。
- `SKF_DeleteContainer` 聚合删除错误，返回首个非 `SAR_FILE_NOT_EXIST` 错误。

### 8.3 错误映射

| 场景 | 返回 |
| --- | --- |
| 设备/应用/容器/文件不存在 | `SAR_FILE_NOT_EXIST` / `SAR_APPLICATION_NOT_EXISTS` |
| 已存在 | `SAR_APPLICATION_EXISTS` / `SAR_FILE_ALREADY_EXIST` |
| 未登录 | `SAR_USER_NOT_LOGGED_IN` |
| PIN 错误/锁定 | `SAR_PIN_INCORRECT` / `SAR_PIN_LOCKED` |
| 参数/长度 | `SAR_INVALIDPARAMERR` / `SAR_INDATALENERR` |
| 认证失败/安全状态 | `SAR_UNKNOWNERR`（设备认证兼容原厂） |
| 数据损坏/验签失败 | `SAR_OBJERR` / `SAR_INDATAERR` |
| 不支持算法 | `SAR_NOTSUPPORTYETERR` |
| 空间不足 | `SAR_NO_ROOM` |

---

## 9. 安全分析与威胁模型

| 威胁 | 防护 | 残余风险 |
| --- | --- | --- |
| 复制 token 目录到另一台机器 | 私钥/文件用 PIN 派生 AK 加密；没有 PIN 无法解密 | 拿到 PIN 可解密 |
| 直接改数据库伪造应用/容器 | AEAD 标签、PIN verifier、事务 | 公开字段可被 DoS 篡改 |
| 伪造私钥/证书 | 私钥 AEAD；证书导入校验公钥匹配 | 无 |
| 暴力猜 PIN | Argon2id/PBKDF2 + 重试锁定 | 本机 root 可改计数 |
| 设备认证暴力 | 重试计数 + 锁定 | 本机 root 可改计数 |
| 内存抓取 | 及时清零、可选 mlock | root/ptrace 可读 |
| 回滚整个目录 | 无单调计数器 | 可回滚到旧备份 |
| 替换 `libsoftskf.so` | 无 | 本机管理员可替换 |
| SM1/SSF33 合规 | 不实现，直接返回 `SAR_NOTSUPPORTYETERR` | 需要授权实现或硬件；本期不提供 |

**结论：软 SKF 适合开发测试、离线软授权、低安全等级部署；高安全等级仍应使用硬件 UKey。**

---

## 10. 测试计划

### 10.1 功能/兼容

- `skf_all` 全接口调用：79/79，无崩溃；状态与预期一致。
- `skf_imports_test`：证书/ECC/RSA/会话密钥/协商。
- `skf_destructive`：临时应用/容器/文件/密钥生成/签名/验签。
- 自建 `softskf_test`：初始化、PIN、锁定、解锁、重启持久化、多设备、多进程。

### 10.2 密码学测试向量

- SM3：GB/T 32905 测试向量。
- SM4：GB/T 32907 测试向量；ECB/CBC/CFB/OFB。
- SM2：GM/T 0003 签名/加密/密钥交换测试向量。
- SM1/SSF33：不测密码运算；只测 `SKF_SetSymmKey` 返回 `SAR_NOTSUPPORTYETERR`，以及未创建句柄。
- RSA：OpenSSL 标准测试；PKCS#1 v1.5 签名/加密。
- ECDH：SM2 曲线已知向量。
- 随机数：NIST/健康检查（可选）。

### 10.3 安全/异常

- 错误 PIN/设备认证、锁定、解锁、重试计数。
- 篡改数据库字段/密文/标签 -> 必须失败。
- 复制 token 目录到另一路径 -> 仍可用（同一 PIN），但不能伪造。
- 删除/回滚数据库 -> 行为定义（拒绝启动或恢复）。
- 并发多进程读写、`SKF_LockDev` 并发。
- 崩溃注入（写事务中 kill -9）-> WAL 恢复。
- 文件大小/名称/数量边界。
- ASan/UBSan/Valgrind；SQLite/文件解析 fuzz。

### 10.4 性能

- 连接/打开/枚举延迟；
- SM4/SM3 吞吐；
- RSA 2048 生成/签名；
- SQLite 事务写入延迟。

---

## 11. 构建与交付

> 首版实际构建入口是 `Makefile`（见 `README.md`）；下面的 CMake
> 命令是后续跨平台打包方案。

构建：

```bash
cmake -S . -B build -DSOFTSKF_WITH_GMSSL=OFF
cmake --build build
```

依赖：

- OpenSSL >= 3.0
- SQLite >= 3.40
- pthread
- 可选：libsodium、GmSSL

交付物：

```text
libsoftskf.so          # SKF ABI
softskf-init           # 初始化 token
softskf-admin          # 维护
include/skf/skf.h
LICENSES/              # 第三方许可证与 NOTICE
```

安装后应用可通过 `LD_LIBRARY_PATH` 或替换 `libskf.so` 使用。SM1/SSF33 不提供实现，相关标识返回 `SAR_NOTSUPPORTYETERR`。

---

## 12. 实施计划

| 阶段 | 内容 | 产出 |
| --- | --- | --- |
| 1 | 存储层、初始化 CLI、设备/应用/PIN/文件/容器 | 可跑 `skf_all` 基础接口 |
| 2 | SM4/SM3/MAC/摘要/随机 | 对称与摘要测试通过 |
| 3 | SM2/RSA 密钥、签名、验签、会话密钥 | `skf_destructive` 通过 |
| 4 | 证书、导入、信封、ECDH | `skf_imports_test` 通过 |
| 5 | 事件、锁、并发、崩溃恢复 | 并发/异常测试通过 |
| 6 | 文档、打包、跨平台 | 发布候选 |

---

## 13. 需要评审确认的问题

> 已确认：SM1/SSF33 不实现，`SGD_SM1_*` / `SGD_SSF33_*` 直接返回 `SAR_NOTSUPPORTYETERR`；不做 SM4 映射，不加载外部 provider。

1. **ZUC 是否需要**：默认不编译 GmSSL/ZUC，是否可以？
2. **存储引擎**：接受 SQLite 单文件数据库，还是必须用纯目录/TLV 文件？
3. **RSA 签名语义**：按硬件行为使用 PKCS#1 v1.5 + 原始 digest（无 DigestInfo），还是使用标准 DigestInfo？默认建议前者。
4. **SM2 签名语义**：按硬件行为 `e=digest`，还是标准 `e=SM3(ZA||M)`？默认建议前者，并在文档中说明调用方需传入正确 digest。
5. **应用/文件权限**：私有操作是否都要求 user/admin PIN？默认：私钥/文件内容需要 PIN，公开元数据不需要。
6. **设备认证锁定错误码**：`SKF_DevAuth` 锁定返回 `SAR_UNKNOWNERR`（兼容原厂）还是 `SAR_PIN_LOCKED`（更清晰）？
7. **`SKF_ECCDecrypt`**：是否导出？原厂库未导出，软库可以实现容器私钥解密，作为扩展。
8. **默认凭据**：初始化 CLI 是否强制设置随机设备认证密钥和 PIN，禁止通用默认值？
9. **Windows 支持**：第一版只做 Linux，还是同时做 Windows（SQLite/OpenSSL 可跨平台，事件/锁需适配）？
10. **安全等级**：是否接受“软件 SKF 无法防本机 root/调试器”的边界？如果不接受，应继续用硬件 UKey。
11. **与硬件行为一致性**：是否需要逐接口对照原厂库（包括错误码、文件 ID、`EnumDev` 格式）？这会影响测试和兼容工作量。

---

## 14. 结论

该设计用本地 SQLite + 分层密钥（设备认证 MK / 应用 PIN AK）实现完整 SKF API：

- 设备级管理由设备认证密钥保护；
- 应用私钥/文件由应用 PIN 派生的 AK 保护；
- 密码算法优先使用 OpenSSL 3（SM2/SM3/SM4/RSA/X.509），可选 GmSSL（ZUC）和 libsodium（Argon2id）；
- **SM1/SSF33 规范未公开，本期不实现**；相关算法标识直接返回 `SAR_NOTSUPPORTYETERR`，不做 SM4 映射，也不加载外部 provider；
- 软件 SKF 的安全边界是“防离线文件复制/篡改”，不是“防本机 root/调试器”。

请重点评审第 13 节的 11 个问题，确认后我再进入编码阶段。

---

## 15. 首版实现状态（2026-11-05）

首版实现位于：

```text
libsoftskf.so      # 导出全部 79 个 SKF_* 符号
softskf-init       # 初始化软令牌
include/sgd.h
include/skf/skf.h
src/softskf.c
src/softskf_init.c
tests/softskf_test.c
tests/softskf_admin_test.c
tests/skf_all.c
tests/skf_imports_test.c
tests/hw_cross_test.c
HW_CROSS_REPORT.md
third_party/sqlite3/sqlite3.h
```

构建与测试：

```bash
make
make test
```

已验证：

- `nm -D` 导出 79 个 `SKF_*` 符号，无缺失；
- `make test` 的 `softskf_test` 和 `softskf_admin_test` 全部通过；
- `linux/skf_all` 对软库运行：48 PASS，1 个预期返回（`SKF_Transmit`
  不支持），0 missing，0 not run；
- `linux/skf_imports_test` 对软库运行：0 failures（ECC/RSA 导入、证书、
  会话密钥、密钥协商、签名验签均通过）；
- `SM1`/`SSF33` 相关调用返回 `SAR_NOTSUPPORTYETERR`，未做 SM4 映射；
- 与硬件 CCM3302 UKey 交叉验证（`tests/hw_cross_test.c`）：
  26 PASS，0 FAIL，1 个预期差异（SM1 硬件支持、软库不支持），1 个 NA
  （SM4-CFB128 厂商库不支持，无法比较）。已验证 SM4-ECB/CBC/OFB 密文逐字节
  一致、SM4 CBC-MAC 一致、SM3/SHA1/SHA256 一致、SM2 签名/验签双向通过、
  ExtECCEncrypt/Decrypt 双向通过、软库 RSA 签名可由硬件验证。

实现约定：

- 每个软令牌一个 `token.db`，使用 SQLite WAL；`token.key` 为 0600；
- 设备认证密钥、应用 PIN 包装密钥、应用私钥/文件内容均按第 3 节分层加密；
- 应用 PIN 使用 PBKDF2-HMAC-SHA256（10 万次），应用密钥用 AES-256-GCM 包装；
- 文件和容器私钥使用 HKDF + AES-256-GCM；
- `SKF_EncryptUpdate`/`SKF_DecryptUpdate` 缓冲到 Final 输出，兼容现有硬件库；
- ECC 签名按 `e=digest`，RSA 签名按 PKCS#1 v1.5 + 原始 digest。

仍待后续完善：

- Windows 事件/锁适配；
- 可选 Argon2id PIN KDF；
- 标准 ECC 信封导入在“容器尚无 ECC 私钥”时的完整支持；
- 更严格的跨进程设备锁和审计日志；
- SM1/SSF33 如未来需要，必须单独评审并引入有明确授权的实现。
