# 原生 SKF 实现代码走读与测试覆盖审计

> 审计对象：`linux/reimpl/skf_native.c`（3544 行，78 个导出 `SKF_*` 符号）
> 对照：`SKF_API`、厂商 `linux/lib/libskf.so`、`linux/skf_all.c`、
> `linux/skf_destructive.c`、`linux/skf_imports_test.c`
>
> 审计方式：接口清单比对、`nm`/`grep` 静态清点、`skf_all` 差分运行、
> `skf_destructive`/`skf_imports_test` 运行、标准信封独立构造测试、
> `gcc -Wall -Wextra -Wpedantic` 与 `gcc -fanalyzer` 静态检查。

## 0. 结论摘要

| 指标 | 结果 |
| --- | --- |
| 头文件接口数 | 79 |
| 原生导出接口数 | 78 |
| 缺失接口 | 1：`SKF_ECCDecrypt`（厂商库也未导出） |
| 完整实现 | 50 |
| 部分实现/有限制 | 21 |
| 桩/空操作/损坏/缺失 | 8 |
| `skf_all` 覆盖 | 79/79 被调用；72 PASS / 12 RET / 20 SKIP / 1 MISSING |
| 与厂商库逐接口状态差分 | 79/79 状态一致 |
| `skf_destructive` | 21 PASS / 0 FAIL |
| `skf_imports_test` | 21/21 PASS |
| 静态检查 | 无新增内存分析错误；有 1 个不兼容指针警告，其余主要是 signedness 和 OpenSSL 3 弃用警告 |

总体判断：核心设备、应用、文件、容器、PIN、SM1/DevAuth、SM4/SM3/MAC、
ECC/RSA 主路径已经可用；差异主要集中在**设备事件、SetLabel、证书校验、
设备私钥封装、边界参数和并发/回滚**。

> 注：下文的接口统计、发现编号和优先级是 2026-10-30 审计时的快照。
> 2026-11-02 已完成的高/中优先级修复见 0.1 节；未修复项仍在第 3 节保留，
> 作为后续工作清单。

## 0.1 2026-11-02 修复进展

已修复并有厂商/native 对照测试：

| 编号 | 项目 | 结果 |
| --- | --- | --- |
| H1 | `SKF_SetLabel` / `GetDevInfo.Label` | 写 `3F02`（33 字节），读回标签；vendor/native 一致 |
| H2 | `SKF_ImportCertificate` | 解析 X.509 并校验容器公钥；伪证书返回 `SAR_OBJERR` |
| H3 | `SKF_WaitForDevEvent` / `SKF_CancelWaitForDevEvent` | 50 ms 轮询 `/dev`，支持插拔事件和取消；与 vendor 输出一致 |
| H4 | `SKF_ChangeDevAuthKey` | 实现 `84 A5 01`、控制密钥、DES-MAC；长度 17 映射与 vendor 一致；零长度会被拒绝（安全偏差） |
| M1 | `SKF_GetPINInfo` | 按 USER/ADMIN 选择 `P1`，max/default/remain 解析正确 |
| M2 | `SKF_ReadFile` / `SKF_WriteFile` | 分块前检查 `off + done > 0xFFFF` |
| M3 | `SKF_CreateApplication` | 使用 `adminlen`/`userlen`，本地 NUL 结尾缓冲 |
| M4 | `SKF_CreateContainer` / `SKF_DeleteContainer` | 失败回滚、删除错误聚合 |
| M5 | `SKF_EnumDev` | 过滤 C*Core、返回 `sdd1\0sdd\0\0`（长度 10） |
| M6 | ECC blob / `SKF_ECCExportSessionKey` | 坐标/私钥/签名右对齐，设备字序转换，SM2 双向互操作 |
| M7 | 标准信封 | 仍只支持软件私钥容器，设备生成私钥路径未完成 |
| M8 | `SKF_LockDev` / `SKF_UnlockDev` | 真实 `pthread_mutex`，8 线程并发 max_active=1 |
| H4+ | `SKF_ExtECCSign` / `SKF_ExtECCDecrypt` | 软件 SM2 实现；vendor/native 交叉验签/解密通过 |

新增对照测试（均要求 vendor 与 native 输出一致）：

```text
linux/skf_diff_test.c          设备信息/标签/PIN/文件/容器/错误路径
linux/skf_event_diff_test.c    热插拔 add/remove/cancel
linux/skf_lock_test.c          LockDev/UnlockDev 并发
linux/skf_ext_ecc_test.c        ECC 加解密与签名双向交叉
linux/skf_session_ecc_test.c    ECCExportSessionKey 句柄密钥与封装结果一致
```

当前设备认证处于锁定状态（`00 82` 返回 `6983`），因此依赖 DevAuth 的
应用/容器用例暂时无法重跑；不依赖 DevAuth 的 `skf_all` 结果为：

```text
vendor: 53 PASS / 12 RET / 20 SKIP / 1 MISSING
native: 53 PASS / 12 RET / 20 SKIP / 1 MISSING
逐接口输出完全一致（diff 为空）
```

锁定原因与恢复：早期 `skf_diff_test` 曾调用
`SKF_ChangeDevAuthKey(dev, empty, 0)`，vendor 库接受该调用并把设备认证
密钥写成 16 个 0 字节；随后用旧密钥反复认证触发 `6983`。USB 端口复位
和 root hub 重新绑定都不能清除该锁定，需要物理重新上电/工厂复位或
厂商恢复工具。native 现在明确拒绝零长度密钥（`SAR_INDATALENERR`），
避免再次发生。

仍未完成的主要项：

```text
标准信封导入到设备生成、不可导出的私钥容器（M7）
SKF_CreateFile 非 SECURE_ANYONE_ACCOUNT 权限组合
SKF_GenRSAKeyPair 2048 位及对应签名/验签
SKF_ExportCertificate 动态缓冲（当前固定 512 字节）
SKF_ImportCertificate 失败时旧证书保留
SKF_ECCDecrypt（头文件声明，厂商库同样未导出）
静态警告清理（signedness、OpenSSL 3 弃用 API）
```


---

## 1. 接口实现统计

### 1.1 完整实现（50）

这些接口有有效路径测试，且当前没有发现明确的功能性缺陷：

```text
SKF_EnumDev
SKF_ConnectDev
SKF_GetDevState
SKF_DevAuth
SKF_ChangePIN
SKF_UnblockPIN
SKF_EnumApplication
SKF_OpenApplication
SKF_VerifyPIN
SKF_CreateApplication
SKF_DeleteApplication
SKF_EnumFiles
SKF_GetFileInfo
SKF_DeleteFile
SKF_EnumContainer
SKF_OpenContainer
SKF_GetContainerType
SKF_ExportPublicKey
SKF_ECCSignData
SKF_ECCVerify
SKF_ExtECCVerify
SKF_ExtECCEncrypt
SKF_CloseHandle
SKF_RSASignData
SKF_RSAVerify
SKF_GenExtRSAKey
SKF_ExtRSAPubKeyOperation
SKF_ExtRSAPriKeyOperation
SKF_CloseContainer
SKF_SetSymmKey
SKF_EncryptInit
SKF_Encrypt
SKF_DecryptInit
SKF_Decrypt
SKF_EncryptUpdate
SKF_EncryptFinal
SKF_DecryptUpdate
SKF_DecryptFinal
SKF_MacInit
SKF_Mac
SKF_MacUpdate
SKF_MacFinal
SKF_DigestInit
SKF_Digest
SKF_DigestUpdate
SKF_DigestFinal
SKF_GenRandom
SKF_ClearSecureState
SKF_CloseApplication
SKF_DisConnectDev
```

说明：`SKF_CreateApplication`/`SKF_DeleteApplication` 虽然功能通过，但
创建失败时的回滚仍不完整，见第 3 节。

### 1.2 部分实现或有限制（21）

| 接口 | 当前实现 | 主要限制 |
| --- | --- | --- |
| `SKF_GetDevInfo` | 解析 `80 aa`/`80 b7`/`80 b9` | Label 最终被硬编码为 `UKEY`；算法能力字段是固定值 |
| `SKF_GetPINInfo` | `80 BC` 固定偏移解析 | `type` 参数未使用，ADMIN/USER 返回同一组值 |
| `SKF_CreateFile` | `2002` 目录 + `2Fxx` 文件 | 只接受 `SECURE_ANYONE_ACCOUNT`；文件大小字段实际按 16 位处理 |
| `SKF_ReadFile` | 分块读 | 偏移是 16 位；`off + done` 可能超过 `0xFFFF` 后回绕 |
| `SKF_WriteFile` | 分块写 | 同样存在 16 位偏移问题；未做文件大小边界检查 |
| `SKF_CreateContainer` | 创建 `110x` 名称 EF 和 `130x` 密钥 EF | `select_file` 返回值未全部检查；失败时无回滚 |
| `SKF_DeleteContainer` | 删除多个 EF | 删除子文件失败被忽略，仍可能返回 `SAR_OK` |
| `SKF_ExportCertificate` | FCI 长度 + 读取 | 固定 512 字节栈缓冲；超过 512 字节的证书会截断 |
| `SKF_ECCExportSessionKey` | 设备 SM2 封装 + 句柄 | 只验证返回码，未验证“句柄密钥”与 `ECCCipherBlob` 解出的密钥一致 |
| `SKF_ImportCertificate` | 创建 `1501/1502` 并写入 | 不校验证书内容/公钥是否与容器密钥匹配 |
| `SKF_ImportECCKeyPair` | 支持标准 SM2 信封和原生明文扩展 | 标准信封要求容器已有软件 ECC 私钥；设备生成私钥不可导出 |
| `SKF_ImportRSAKeyPair` | 支持标准 RSA wrapped-key 和原生明文扩展 | 标准格式同样要求容器已有软件 RSA 私钥 |
| `SKF_ImportSessionKey` | 接受 16/24/32 字节原始密钥 | 尚未实现厂商标准 wrapped session key 解包 |
| `SKF_GenRSAKeyPair` | 设备生成 1024 位 RSA | 只接受 `bits==1024`；2048 位未覆盖 |
| `SKF_GenECCKeyPair` | 设备生成 SM2 密钥 | 私钥不导出，不能直接用于原生 ECC 协商 |
| `SKF_RSAExportSessionKey` | RSA 封装随机 SM4 密钥 | 仅验证返回，未验证封装结果可被对应私钥解出 |
| `SKF_GenerateAgreementDataWithECC` | 软件 SM2 ECDH | 依赖 `SKF_ImportECCKeyPair` 导入的软件私钥 |
| `SKF_GenerateAgreementDataAndKeyWithECC` | 软件 SM2 ECDH | 同上；静态私钥必须在容器上下文中 |
| `SKF_GenerateKeyWithECC` | 软件 SM2 ECDH | 同上；协商句柄只在当前进程有效 |
| `SKF_LockDev` | 空操作 | 未实现设备级互斥/超时 |
| `SKF_UnlockDev` | 空操作 | 与 `SKF_LockDev` 对称但无实际锁 |

### 1.3 桩、空操作、损坏或缺失（8）

| 接口 | 状态 | 说明 |
| --- | --- | --- |
| `SKF_SetLabel` | 损坏 | 实测 native 返回 `0xA000002`；原库对 `"AUDIT1"` 返回 `SAR_OK`，且 `GetDevInfo` 能读回 |
| `SKF_WaitForDevEvent` | 桩 | 原库实现了热插拔事件等待；native 返回 `SAR_NOTSUPPORTYETERR` |
| `SKF_CancelWaitForDevEvent` | 空操作 | 返回 `SAR_OK`，但没有等待上下文可取消 |
| `SKF_Transmit` | 桩 | native 与原库都返回 `SAR_NOTSUPPORTYETERR`；属于“原库也不支持” |
| `SKF_ChangeDevAuthKey` | 桩 | 原库支持 `84 A5 01`；native 未实现 |
| `SKF_ExtECCSign` | 桩 | 外部 ECC 私钥签名未实现 |
| `SKF_ExtECCDecrypt` | 桩 | 外部 ECC 私钥解密未实现 |
| `SKF_ECCDecrypt` | 缺失 | 头文件声明，但厂商库和 native 都没有导出；`skf_all` 记为 MISSING |

---

## 2. 测试覆盖情况

### 2.1 测试入口

| 测试 | 覆盖内容 | 结果 |
| --- | --- | --- |
| `linux/skf_all.c` | 79 个接口动态调用；带设备认证时创建/删除临时应用、文件、容器 | 72 PASS / 12 RET / 20 SKIP / 1 MISSING |
| `linux/skf_destructive.c` | KEDA 临时容器、ECC/RSA 生成/签名/验签、RSA 会话密钥、外部 RSA | 21 PASS / 0 FAIL |
| `linux/skf_imports_test.c` | 导入证书/会话密钥/ECC/RSA、ECC 协商、导入 RSA 签名验签 | 21/21 PASS |
| 独立标准信封测试 | 标准 SM2 `ENVELOPEDKEYBLOB`、标准 RSA wrapped-key | 导入/协商/验签通过 |
| `gcc -fanalyzer` | 静态内存/路径分析 | 未发现新增内存错误 |

`skf_all` 差分结果：

```text
vendor: 72 PASS / 12 RET / 20 SKIP / 1 MISSING
native: 72 PASS / 12 RET / 20 SKIP / 1 MISSING
```

逐接口最终状态与厂商库 79/79 一致。

### 2.2 覆盖较好的部分

以下路径有有效参数和结果验证：

- 设备枚举/连接/断开/设备信息/随机数
- 设备认证、应用创建/删除、PIN 验证/修改/锁定/解锁
- 文件目录创建、文件创建/写/读/删/信息查询
- 容器创建/打开/枚举/类型/删除
- ECC 生成/签名/验签/加密/扩展验签
- RSA 生成/签名/验签/会话密钥导出/外部 RSA 运算
- SM4 ECB/CBC/CFB/OFB、SM3、SM4 MAC 及流式接口
- 原生导入、ECC 协商、标准 ECC/RSA 信封（软件私钥容器）

### 2.3 未覆盖或弱覆盖的情形

#### 完全未覆盖的有效路径

```text
SKF_SetLabel               当前实现直接失败，测试也跳过
SKF_WaitForDevEvent        不支持，测试跳过
SKF_ChangeDevAuthKey       未实现，测试跳过
SKF_ExtECCSign             未实现，测试跳过
SKF_ExtECCDecrypt          未实现，测试跳过
SKF_ECCDecrypt             缺失，无法测试
```

#### 只测了 USER，未测 ADMIN

```text
SKF_GetPINInfo(ADMIN_TYPE)
```

实测 KEDA 的 USER/ADMIN 返回相同值，因此不能证明 `type` 处理正确；
代码中 `type` 参数完全没有参与解析。

#### 只测了部分参数

```text
SKF_CreateFile:
  只测 SECURE_ANYONE_ACCOUNT；未测 SECURE_NEVER/ADM/USER 权限组合

SKF_ReadFile / SKF_WriteFile:
  只测 offset=0、小文件；未测 offset>0、跨块、接近 0xFFFF 的边界

SKF_ImportCertificate:
  只测空证书和“伪证书”；未测真实 X.509 证书、证书公钥不匹配、证书过长

SKF_ImportSessionKey:
  只测原始 16 字节密钥；未测厂商标准 wrapped session key

SKF_ECCExportSessionKey:
  只测返回码；未用返回句柄加密数据、再用封装结果反解验证密钥一致

SKF_RSAExportSessionKey:
  只测返回码；未用私钥解出会话密钥并验证

SKF_GenRSAKeyPair / SKF_RSASignData:
  只测 1024 位；未测 2048 位或其他长度

SKF_GenECCKeyPair / 协商:
  只测导入的软件 ECC 私钥；未测设备生成私钥的协商

SKF_CreateApplication:
  只测 NUL 结尾的 PIN；未测非 NUL 缓冲区配合 adminlen/userlen

SKF_LockDev / SKF_UnlockDev:
  只检查返回码；未测多线程并发、超时、重入

SKF_EnumDev:
  只测单设备；未测无设备、多个 C*Core 设备、非 C*Core /dev/sgN 的过滤
```

#### 异常路径覆盖不足

- 空指针、NULL 输出缓冲区、过小缓冲区
- 超长应用名/文件名/容器名
- 文件/容器/应用数量达到上限
- 设备中途拔出、`SG_IO` 超时/SCSI 错误
- 应用创建/容器创建失败后的回滚与残留
- 证书/密钥导入失败后的原对象保留
- 设备认证/PIN 锁定后的恢复路径

---

## 3. 代码走读发现

### 3.1 高优先级

#### H1. `SKF_SetLabel` 损坏，且 `GetDevInfo` 不反映真实标签

证据：

```text
native SKF_SetLabel("AUDIT1") -> 0xA000002
原始库 SKF_SetLabel("AUDIT1") -> 0
原始库 GetDevInfo.Label -> "AUDIT1"
```

代码位置：

- `SKF_SetLabel()`：约 `skf_native.c:620`
- `get_devinfo()` 末尾：`strcpy((char *)info->Label, "UKEY")`

风险：标签接口不可用，且 `GetDevInfo` 总是返回 `UKEY`，会误导调用方。

建议：反向 `SKF_DEV_set_lable` 的实际 APDU；在 `get_devinfo` 中保留
`80 aa` 解析出的 Label，不要无条件覆盖。

#### H2. `SKF_ImportCertificate` 不校验证书

证据：

```text
原始库 ImportCertificate(随机 64 字节) -> 0xA00000D
native    ImportCertificate(随机 64 字节) -> 0
```

代码位置：`SKF_ImportCertificate()` 约 `skf_native.c:2410`。

风险：任意字节都可被当成证书写入；与原库行为不一致，也可能导致后续
证书相关操作使用错误数据。

建议：用 OpenSSL 解析 X.509，校验证书公钥与容器公钥一致；失败返回
`SAR_OBJERR`/`SAR_INDATAERR`。

#### H3. 设备事件接口缺失

`SKF_WaitForDevEvent` 直接返回 `SAR_NOTSUPPORTYETERR`，而原库实现了
事件注册/等待/取消。代码位置约 `skf_native.c:665`。

建议：至少实现 Linux 热插拔事件（netlink/inotify/udev）或明确文档说明
平台不支持；不要静默返回成功给 `SKF_CancelWaitForDevEvent`。

#### H4. `SKF_ChangeDevAuthKey` 未实现

原库有 `84 A5 01` 路径；native 仍返回 `SAR_NOTSUPPORTYETERR`。

建议：继续反向 36 字节数据布局，并在临时设备/临时认证密钥上验证；
实现前不要在生产设备上尝试。

### 3.2 中优先级

#### M1. `SKF_GetPINInfo` 忽略 `type`

代码位置约 `skf_native.c:1151`。`type` 参数未使用，USER/ADMIN 走同一
固定偏移。KEDA 两者恰好相同，但不同应用可能不同。

建议：按 `type` 选择 PIN 对象，并分别解析 max/remain/default。

#### M2. 文件读写偏移超过 16 位会回绕

代码位置：

- `SKF_ReadFile()` 约 `skf_native.c:1870`
- `SKF_WriteFile()` 约 `skf_native.c:1902`

代码只检查初始 `off > 0xffff`，但循环中 `off + done` 可能超过
`0xFFFF`，随后被截断到 P1/P2，导致写到错误位置。

建议：每次分块前检查 `off + done <= 0xffff`；或扩展协议支持更大偏移。

#### M3. `SKF_CreateApplication` 用 `strlen` 读取 PIN

代码位置约 `skf_native.c:981`。函数接收 `adminlen/userlen`，但实际用
`strlen(adminpin)`/`strlen(userpin)`。若调用方传入非 NUL 结尾的定长
缓冲区，会越界读取。

建议：使用传入长度；对 PIN 缓冲区先拷贝到本地 NUL 结尾数组。

#### M4. 容器创建/删除缺少回滚和错误检查

`SKF_CreateContainer` 忽略部分 `select_file` 返回值，创建失败时可能
留下半成品文件；`SKF_DeleteContainer` 忽略子文件删除错误，仍返回
`SAR_OK`。

建议：统一记录已创建对象，失败时逆序删除；删除失败返回首个错误或
汇总错误。

#### M5. `SKF_EnumDev` 回退可能返回非 C*Core 设备

代码位置约 `skf_native.c:468`。当 `glob` 找不到 C*Core 设备时，回退
选择第一个可访问的 `/dev/sgN`，没有再次校验 vendor。

建议：回退时仍检查 `vendor_is_ccore()`；或者明确要求调用方传入设备名。

#### M6. `SKF_ECCExportSessionKey` 语义未验证

`SKF_ECCExportSessionKey` 只验证返回码；我们独立测试中发现：
用 `SKF_ExtECCEncrypt`/设备 `80 56 03` 的输出做标准 SM2 解密，得到的
会话密钥与传入的会话密钥不一致。可能是坐标/字节序/KDF 细节问题，也
可能是设备命令并不等价于标准 SM2 加密。

建议：抓包对比原库 `SKF_ECCExportSessionKey` 的 `ECCCipherBlob`，
用对应私钥验证解出的会话密钥；在未确认前不要承诺跨实现互操作。

#### M7. 标准信封只支持“软件私钥容器”

标准 ECC/RSA 信封路径已实现，但解密必须依赖容器中的软件私钥。设备
`SKF_GenECCKeyPair`/`SKF_GenRSAKeyPair` 生成的私钥不可导出，因此不能
直接解密标准信封。

建议：继续反向 `80 56 03`（ECC）和 `80 52/80 53`（RSA）的设备私钥
运算路径，或明确文档限制。

#### M8. `SKF_LockDev` / `SKF_UnlockDev` 是空操作

代码约 `skf_native.c:602`。多线程调用同一设备时没有串行化。

建议：在 `DEV_CTX` 中加 pthread mutex，`LockDev`/`UnlockDev` 做真实
加锁/解锁；或明确单线程 API 约束。

### 3.3 低优先级

- `SKF_GenRandom()` 中 `cmd[8]` 未使用，建议删除。
- `rsa_host_verify_any()` 的 `siglen` 参数未使用，建议移除或校验。
- `get_devinfo()`/`SKF_ConnectDev()` 未检查 `get_devinfo` 的返回值。
- `SKF_ExportCertificate()` 固定 512 字节缓冲，建议按 FCI 长度动态分配。
- `SKF_ImportCertificate()` 先删除旧文件再创建，创建失败会丢失旧证书；
  建议先创建临时文件或失败恢复。
- `SKF_CreateFile()` 只支持 `SECURE_ANYONE_ACCOUNT`，如果原库支持其他
  权限组合，应补齐。
- `SKF_GenRSAKeyPair()` 只支持 1024 位；建议支持 2048 位并补充测试。
- OpenSSL 3 弃用 API 较多（DES/RSA/EC_KEY），建议迁移到 EVP/PKEY API。

### 3.4 静态检查结果

`gcc -Wall -Wextra -Wpedantic` 产生约 737 行警告，主要是：

- `CHAR`/`char` signedness 警告
- OpenSSL 3 弃用 API 警告
- 一个 `RSA_get0_key` 的 `const BIGNUM **` 不兼容指针

`gcc -fanalyzer` 未报告新的内存泄漏/越界路径。上述 signedness 警告
大多不影响当前行为，但会掩盖真正的问题，建议逐步清理。

---

## 4. 优化建议（按优先级）

1. **修复功能缺口**：`SetLabel`、证书校验、设备事件、`ChangeDevAuthKey`、
   `ExtECCSign`/`ExtECCDecrypt`。
2. **强化边界安全**：文件偏移、PIN 长度、证书长度、容器/应用回滚。
3. **补充错误/并发测试**：空参数、超长名称、对象上限、设备拔出、
   多线程、锁定/解锁。
4. **确认会话密钥封装语义**：`ECCExportSessionKey`/`ExtECCEncrypt`
   需要跨实现解密验证。
5. **减少警告**：统一 `char`/`CHAR` 转换；迁移 OpenSSL 弃用接口。
6. **建立自动化回归**：把 `skf_all`、`skf_destructive`、
   `skf_imports_test` 和标准信封测试纳入 CI（需要真实设备或 USB 透传）。

---

## 5. 建议新增的测试用例

```text
SKF_SetLabel + GetDevInfo 标签回读
SKF_GetPINInfo USER/ADMIN 差异
SKF_ImportCertificate 真实证书、错误公钥、超长证书
SKF_ReadFile/WriteFile offset=1、跨 0x1E8 块、接近 0xFFFF
SKF_CreateFile 各权限组合
SKF_GenRSAKeyPair 2048 + RSASignData/RSAVerify
SKF_ECCExportSessionKey 句柄密钥与 ECCCipherBlob 反解一致性
SKF_RSAExportSessionKey 私钥反解一致性
标准 ECC/RSA 信封到设备生成私钥的导入
SKF_WaitForDevEvent/CancelWaitForDevEvent 热插拔
SKF_LockDev/UnlockDev 多线程并发
设备拔出/重新插入后的连接恢复
```

## 6. 审计命令与证据

```bash
# 接口清单
grep -oE 'SKF_[A-Za-z0-9_]+[[:space:]]*\(' include/skf/skf.h
nm -D --defined-only reimpl/libskf_native.so | grep '^.* SKF_'

# 差分测试
skf_all ./lib/libskf.so
skf_all ./reimpl/libskf_native.so
skf_destructive
skf_imports_test

# 静态检查
gcc -shared -fPIC -O0 -Wall -Wextra -Wpedantic \
    -Iinclude/skf -o /tmp/libskf_audit.so \
    reimpl/skf_native.c -lcrypto
gcc -c -O0 -fanalyzer -Iinclude/skf \
    -o /tmp/skf_analyzer.o reimpl/skf_native.c
```

关键实测证据：

```text
native SetLabel("AUDIT1")        -> 0xA000002
original SetLabel("AUDIT1")      -> 0
original GetDevInfo.Label        -> AUDIT1

native ImportCertificate(fake)   -> 0
original ImportCertificate(fake) -> 0xA00000D
```
