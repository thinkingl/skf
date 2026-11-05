# 原生 SKF 重实现（直接 SG_IO）

目标：不依赖厂商 x86-64 `libskf.so`，用 C 直接通过 Linux `SG_IO` 访问
C*Core UKey 的 vendor SCSI 接口，实现一份可交叉编译到 arm64 的 SKF 库。

完整的线协议说明见 [`PROTOCOL.md`](PROTOCOL.md)。

## 2026-11-02 更新

本轮补齐并验证了以下差异（全部有 vendor/native 对照测试）：

```text
SKF_SetLabel / GetDevInfo.Label     3F02 33 字节标签，读写回一致
SKF_GetPINInfo                      USER/ADMIN P1 区分
SKF_EnumDev                         sdd1\0sdd\0\0（长度 10）
SKF_ReadFile / SKF_WriteFile        16 位偏移回绕检查
SKF_CreateApplication               adminlen/userlen 语义
SKF_CreateContainer/DeleteContainer 失败回滚、删除错误聚合
SKF_ImportCertificate               X.509 与容器公钥校验
SKF_WaitForDevEvent/Cancel          50ms /dev 轮询，插拔/取消语义
SKF_ChangeDevAuthKey                84 A5 01 + 控制密钥 + DES-MAC
SKF_ExtECCSign / ExtECCDecrypt      软件 SM2 签名/解密
SKF_LockDev / SKF_UnlockDev         pthread_mutex，8 线程串行化
ECC blob 布局                       坐标/私钥/签名右对齐，设备字序转换
```

新增测试：

```text
linux/skf_diff_test          设备/应用/文件/容器/错误路径差分
linux/skf_event_diff_test    热插拔 add/remove/cancel 差分
linux/skf_lock_test          LockDev/UnlockDev 并发差分
linux/skf_ext_ecc_test       ECC 加解密/签名双向交叉
linux/skf_session_ecc_test   ECCExportSessionKey 句柄密钥与封装结果一致
```

当前设备认证被锁定（`6983`），依赖 DevAuth 的用例暂时不能重跑；不依赖
DevAuth 的 `skf_all` 结果：

```text
vendor: 53 PASS / 12 RET / 20 SKIP / 1 MISSING
native: 53 PASS / 12 RET / 20 SKIP / 1 MISSING
```

逐接口输出 diff 为空。锁定原因见文末“设备认证”一节。

源码：

```text
linux/reimpl/skf_native.c     SKF API + 协议实现
linux/reimpl/sg_trace.c       LD_PRELOAD SG_IO 抓包工具
linux/reimpl/apdu_probe.c     单条 APDU 探测工具
linux/reimpl/capture_*.c      协议抓包程序
```

构建 x86-64：

```bash
cd linux
gcc -shared -fPIC -O2 -Iinclude/skf \
  -o reimpl/libskf_native.so reimpl/skf_native.c -lcrypto
```

构建 arm64（需要 aarch64 的 libcrypto）：

```bash
aarch64-linux-gnu-gcc -shared -fPIC -O2 \
  -Ilinux/include/skf \
  -o linux/reimpl/libskf_native_aarch64.so \
  linux/reimpl/skf_native.c -lcrypto
```

运行时：

```bash
LD_LIBRARY_PATH=linux/reimpl ./skf_test_generic
LD_LIBRARY_PATH=linux/reimpl ./skf_all ./linux/reimpl/libskf_native.so
LD_LIBRARY_PATH=linux/reimpl ./skf_destructive
```

注意：`skf_destructive` 需要先复制/链接
`reimpl/libskf_native.so` 为 `reimpl/libskf.so`，或直接使用
`LD_PRELOAD`。

## 已实现的接口

### 设备/应用/容器

```text
SKF_EnumDev
SKF_ConnectDev
SKF_DisConnectDev
SKF_GetDevState
SKF_GetDevInfo
SKF_GenRandom
SKF_LockDev
SKF_UnlockDev
SKF_CancelWaitForDevEvent
SKF_Transmit                 （返回 SAR_NOTSUPPORTYETERR，与原库一致）
SKF_DevAuth                  （SM1 challenge/response，已稳定通过）
SKF_EnumApplication
SKF_OpenApplication
SKF_CloseApplication
SKF_CreateApplication        （临时应用实测）
SKF_DeleteApplication        （临时应用实测）
SKF_GetPINInfo
SKF_VerifyPIN                （DES challenge/response，已实测）
SKF_ChangePIN                （80 5e，临时应用实测）
SKF_UnblockPIN               （80 2c，临时应用实测）
SKF_ClearSecureState
SKF_EnumContainer
SKF_OpenContainer
SKF_CloseContainer
SKF_GetContainerType
SKF_CreateContainer          （已实测创建/删除）
SKF_DeleteContainer          （已实测）
SKF_EnumFiles                （读 0x2002 文件目录）
SKF_CreateFile               （0x2002 + 0x2Fxx，临时应用实测）
SKF_ReadFile / SKF_WriteFile （临时应用实测）
SKF_DeleteFile               （临时应用实测）
SKF_GetFileInfo              （读 FCI，临时应用实测）
```

### 证书/ECC

```text
SKF_ExportCertificate        （读 0x1502）
SKF_ExportPublicKey          （读公钥 0x130x）
SKF_GenECCKeyPair            （80 55 / 80 57）
SKF_ECCSignData              （80 56 01）
SKF_ECCVerify                （80 58 / 80 56 02）
SKF_ExtECCVerify
SKF_ExtECCEncrypt            （80 58 / 80 56 03）
SKF_ECCExportSessionKey      （生成会话密钥并用 ECC 公钥封装）
```

### RSA 容器/外部密钥

```text
SKF_GenRSAKeyPair            （80 50 / 80 51，临时容器实测）
SKF_RSASignData              （80 54 / 80 52 / 80 53，临时容器实测）
SKF_RSAExportSessionKey      （RSA 封装随机 SM4 会话密钥，临时容器实测）
```

`SKF_RSAVerify` 已改为使用设备 `80 52`/`80 53` 做公钥运算，并保留
主机侧 raw RSA 回退；设备生成的 1024 位 RSA 签名已通过验签。

### 对称/摘要/MAC

```text
SKF_SetSymmKey
SKF_EncryptInit / SKF_Encrypt / SKF_EncryptUpdate / SKF_EncryptFinal
SKF_DecryptInit / SKF_Decrypt / SKF_DecryptUpdate / SKF_DecryptFinal
SKF_MacInit / SKF_Mac / SKF_MacUpdate / SKF_MacFinal
SKF_DigestInit / SKF_Digest / SKF_DigestUpdate / SKF_DigestFinal
SKF_CloseHandle
```

说明：会话密钥的 SM4/SM3 运算目前使用 OpenSSL 软件实现，因为原库的
`80 ae` 命令使用一个 40 字节的加密密钥 blob，尚未完全反向；容器私钥
签名/解密仍然走设备命令。

### 外部 RSA

```text
SKF_GenExtRSAKey
SKF_ExtRSAPubKeyOperation
SKF_ExtRSAPriKeyOperation
```

`GenExtRSAKey`/外部 RSA 运算使用 OpenSSL 生成/计算（外部密钥本来就
不驻留设备）。

## 验证结果

历史记录：设备认证可用时，用原始 `skf_all` 动态加载
`libskf_native.so` 并设置 `SKF_DEVAUTH_KEY=<设备认证密钥>` 的结果为
72 PASS / 12 RET / 20 SKIP / 1 MISSING。当前设备认证锁定，未认证运行
结果为 53 PASS，且与 vendor 逐接口一致（见 2026-11-02 更新）。

这次运行已实际完成：

```text
SKF_DevAuth                  PASS
SKF_CreateApplication        PASS
SKF_OpenApplication          PASS
SKF_VerifyPIN                PASS
SKF_ChangePIN                PASS
SKF_UnblockPIN               PASS
SKF_CreateFile               PASS
SKF_WriteFile                PASS
SKF_ReadFile                 PASS
SKF_GetFileInfo              PASS
SKF_DeleteFile               PASS
SKF_CreateContainer          PASS
SKF_DeleteContainer          PASS
SKF_DeleteApplication        PASS
```

`skf_destructive` 使用原生库的结果（21 PASS / 0 FAIL）：

```text
SKF_CreateContainer          PASS
SKF_GenECCKeyPair            PASS
SKF_ECCSignData              PASS
SKF_ECCVerify                PASS
SKF_GenRSAKeyPair            PASS
SKF_RSASignData              PASS
SKF_RSAExportSessionKey      PASS
SKF_GenExtRSAKey             PASS
SKF_ExtRSAPriKeyOperation    PASS
SKF_DeleteContainer          PASS
SKF_RSAVerify                PASS
```

`SKF_CreateApplication` 在设置 `SKF_DEVAUTH_KEY` 的 `skf_all` 流程中已经
稳定通过；`skf_destructive` 本身不执行设备认证，因此在其中仍会显示
`SAR_USER_NOT_LOGGED_IN` 并使用 KEDA 回退。

### 导入与 ECC 协商

新增 `linux/skf_imports_test.c` 回归测试，运行结果 21/21 PASS：

```text
SKF_ImportSessionKey                  PASS
imported session encrypt/decrypt      PASS
SKF_ImportCertificate                 PASS
SKF_ExportCertificate                 PASS
SKF_ImportECCKeyPair                  PASS
SKF_GenerateAgreementDataWithECC      PASS
SKF_GenerateAgreementDataAndKeyWithECC PASS
SKF_GenerateKeyWithECC                PASS
agreement key agreement               PASS
SKF_ImportRSAKeyPair                  PASS
SKF_RSASignData(imported)             PASS
SKF_RSAVerify(imported)               PASS
```

原生实现约定：

- `SKF_ImportCertificate` 把证书写入 `1501`（加密）或 `1502`（签名）EF；
  `SKF_ExportCertificate` 先读 FCI 得到实际长度，再读文件内容。
- `SKF_ImportSessionKey` 接受 16/24/32 字节原始会话密钥，返回可直接
  用于 `SKF_Encrypt`/`SKF_Decrypt` 的句柄。
- `SKF_ImportRSAKeyPair` 同时支持：
  - 标准 wrapped-key：`pbEncryptedData` 为 RSA PKCS#1 v1.5 加密的
    会话密钥，`pbWrappedKey` 为 SM4 加密的 RSA 私钥（blob 或 PKCS#1 DER）。
  - 原生扩展：`pbWrappedKey` 直接是明文 `RSAPRIVATEKEYBLOB`。
- `SKF_ImportECCKeyPair` 同时支持：
  - 标准 `ENVELOPEDKEYBLOB`：`ECCCipherBlob` 为 SM2 加密的会话密钥，
    `cbEncryptedPriKey[32..63]` 为 SM4 加密的 ECC 私钥标量。
  - 原生扩展：`ECCCipherBlob.CipherLen=0`，`cbEncryptedPriKey[0..31]`
    直接是 32 字节 SM2 私钥标量。
- ECC 协商使用 SM2 曲线 ECDH + SM3 KDF。发起方和响应方各自需要
  已导入的 ECC 私钥容器；导入的私钥保存在当前容器句柄内。

标准信封解密要求容器内已有**可用的软件私钥**（可先通过原生扩展导入）。
由设备 `SKF_GenECCKeyPair` / `SKF_GenRSAKeyPair` 生成、不可导出的私钥
目前还不能直接解密标准信封；这条路径需要继续反向设备私钥运算命令
（`80 56 03` / `80 52` / `80 53`）。

临时应用 `SKFPIN1`（由原库创建）上，原生库完成了
`VerifyPIN -> ChangePIN -> VerifyPIN -> ChangePIN -> 锁定 -> UnblockPIN
-> VerifyPIN` 全流程，全部返回 `SAR_OK`；测试后应用已由原库删除。

测试后已确认容器列表恢复为 `DEFAULT`、`K01231-85422873-3457921`。
临时应用 `SKFC1` 已删除。

## 设备认证

`SKF_DevAuth` 已稳定通过。关键点：

- 认证前先选择 `3F00`。
- 用 `80 5B 00 01` 下发 SM1 密钥 blob；blob 为 8 字节主机随机 +
  DES-CBC(serial/random) 加密的 64 字节密钥材料。
- 用 `00 84` 生成 challenge，再用 `80 5B 00 00` 加密，最后发
  `00 82`。
- challenge 生成到 `00 82` 之间不能插入额外的 `00 84`；设备会把最近
  一次随机数与认证/密钥命令关联。

`SKF_ChangeDevAuthKey` 已实现：`84 A5 01 00 00000024`，明文为
`BE32(0x14) + 20 字节对象 (02 01 10 00 + 16 字节密钥) + 0x80 填充`，
控制密钥为 `MD5(serial[0..11])`，MAC 为 DES-CBC + EDE。长度 17 与原库
一样返回 `SAR_INDATALENERR`。

注意：本实现**拒绝零长度密钥**（返回 `SAR_INDATALENERR`）。原库会接受
`SKF_ChangeDevAuthKey(dev, empty, 0)` 并把设备认证密钥写成 16 个 0 字节，
本轮测试设备正是因此被锁；这是有意的安全偏差。

当前设备状态：`00 82` 返回 `6983`，`SKF_DevAuth` 返回
`SAR_UNKNOWNERR`（与原库映射一致）。USB 端口复位和 root hub 重新绑定
不能清除锁定，需要物理重新上电、工厂复位或厂商恢复工具。

## 尚未完成

```text
设备生成私钥的标准信封导入（需要设备私钥解密命令）
SKF_CreateFile 非 SECURE_ANYONE_ACCOUNT 权限组合
SKF_GenRSAKeyPair 2048 位及对应签名/验签
SKF_ExportCertificate 动态缓冲（当前固定 512 字节）
SKF_ImportCertificate 失败时旧证书保留
SKF_ECCDecrypt（原库同样未导出）
静态警告清理（signedness、OpenSSL 3 弃用 API）
设备认证锁定恢复（物理重新上电/工厂复位/厂商工具）
```

标准 ECC/RSA 信封格式已经可以在“容器内含软件私钥”时导入；
设备生成、不可导出的私钥仍需继续反向 `80 56 03` / `80 52` / `80 53`
相关设备解密路径。

`SKF_ECCDecrypt` 原库未导出，`skf_all` 将其记为 MISSING，是预期结果。

## 协议要点

```text
USB             Mass Storage / SCSI Bulk-Only
SCSI CDB        0xC0 WRITE(16) / 0xC1 READ(16), 512-byte blocks
请求帧          "DEMO" + BE32(apdu_len) + 00000000 + 12345678 + APDU
响应帧          "DEMO" + BE32(data_len+2) + echo(4) + 87654321 + data + SW
状态优先响应    "DEMO" + 00000002 + echo(4) + 87654321 + SW + 0000 + BE32(len) + data
握手            "checking" + aa bb cc dd 11 22 33 44 -> 取反
PIN             00 84(8) + DES-CBC(serial/random) + 00 20(16)
设备信息        80 aa / 80 b7 / 80 b9
ECC             80 55 / 80 57 / 80 56 xx / 80 58
容器/文件       00 a4 / 00 b0 / 00 d6 / 80 e0 / 80 e4
```

更完整的协议记录见 [`PROTOCOL.md`](PROTOCOL.md)；ARM64/SDF 说明见
`ARM64.md`。
