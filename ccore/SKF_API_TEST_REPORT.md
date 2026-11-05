# SKF 接口测试报告（含设备认证、应用/容器破坏性测试）

测试对象：**C*Core USB Key**，USB ID `02e3:0702`，产品字符串 `CCore USB CCID DEVICE`。
实际传输为 USB Mass Storage / vendor SCSI（`0xC0` 写、`0xC1` 读），不是标准 CCID。

- 测试日期：2026-10-30
- 测试库：`linux/lib/libskf.so`（C*Core 通用 SKF，438 KB）
- 测试程序：`linux/skf_all.c`（`dlopen` 动态加载）、`linux/skf_devauth.c`、`linux/skf_destructive.c`
- 运行用户：root（vendor SCSI 需要 `CAP_SYS_RAWIO`）
- 设备节点：`/dev/sdd`、`/dev/sdd1`、`/dev/sg3`

## 结论摘要

共覆盖 **79** 个 `skf.h` 中声明的国标接口（含条件编译的 `SKF_ECCDecrypt`）：

| 状态 | 数量 | 说明 |
| --- | ---: | --- |
| PASS | 65 | 调用成功，返回 `SAR_OK` |
| RET | 5 | 参数校验/不存在对象/设备不支持等预期错误 |
| SKIP | 8 | 为避免破坏设备或缺少私钥/协商方，未用有效参数执行 |
| MISSING | 1 | `SKF_ECCDecrypt` 可选接口未导出 |
| FAIL | 0 | 无 |

核心结论：

- **设备认证已打通**：16 字节设备密钥不能直接传给 `SKF_DevAuth`；厂商封装要求 challenge-response。按 `GenRandom(8)` → 补零到 16 字节 → 用 `DevAuthAlgId`（本设备为 `0x101`，SM1 ECB）加密 → 把 16 字节密文传给 `SKF_DevAuth`，返回 `SAR_OK`。
- 设备认证成功后，`SKF_CreateApplication` 成功；已在临时应用 `SKFA5` / `SKFALL1` 中完成 PIN 修改、PIN 锁定/解锁、文件创建/写入/读取/属性/删除、容器创建/查询/删除，最后删除临时应用，没有残留。
- `KEDA` 应用的 **USER PIN = `123456`**，已验证成功；`DEFAULT` 应用 USER PIN 只剩 **1 次**重试，未做任何尝试。
- 已在 KEDA 下实际创建/删除临时容器 `SKFC1`，并在临时容器中完成 ECC/RSA 密钥生成、签名/验签、RSA 会话密钥导出、RSA 公钥/私钥运算；容器删除成功，没有残留。
- `SKF_Transmit` 原始 APDU 通道返回 `SAR_NOTSUPPORTYETERR`，该固件不支持此接口。
- 设备认证密钥只在运行时通过参数/环境变量传入，未写入仓库或本报告。

## 设备信息（实测）

```text
Manufacturer     C*CORE
Issuer           XXXX
Label            UKEY
SerialNumber     3430483532044F43
Version          1.0
HWVersion        1.0
FirmwareVersion  1.24
TotalSpace       115680
FreeSpace        109440
MaxECCBufferSize 256
MaxBufferSize    59360
AlgSymCap        0x80000713
AlgAsymCap       0x30700
AlgHashCap       0x7
DevAuthAlgId     0x101  (SGD_SM1_ECB)
```

应用与容器（测试后）：

```text
DEFAULT
KEDA
  DEFAULT
  K01231-85422873-3457921
```

## 关键功能证据

### PIN

```text
KEDA/USER GetPINInfo max=6 remain=6 default=0
KEDA/USER VerifyPIN(123456) -> SAR_OK, retry=0
```

`DEFAULT/USER` 的 `remain=1`，不要尝试猜测。

### 设备认证（关键）

本设备的 `DEVINFO.DevAuthAlgId = 0x00000101`（`SGD_SM1_ECB`）。正确流程：

```text
SKF_GenRandom(hDev, challenge, 8)          -> SAR_OK
challenge[8..15] = 0
SKF_SetSymmKey(hDev, key, 0x101, &hKey)    -> SAR_OK
SKF_EncryptInit(hKey, ECB / no padding)    -> SAR_OK
SKF_Encrypt(hKey, challenge, 16, wrapped)  -> SAR_OK
SKF_DevAuth(hDev, wrapped, 16)             -> SAR_OK
```

线索来自 `win/ukeytool-新key/libkdssl-ext.dll` 中的 DevAuth 封装：日志字符串包括
`DevAuth -- SKF_GenRandom`、`SKF_SetSymmKey`、`SKF_EncryptInit`、`SKF_Encrypt`、
`SKF_DevAuth`、`DevAuthAlgId`；`SKF.dll` 中也有 `device_auth()` / `pbAuthData` 日志。

直接传明文密钥的失败记录（历史）：

```text
SKF_DevAuth("123456", 6)                    -> 0x0A000010 SAR_INDATALENERR
SKF_DevAuth("123456" + 10 个零字节, 16)      -> 0x0A000012 SAR_GENRANDERR
```

失败原因不是密钥错误，而是设备要的是 challenge 密文，不是明文密钥。按上述封装后认证成功。

### 证书与 ECC

```text
SKF_ExportCertificate  -> SAR_OK (sign certificate)
SKF_ExportPublicKey    -> SAR_OK (ECC public key)
SKF_ECCSignData        -> SAR_OK (SM2 sign of 32-byte test digest)
SKF_ECCVerify          -> SAR_OK
SKF_ExtECCVerify       -> SAR_OK
SKF_ExtECCEncrypt      -> SAR_OK
SKF_ECCExportSessionKey-> SAR_OK
```

### 对称、摘要、MAC

```text
SKF_SetSymmKey    -> SAR_OK (SM4)
SKF_EncryptInit   -> SAR_OK
SKF_Encrypt       -> SAR_OK
SKF_DecryptInit   -> SAR_OK
SKF_Decrypt       -> SAR_OK
SKF_EncryptUpdate -> SAR_OK
SKF_EncryptFinal  -> SAR_OK
SKF_DecryptUpdate -> SAR_OK
SKF_DecryptFinal  -> SAR_OK
SKF_MacInit       -> SAR_OK (SGD_SM4_MAC)
SKF_Mac           -> SAR_OK
SKF_MacUpdate     -> SAR_OK
SKF_MacFinal      -> SAR_OK
SKF_DigestInit    -> SAR_OK (SM3)
SKF_Digest        -> SAR_OK
SKF_DigestUpdate  -> SAR_OK
SKF_DigestFinal   -> SAR_OK
SKF_GenRandom     -> SAR_OK
```

## 临时应用/文件/容器测试（已授权）

临时应用：`SKFA5`（`skf_devauth`）、`SKFALL1`（`skf_all`）；临时文件 `SKFF1.TMP` / `SKFALL1.TMP`；临时容器 `SKFC1` / `SKFALL1.CTN`。

```text
SKF_CreateApplication          -> SAR_OK
SKF_OpenApplication            -> SAR_OK
SKF_VerifyPIN(USER 123456)     -> SAR_OK
SKF_ChangePIN(123456->654321)  -> SAR_OK
SKF_VerifyPIN(USER 654321)     -> SAR_OK
SKF_ChangePIN(654321->123456)  -> SAR_OK
6 次错误 USER PIN              -> SAR_PIN_LOCKED（预期）
SKF_UnblockPIN(admin 123456)   -> SAR_OK
SKF_VerifyPIN(USER 123456)     -> SAR_OK
SKF_CreateFile                 -> SAR_OK
SKF_WriteFile                  -> SAR_OK
SKF_ReadFile                   -> SAR_OK
SKF_GetFileInfo                -> SAR_OK
SKF_DeleteFile                 -> SAR_OK
SKF_CreateContainer            -> SAR_OK
SKF_GetContainerType           -> SAR_OK
SKF_CloseContainer             -> SAR_OK
SKF_DeleteContainer            -> SAR_OK
SKF_CloseApplication           -> SAR_OK
SKF_DevAuth（重新连接后）       -> SAR_OK
SKF_DeleteApplication          -> SAR_OK
```

测试后重新枚举确认应用列表恢复为 `DEFAULT`、`KEDA`，没有 `SKFA5` / `SKFALL1` 残留。
现有 KEDA 容器 `DEFAULT`、`K01231-85422873-3457921` 没有被修改。

## 临时容器密钥测试（已授权）

临时容器 `SKFC1`（KEDA 应用内）：

```text
SKF_CreateContainer          -> SAR_OK
SKF_GetContainerType         -> SAR_OK
SKF_GenECCKeyPair            -> SAR_OK (SGD_SM2)
SKF_ECCSignData              -> SAR_OK
SKF_ECCVerify                -> SAR_OK
SKF_GenRSAKeyPair            -> SAR_OK (1024-bit)
SKF_RSASignData              -> SAR_OK
SKF_RSAVerify                -> SAR_OK
SKF_RSAExportSessionKey      -> SAR_OK
SKF_ExtRSAPubKeyOperation    -> SAR_OK
SKF_GenExtRSAKey             -> SAR_OK (1024-bit external key)
SKF_ExtRSAPriKeyOperation    -> SAR_OK
SKF_CloseContainer           -> SAR_OK
SKF_DeleteContainer          -> SAR_OK
```

测试后已确认容器列表恢复为 `DEFAULT`、`K01231-85422873-3457921`，没有 `SKFC1` 残留。

## 完整接口结果

| 接口 | 状态 | 返回码 | 说明 |
| --- | --- | --- | --- |
| `SKF_CancelWaitForDevEvent` | PASS | `0x00000000` | no wait in progress |
| `SKF_ChangeDevAuthKey` | SKIP | `0x00000000` | destructive: would change the device auth key |
| `SKF_ChangePIN` | PASS | `0x00000000` | temporary application 123456 <-> 654321 |
| `SKF_ClearSecureState` | PASS | `0x00000000` | clear application secure state |
| `SKF_CloseApplication` | PASS | `0x00000000` | close application |
| `SKF_CloseContainer` | PASS | `0x00000000` | close container |
| `SKF_CloseHandle` | PASS | `0x00000000` | close stream hash handle |
| `SKF_ConnectDev` | PASS | `0x00000000` | sdd1 |
| `SKF_CreateApplication` | PASS | `0x00000000` | temporary application `SKFALL1` created |
| `SKF_CreateContainer` | PASS | `0x00000000` | temporary application container `SKFALL1.CTN` |
| `SKF_CreateFile` | PASS | `0x00000000` | temporary application file `SKFALL1.TMP` |
| `SKF_Decrypt` | PASS | `0x00000000` | one-shot decrypt |
| `SKF_DecryptFinal` | PASS | `0x00000000` | stream decrypt final |
| `SKF_DecryptInit` | PASS | `0x00000000` | stream decrypt init |
| `SKF_DecryptUpdate` | PASS | `0x00000000` | stream decrypt update |
| `SKF_DeleteApplication` | PASS | `0x00000000` | temporary application `SKFALL1` deleted |
| `SKF_DeleteContainer` | PASS | `0x00000000` | temporary application container `SKFALL1.CTN` |
| `SKF_DeleteFile` | PASS | `0x00000000` | temporary application file `SKFALL1.TMP` |
| `SKF_DevAuth` | PASS | `0x00000000` | wrapped challenge; `DevAuthAlgId=0x101` (SM1 ECB); `SAR_OK` |
| `SKF_Digest` | PASS | `0x00000000` | one-shot SM3 digest |
| `SKF_DigestFinal` | PASS | `0x00000000` | stream digest final |
| `SKF_DigestInit` | PASS | `0x00000000` | SM3 digest init |
| `SKF_DigestUpdate` | PASS | `0x00000000` | stream digest update |
| `SKF_DisConnectDev` | PASS | `0x00000000` | disconnect device |
| `SKF_ECCDecrypt` | MISSING | `0x00000000` | dlsym failed |
| `SKF_ECCExportSessionKey` | PASS | `0x00000000` | export SM4 session key encrypted to ECC public key |
| `SKF_ECCSignData` | PASS | `0x00000000` | SM2 sign of 32-byte test digest |
| `SKF_ECCVerify` | PASS | `0x00000000` | verify with exported ECC public key |
| `SKF_Encrypt` | PASS | `0x00000000` | one-shot encrypt |
| `SKF_EncryptFinal` | PASS | `0x00000000` | stream encrypt final |
| `SKF_EncryptInit` | PASS | `0x00000000` | stream encrypt init |
| `SKF_EncryptUpdate` | PASS | `0x00000000` | stream encrypt update |
| `SKF_EnumApplication` | PASS | `0x00000000` | list applications |
| `SKF_EnumContainer` | PASS | `0x00000000` | list containers |
| `SKF_EnumDev` | PASS | `0x00000000` | enumerate present devices |
| `SKF_EnumFiles` | PASS | `0x00000000` | list files in app |
| `SKF_ExportCertificate` | PASS | `0x00000000` | sign certificate export |
| `SKF_ExportPublicKey` | PASS | `0x00000000` | sign public key export |
| `SKF_ExtECCDecrypt` | SKIP | `0x00000000` | requires an ECC private key blob |
| `SKF_ExtECCEncrypt` | PASS | `0x00000000` | ECC public-key encryption of 16-byte test block |
| `SKF_ExtECCSign` | SKIP | `0x00000000` | requires an ECC private key blob |
| `SKF_ExtECCVerify` | PASS | `0x00000000` | ext verify with exported ECC public key |
| `SKF_ExtRSAPriKeyOperation` | PASS | `0x00000000` | temporary external RSA private-key operation |
| `SKF_ExtRSAPubKeyOperation` | PASS | `0x00000000` | temporary container; 128-byte input |
| `SKF_GenECCKeyPair` | PASS | `0x00000000` | temporary container; `SGD_SM2` accepted |
| `SKF_GenExtRSAKey` | PASS | `0x00000000` | temporary external 1024-bit RSA key |
| `SKF_GenRSAKeyPair` | PASS | `0x00000000` | temporary container; 1024-bit |
| `SKF_GenRandom` | PASS | `0x00000000` | 16 random bytes |
| `SKF_GenerateAgreementDataAndKeyWithECC` | SKIP | `0x00000000` | requires a sponsor private key |
| `SKF_GenerateAgreementDataWithECC` | SKIP | `0x00000000` | requires a container private key |
| `SKF_GenerateKeyWithECC` | SKIP | `0x00000000` | requires an agreement handle |
| `SKF_GetContainerType` | PASS | `0x00000000` | SKFALL1.CTN |
| `SKF_GetDevInfo` | PASS | `0x00000000` | device information |
| `SKF_GetDevState` | PASS | `0x00000000` | sdd1 |
| `SKF_GetFileInfo` | PASS | `0x00000000` | temporary application file `SKFALL1.TMP` |
| `SKF_GetPINInfo` | PASS | `0x00000000` | KEDA USER PIN info |
| `SKF_ImportCertificate` | RET | `0x0a000011` | empty certificate; expected parameter error |
| `SKF_ImportECCKeyPair` | RET | `0x0a000006` | NULL enveloped key; expected parameter error |
| `SKF_ImportRSAKeyPair` | RET | `0x0a000006` | empty wrapped key; expected parameter error |
| `SKF_ImportSessionKey` | RET | `0x0a000006` | empty session key; expected parameter error |
| `SKF_LockDev` | PASS | `0x00000000` | lock device for 1 second |
| `SKF_Mac` | PASS | `0x00000000` | one-shot MAC |
| `SKF_MacFinal` | PASS | `0x00000000` | stream MAC final |
| `SKF_MacInit` | PASS | `0x00000000` | SM4 MAC key/init |
| `SKF_MacUpdate` | PASS | `0x00000000` | stream MAC update |
| `SKF_OpenApplication` | PASS | `0x00000000` | SKFALL1 |
| `SKF_OpenContainer` | PASS | `0x00000000` | K01231-85422873-3457921 |
| `SKF_RSAExportSessionKey` | PASS | `0x00000000` | temporary container; RSA-wrapped SM4 |
| `SKF_RSASignData` | PASS | `0x00000000` | temporary container after RSA keygen |
| `SKF_RSAVerify` | PASS | `0x00000000` | temporary container after RSA keygen |
| `SKF_ReadFile` | PASS | `0x00000000` | temporary application file `SKFALL1.TMP` |
| `SKF_SetLabel` | SKIP | `0x00000000` | would modify the device label |
| `SKF_SetSymmKey` | PASS | `0x00000000` | SM4 ECB key |
| `SKF_Transmit` | RET | `0x0a000003` | SELECT MF APDU |
| `SKF_UnblockPIN` | PASS | `0x00000000` | temporary application; admin PIN 123456 |
| `SKF_UnlockDev` | PASS | `0x00000000` | unlock device |
| `SKF_VerifyPIN` | PASS | `0x00000000` | temporary application USER PIN 123456 |
| `SKF_WaitForDevEvent` | SKIP | `0x00000000` | would block waiting for a hotplug event |
| `SKF_WriteFile` | PASS | `0x00000000` | temporary application file `SKFALL1.TMP` |

## 未执行/限制说明

### 预期错误（RET）

- `SKF_Transmit`：`SAR_NOTSUPPORTYETERR`，该固件不支持原始 APDU 透传。
- `SKF_ImportCertificate` / `SKF_ImportECCKeyPair` / `SKF_ImportRSAKeyPair` / `SKF_ImportSessionKey`：空/NULL 数据参数校验，返回 `SAR_INDATAERR` / `SAR_INVALIDPARAMERR`，未写入数据。

### 未执行（SKIP）

- `SKF_SetLabel`：会修改设备标签，未执行。
- `SKF_WaitForDevEvent`：会阻塞等待热插拔事件，未执行。
- `SKF_ChangeDevAuthKey`：会修改设备认证密钥，风险高，未执行。
- `SKF_ExtECCSign` / `SKF_ExtECCDecrypt`：需要 ECC 私钥 blob；标准接口不导出容器私钥，无法构造有效参数。
- `SKF_GenerateAgreementDataWithECC` / `SKF_GenerateAgreementDataAndKeyWithECC` / `SKF_GenerateKeyWithECC`：需要容器私钥和协商方/协商句柄，未构造完整协商流程。

### 未导出（MISSING）

- `SKF_ECCDecrypt`：由 `SKF_HAS_ECCDECRYPT` 条件编译控制，当前库未导出，属于可选接口。

## 复现

```bash
cd ~/code/ukey/ccore/linux
make

# 全接口测试（设备认证密钥通过环境变量传入，不写入仓库）
sudo env SKF_DEVAUTH_KEY='<16-byte-device-key>' ./skf_all ./lib/libskf.so

# 设备认证 + 临时应用/文件/容器测试
sudo env LD_LIBRARY_PATH="$PWD/lib" ./skf_devauth '<16-byte-device-key>' SKFA5

# 临时容器 ECC/RSA/外部 RSA 测试
sudo env LD_LIBRARY_PATH="$PWD/lib" ./skf_destructive
```

`skf_all` 生成 `linux/report.md`；`skf_devauth` 生成 `linux/devauth-report.md`；`skf_destructive` 生成 `linux/destructive-report.md`。

## 安全说明

- 未执行 `format_tool_usb_ms.exe`，未清空/重初始化 UKey。
- 未尝试 `DEFAULT` 的 PIN，未修改现有 KEDA 应用的 PIN；只在临时应用中修改/锁定/解锁 PIN。
- 临时应用、临时文件、临时容器均已删除；测试后重新枚举确认无残留。
- 设备认证密钥只在运行时通过参数/环境变量传入，未写入仓库或本报告。
- 未执行 `SKF_ChangeDevAuthKey`，设备认证密钥未被修改。
