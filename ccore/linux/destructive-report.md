# SKF destructive app/container test

Temporary names: app `SKFT1`, container `SKFC1`, file `SKFF1.TMP`

| Operation | Status | Return | Note |
| --- | --- | --- | --- |
| `SKF_EnumDev` | PASS | `0x00000000` (SAR_OK) | find device |
| `SKF_ConnectDev` | PASS | `0x00000000` (SAR_OK) | sdd1 |
| `SKF_EnumApplication` | PASS | `0x00000000` (SAR_OK) | before test |
| `SKF_CreateApplication` | SKIP | `0x0a00002d` (SAR_USER_NOT_LOGGED_IN) | needs device auth; using KEDA for the container test |
| `SKF_OpenApplication(KEDA)` | PASS | `0x00000000` (SAR_OK) | fallback for container test |
| `SKF_VerifyPIN(KEDA 123456)` | PASS | `0x00000000` (SAR_OK) | container test |
| `SKF_CreateContainer(KEDA)` | PASS | `0x00000000` (SAR_OK) | SKFC1 |
| `SKF_GetContainerType(KEDA temp)` | PASS | `0x00000000` (SAR_OK) | SKFC1 |
| `SKF_GenECCKeyPair(KEDA temp)` | PASS | `0x00000000` (SAR_OK) | tried SGD_SM2 and SGD_SM2_1 |
| `SKF_ECCSignData(after GenECC)` | PASS | `0x00000000` (SAR_OK) | temporary container |
| `SKF_ECCVerify(after GenECC)` | PASS | `0x00000000` (SAR_OK) | temporary container |
| `SKF_GenRSAKeyPair(KEDA temp)` | PASS | `0x00000000` (SAR_OK) | 1024-bit temporary key |
| `SKF_RSASignData(after GenRSA)` | PASS | `0x00000000` (SAR_OK) | temporary container |
| `SKF_RSAVerify(after GenRSA)` | PASS | `0x00000000` (SAR_OK) | temporary container |
| `SKF_RSAExportSessionKey(KEDA temp)` | PASS | `0x00000000` (SAR_OK) | RSA-wrapped SM4 session key |
| `SKF_CloseHandle(RSA session)` | PASS | `0x00000000` (SAR_OK) | cleanup |
| `SKF_ExtRSAPubKeyOperation(KEDA temp)` | PASS | `0x00000000` (SAR_OK) | RSA public-key operation |
| `SKF_GenExtRSAKey(KEDA temp)` | PASS | `0x00000000` (SAR_OK) | 1024-bit external RSA key |
| `SKF_ExtRSAPriKeyOperation(KEDA temp)` | PASS | `0x00000000` (SAR_OK) | RSA private-key operation |
| `SKF_CloseContainer(KEDA temp)` | PASS | `0x00000000` (SAR_OK) | SKFC1 |
| `SKF_DeleteContainer(KEDA temp)` | PASS | `0x00000000` (SAR_OK) | SKFC1 |
| `SKF_CloseApplication(KEDA)` | PASS | `0x00000000` (SAR_OK) | cleanup |
| `SKF_DisConnectDev` | PASS | `0x00000000` (SAR_OK) | cleanup |

## Result

- Failures: 0
