# SKF device authentication and temp app test

Device auth key: user-provided 16-byte value (not stored in this report).

| Operation | Status | Return | Note |
| --- | --- | --- | --- |
| `SKF_EnumDev` | PASS | `0x00000000` (SAR_OK) | find device |
| `SKF_ConnectDev` | PASS | `0x00000000` (SAR_OK) | sdd1 |
| `SKF_GetDevInfo` | PASS | `0x00000000` (SAR_OK) | read DevAuthAlgId |
| `SKF_GenRandom(8)` | PASS | `0x00000000` (SAR_OK) | device auth challenge |
| `SKF_SetSymmKey(devauth)` | PASS | `0x00000000` (SAR_OK) | DevAuthAlgId=0x101, SM1 ECB |
| `SKF_EncryptInit(devauth)` | PASS | `0x00000000` (SAR_OK) | ECB, no padding |
| `SKF_Encrypt(devauth)` | PASS | `0x00000000` (SAR_OK) | encrypt challenge |
| `SKF_DevAuth(wrapped challenge)` | PASS | `0x00000000` (SAR_OK) | device authentication |
| `SKF_CreateApplication` | PASS | `0x00000000` (SAR_OK) | SKFA5 |
| `SKF_CloseApplication(after create)` | PASS | `0x00000000` (SAR_OK) | SKFA5 |
| `SKF_OpenApplication(temp)` | PASS | `0x00000000` (SAR_OK) | SKFA5 |
| `SKF_VerifyPIN(temp 123456)` | PASS | `0x00000000` (SAR_OK) | temp app user PIN |
| `SKF_ChangePIN(temp 123456->654321)` | PASS | `0x00000000` (SAR_OK) | temp app only |
| `SKF_VerifyPIN(temp 654321)` | PASS | `0x00000000` (SAR_OK) | verify changed temp PIN |
| `SKF_ChangePIN(temp 654321->123456)` | PASS | `0x00000000` (SAR_OK) | restore temp PIN |
| `SKF_VerifyPIN(lock temp user PIN)` | PASS | `0x0a000025` (SAR_PIN_LOCKED) | 6 wrong attempts exhausted; PIN locked as expected |
| `SKF_UnblockPIN(temp)` | PASS | `0x00000000` (SAR_OK) | admin PIN 123456, new user PIN 123456 |
| `SKF_VerifyPIN(after unblock)` | PASS | `0x00000000` (SAR_OK) | temp user PIN restored |
| `SKF_CreateFile(temp)` | PASS | `0x00000000` (SAR_OK) | SKFF1.TMP |
| `SKF_WriteFile(temp)` | PASS | `0x00000000` (SAR_OK) | SKFF1.TMP |
| `SKF_ReadFile(temp)` | PASS | `0x00000000` (SAR_OK) | SKFF1.TMP |
| `SKF_GetFileInfo(temp)` | PASS | `0x00000000` (SAR_OK) | SKFF1.TMP |
| `SKF_DeleteFile(temp)` | PASS | `0x00000000` (SAR_OK) | SKFF1.TMP |
| `SKF_CreateContainer(temp)` | PASS | `0x00000000` (SAR_OK) | SKFC1 |
| `SKF_GetContainerType(temp)` | PASS | `0x00000000` (SAR_OK) | SKFC1 |
| `SKF_CloseContainer(temp)` | PASS | `0x00000000` (SAR_OK) | SKFC1 |
| `SKF_DeleteContainer(temp)` | PASS | `0x00000000` (SAR_OK) | SKFC1 |
| `SKF_CloseApplication(temp)` | PASS | `0x00000000` (SAR_OK) | SKFA5 |
| `SKF_DisConnectDev(before delete)` | PASS | `0x00000000` (SAR_OK) | reset application state |
| `SKF_ConnectDev(before delete)` | PASS | `0x00000000` (SAR_OK) | sdd1 |
| `SKF_DevAuth(before delete)` | PASS | `0x00000000` (SAR_OK) | re-authenticate after reconnect |
| `SKF_DeleteApplication(temp)` | PASS | `0x00000000` (SAR_OK) | SKFA5 |

## Result

- Failures: 0
