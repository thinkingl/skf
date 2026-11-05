# SKF API test report

- Date: 2026-10-30
- Library: `./reimpl/libskf_native.so`
- Device: C*Core USB Key `02e3:0702`

| Interface | Status | Return | Note |
| --- | --- | --- | --- |
| `SKF_EnumDev` | PASS | 0x00000000 | enumerate present devices |
| `SKF_ConnectDev` | PASS | 0x00000000 | sdd1 |
| `SKF_GetDevState` | PASS | 0x00000000 | sdd1 |
| `SKF_GetDevInfo` | PASS | 0x00000000 | device information |

## Device information

- Manufacturer: `C*CORE`
- Issuer: `XXXX`
- Label: `UKEY`
- Serial: `3430483532044F43`
- Version: 1.0, HW 1.0, FW 1.24
- Sym/Alg caps: 0x80000713 / 0x30700 / 0x7
- Space: 115680 total, 108480 free

| `SKF_SetLabel` | SKIP | 0x00000000 | would modify the device label |
| `SKF_CancelWaitForDevEvent` | PASS | 0x00000000 | no wait in progress |
| `SKF_WaitForDevEvent` | SKIP | 0x00000000 | would block waiting for a hotplug event |
| `SKF_Transmit` | RET | 0x0a000003 | SELECT MF APDU |
| `SKF_ChangeDevAuthKey` | SKIP | 0x00000000 | destructive: would change the device auth key |
| `SKF_DevAuth` | SKIP | 0x00000000 | set SKF_DEVAUTH_KEY to a 16-byte key to test |
| `SKF_ChangePIN` | SKIP | 0x00000000 | destructive and can consume PIN retries |
| `SKF_UnblockPIN` | SKIP | 0x00000000 | destructive and can change PIN state |
| `SKF_EnumApplication` | PASS | 0x00000000 | list applications |
| `SKF_OpenApplication` | PASS | 0x00000000 | KEDA |
| `SKF_GetPINInfo` | PASS | 0x00000000 | KEDA USER PIN info |
| `SKF_VerifyPIN` | PASS | 0x00000000 | KEDA USER PIN 123456 |
| `SKF_CreateApplication` | SKIP | 0x00000000 | destructive: would create a new application |
| `SKF_DeleteApplication` | RET | 0x0a000031 | nonexistent app; expected error |
| `SKF_CreateFile` | SKIP | 0x00000000 | destructive: would create a file |
| `SKF_CreateContainer` | SKIP | 0x00000000 | destructive: would create a container |
| `SKF_EnumFiles` | PASS | 0x00000000 | list files in app |
| `SKF_GetFileInfo` | RET | 0x0a000031 | nonexistent file; expected error |
| `SKF_ReadFile` | RET | 0x0a000031 | nonexistent file; expected error |
| `SKF_WriteFile` | RET | 0x0a000031 | nonexistent file; expected error |
| `SKF_DeleteFile` | RET | 0x0a000031 | nonexistent file; expected error |
| `SKF_EnumContainer` | PASS | 0x00000000 | list containers |
| `SKF_DeleteContainer` | RET | 0x0a000031 | nonexistent container; expected error |
| `SKF_OpenContainer` | PASS | 0x00000000 | K01231-85422873-3457921 |
| `SKF_GetContainerType` | PASS | 0x00000000 | container type |
| `SKF_ExportCertificate` | PASS | 0x00000000 | sign certificate export |
| `SKF_ExportPublicKey` | PASS | 0x00000000 | sign public key export |
| `SKF_ECCSignData` | PASS | 0x00000000 | SM2 sign of 32-byte test digest |
| `SKF_ECCVerify` | PASS | 0x00000000 | verify with exported ECC public key |
| `SKF_ExtECCVerify` | PASS | 0x00000000 | ext verify with exported ECC public key |
| `SKF_ExtECCEncrypt` | PASS | 0x00000000 | ECC public-key encryption of 16-byte test block |
| `SKF_ECCExportSessionKey` | PASS | 0x00000000 | export SM4 session key encrypted to ECC public key |
| `SKF_CloseHandle` | PASS | 0x00000000 | close session key handle |
| `SKF_RSASignData` | RET | 0x0a000002 | RSA sign (if RSA key exists) |
| `SKF_RSAVerify` | SKIP | 0x00000000 | container has ECC public key |
| `SKF_ImportCertificate` | RET | 0x0a000011 | empty certificate; expected parameter error |
| `SKF_ImportECCKeyPair` | RET | 0x0a000006 | NULL enveloped key; expected parameter error |
| `SKF_ImportRSAKeyPair` | RET | 0x0a000006 | empty wrapped key; expected parameter error |
| `SKF_ImportSessionKey` | RET | 0x0a000006 | empty session key; expected parameter error |
| `SKF_GenRSAKeyPair` | SKIP | 0x00000000 | destructive: would generate a key pair |
| `SKF_GenECCKeyPair` | SKIP | 0x00000000 | destructive: would generate a key pair |
| `SKF_GenExtRSAKey` | SKIP | 0x00000000 | destructive: would generate an external RSA key |
| `SKF_RSAExportSessionKey` | SKIP | 0x00000000 | requires a valid RSA public key |
| `SKF_ExtRSAPubKeyOperation` | SKIP | 0x00000000 | requires an RSA public key blob |
| `SKF_ExtRSAPriKeyOperation` | SKIP | 0x00000000 | requires an RSA private key blob |
| `SKF_ExtECCDecrypt` | SKIP | 0x00000000 | requires an ECC private key blob |
| `SKF_ExtECCSign` | SKIP | 0x00000000 | requires an ECC private key blob |
| `SKF_GenerateAgreementDataWithECC` | SKIP | 0x00000000 | requires a container private key |
| `SKF_GenerateAgreementDataAndKeyWithECC` | SKIP | 0x00000000 | requires a sponsor private key |
| `SKF_GenerateKeyWithECC` | SKIP | 0x00000000 | requires an agreement handle |
| `SKF_ECCDecrypt` | MISSING | 0x00000000 | dlsym failed |
| `SKF_CloseContainer` | PASS | 0x00000000 | close container |
| `SKF_SetSymmKey` | PASS | 0x00000000 | SM4 ECB key |
| `SKF_EncryptInit` | PASS | 0x00000000 | SM4 ECB encrypt init |
| `SKF_Encrypt` | PASS | 0x00000000 | one-shot encrypt |
| `SKF_DecryptInit` | PASS | 0x00000000 | SM4 ECB decrypt init |
| `SKF_Decrypt` | PASS | 0x00000000 | one-shot decrypt |
| `SKF_EncryptInit` | PASS | 0x00000000 | stream encrypt init |
| `SKF_EncryptUpdate` | PASS | 0x00000000 | stream encrypt update |
| `SKF_EncryptFinal` | PASS | 0x00000000 | stream encrypt final |
| `SKF_DecryptInit` | PASS | 0x00000000 | stream decrypt init |
| `SKF_DecryptUpdate` | PASS | 0x00000000 | stream decrypt update |
| `SKF_DecryptFinal` | PASS | 0x00000000 | stream decrypt final |
| `SKF_MacInit` | PASS | 0x00000000 | SM4 MAC key/init |
| `SKF_Mac` | PASS | 0x00000000 | one-shot MAC |
| `SKF_CloseHandle` | PASS | 0x00000000 | close MAC handle |
| `SKF_MacUpdate` | PASS | 0x00000000 | stream MAC update |
| `SKF_MacFinal` | PASS | 0x00000000 | stream MAC final |
| `SKF_CloseHandle` | PASS | 0x00000000 | close stream MAC handle |
| `SKF_CloseHandle` | PASS | 0x00000000 | close MAC key handle |
| `SKF_CloseHandle` | PASS | 0x00000000 | close symmetric key handle |
| `SKF_DigestInit` | PASS | 0x00000000 | SM3 digest init |
| `SKF_Digest` | PASS | 0x00000000 | one-shot SM3 digest |
| `SKF_CloseHandle` | PASS | 0x00000000 | close hash handle |
| `SKF_DigestUpdate` | PASS | 0x00000000 | stream digest update |
| `SKF_DigestFinal` | PASS | 0x00000000 | stream digest final |
| `SKF_CloseHandle` | PASS | 0x00000000 | close stream hash handle |
| `SKF_GenRandom` | PASS | 0x00000000 | 16 random bytes |
| `SKF_LockDev` | PASS | 0x00000000 | lock device for 1 second |
| `SKF_UnlockDev` | PASS | 0x00000000 | unlock device |
| `SKF_ClearSecureState` | PASS | 0x00000000 | clear application secure state |
| `SKF_CloseApplication` | PASS | 0x00000000 | close application |
| `SKF_DisConnectDev` | PASS | 0x00000000 | disconnect device |

## Summary

- PASS: 45
- Returned error (RET): 12
- Skipped: 21
- Missing symbols: 1
- Not run: 0

Device authentication was not performed (SKF_DEVAUTH_KEY unset). Destructive operations (create/delete application, file, container, change PIN, generate key pair, import key, change auth key) were not executed with valid parameters; where safe, parameter-validation was exercised.
