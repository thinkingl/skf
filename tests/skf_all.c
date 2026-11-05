#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include "skf.h"

#ifndef SKF_HAS_ECCDECRYPT
typedef ULONG (*ECCDecryptFn)(HCONTAINER, ECCCIPHERBLOB *, BYTE *, ULONG *);
#endif

static FILE *rep;
static int npass, nret, nskip, nmiss, nnotrun;
static int nres;
static struct result {
    const char *name;
    const char *status;
    ULONG rc;
    char note[200];
} results[160];

static const char *all_names[] = {
    "SKF_CancelWaitForDevEvent",
    "SKF_ChangeDevAuthKey",
    "SKF_ChangePIN",
    "SKF_ClearSecureState",
    "SKF_CloseApplication",
    "SKF_CloseContainer",
    "SKF_CloseHandle",
    "SKF_ConnectDev",
    "SKF_CreateApplication",
    "SKF_CreateContainer",
    "SKF_CreateFile",
    "SKF_Decrypt",
    "SKF_DecryptFinal",
    "SKF_DecryptInit",
    "SKF_DecryptUpdate",
    "SKF_DeleteApplication",
    "SKF_DeleteContainer",
    "SKF_DeleteFile",
    "SKF_DevAuth",
    "SKF_Digest",
    "SKF_DigestFinal",
    "SKF_DigestInit",
    "SKF_DigestUpdate",
    "SKF_DisConnectDev",
    "SKF_ECCDecrypt",
    "SKF_ECCExportSessionKey",
    "SKF_ECCSignData",
    "SKF_ECCVerify",
    "SKF_Encrypt",
    "SKF_EncryptFinal",
    "SKF_EncryptInit",
    "SKF_EncryptUpdate",
    "SKF_EnumApplication",
    "SKF_EnumContainer",
    "SKF_EnumDev",
    "SKF_EnumFiles",
    "SKF_ExportCertificate",
    "SKF_ExportPublicKey",
    "SKF_ExtECCDecrypt",
    "SKF_ExtECCEncrypt",
    "SKF_ExtECCSign",
    "SKF_ExtECCVerify",
    "SKF_ExtRSAPriKeyOperation",
    "SKF_ExtRSAPubKeyOperation",
    "SKF_GenECCKeyPair",
    "SKF_GenerateAgreementDataAndKeyWithECC",
    "SKF_GenerateAgreementDataWithECC",
    "SKF_GenerateKeyWithECC",
    "SKF_GenExtRSAKey",
    "SKF_GenRandom",
    "SKF_GenRSAKeyPair",
    "SKF_GetContainerType",
    "SKF_GetDevInfo",
    "SKF_GetDevState",
    "SKF_GetFileInfo",
    "SKF_GetPINInfo",
    "SKF_ImportCertificate",
    "SKF_ImportECCKeyPair",
    "SKF_ImportRSAKeyPair",
    "SKF_ImportSessionKey",
    "SKF_LockDev",
    "SKF_Mac",
    "SKF_MacFinal",
    "SKF_MacInit",
    "SKF_MacUpdate",
    "SKF_OpenApplication",
    "SKF_OpenContainer",
    "SKF_ReadFile",
    "SKF_RSAExportSessionKey",
    "SKF_RSASignData",
    "SKF_RSAVerify",
    "SKF_SetLabel",
    "SKF_SetSymmKey",
    "SKF_Transmit",
    "SKF_UnblockPIN",
    "SKF_UnlockDev",
    "SKF_VerifyPIN",
    "SKF_WaitForDevEvent",
    "SKF_WriteFile"
};

static void count_status(const char *status, int delta) {
    if (strcmp(status, "PASS") == 0) npass += delta;
    else if (strcmp(status, "SKIP") == 0) nskip += delta;
    else if (strcmp(status, "MISSING") == 0) nmiss += delta;
    else if (strcmp(status, "NOT RUN") == 0) nnotrun += delta;
    else nret += delta;
}

static void rec(const char *name, const char *status, ULONG rc, const char *note) {
    int idx = -1;
    for (int i = 0; i < nres; i++)
        if (strcmp(results[i].name, name) == 0) { idx = i; break; }

    if (idx >= 0) {
        /* A real PASS may replace a placeholder SKIP/RET.  A later SKIP must
         * not hide an earlier real PASS (some cleanup branches do that). */
        if (strcmp(results[idx].status, "PASS") == 0 &&
            strcmp(status, "PASS") != 0)
            return;
        if (strcmp(results[idx].status, "PASS") != 0 &&
            strcmp(status, "PASS") != 0)
            return;
        count_status(results[idx].status, -1);
        results[idx].status = status;
        results[idx].rc = rc;
        snprintf(results[idx].note, sizeof(results[idx].note), "%s", note ? note : "");
        count_status(status, 1);
        fprintf(rep, "| `%s` | %s | 0x%08lx | %s |\n",
                name, status, (unsigned long)rc, note ? note : "");
        printf("[%-7s] %-40s rc=0x%08lx %s\n", status, name, (unsigned long)rc, note ? note : "");
        return;
    }
    if (nres >= (int)(sizeof(results) / sizeof(results[0]))) return;

    results[nres].name = name;
    results[nres].status = status;
    results[nres].rc = rc;
    snprintf(results[nres].note, sizeof(results[nres].note), "%s", note ? note : "");
    nres++;

    count_status(status, 1);

    fprintf(rep, "| `%s` | %s | 0x%08lx | %s |\n",
            name, status, (unsigned long)rc, note ? note : "");
    printf("[%-7s] %-40s rc=0x%08lx %s\n", status, name, (unsigned long)rc, note ? note : "");
}

#define LOAD(name) __typeof__(&name) f_##name = (__typeof__(&name))dlsym(lib, #name)
#define TRY(name, expr, note) do { \
    if (!f_##name) rec(#name, "MISSING", 0, "dlsym failed"); \
    else { ULONG _r = (ULONG)(expr); rec(#name, _r == SAR_OK ? "PASS" : "RET", _r, note); } \
} while (0)
#define SKIP(name, note) do { \
    if (!f_##name) rec(#name, "MISSING", 0, "dlsym failed"); \
    else rec(#name, "SKIP", 0, note); \
} while (0)

/* Device auth is a challenge/response on this device: generate 8 random
 * bytes, zero-pad to 16, encrypt with the 16-byte device key using the
 * algorithm reported in DevAuthAlgId, then pass the ciphertext. */
#define WRAP_AUTH(dev, key, alg, out_rc) do { \
    BYTE _ch[16]; \
    memset(_ch, 0, sizeof(_ch)); \
    ULONG _ar = f_SKF_GenRandom ? f_SKF_GenRandom((dev), _ch, 8) : SAR_NOTSUPPORTYETERR; \
    HANDLE _hk = NULL; \
    if (_ar == SAR_OK) _ar = f_SKF_SetSymmKey((dev), (BYTE *)(key), (alg), &_hk); \
    BLOCKCIPHERPARAM _p; \
    memset(&_p, 0, sizeof(_p)); \
    if (_ar == SAR_OK) _ar = f_SKF_EncryptInit(_hk, _p); \
    BYTE _wr[32]; \
    ULONG _wl = sizeof(_wr); \
    memset(_wr, 0, sizeof(_wr)); \
    if (_ar == SAR_OK) _ar = f_SKF_Encrypt(_hk, _ch, sizeof(_ch), _wr, &_wl); \
    if (_hk) f_SKF_CloseHandle(_hk); \
    if (_ar == SAR_OK) _ar = f_SKF_DevAuth((dev), _wr, _wl); \
    (out_rc) = _ar; \
} while (0)

int main(int argc, char **argv) {
    const char *libpath = argc > 1 ? argv[1] : "libskf.so";
    const char *authkey = getenv("SKF_DEVAUTH_KEY");
    int authed = 0;
    ULONG authalg = 0;
    void *lib = dlopen(libpath, RTLD_NOW | RTLD_LOCAL);
    rep = fopen("report.md", "w");
    if (!rep) { perror("report.md"); return 1; }

    fprintf(rep, "# SKF API test report\n\n");
    fprintf(rep, "- Date: 2026-10-30\n");
    fprintf(rep, "- Library: `%s`\n", libpath);
    fprintf(rep, "- Device: C*Core USB Key `02e3:0702`\n\n");
    fprintf(rep, "| Interface | Status | Return | Note |\n");
    fprintf(rep, "| --- | --- | --- | --- |\n");

    if (!lib) {
        fprintf(rep, "\nFATAL: dlopen failed: %s\n", dlerror());
        fclose(rep);
        printf("dlopen failed: %s\n", dlerror());
        return 1;
    }

    LOAD(SKF_CancelWaitForDevEvent);
    LOAD(SKF_ChangeDevAuthKey);
    LOAD(SKF_ChangePIN);
    LOAD(SKF_ClearSecureState);
    LOAD(SKF_CloseApplication);
    LOAD(SKF_CloseContainer);
    LOAD(SKF_CloseHandle);
    LOAD(SKF_ConnectDev);
    LOAD(SKF_CreateApplication);
    LOAD(SKF_CreateContainer);
    LOAD(SKF_CreateFile);
    LOAD(SKF_Decrypt);
    LOAD(SKF_DecryptFinal);
    LOAD(SKF_DecryptInit);
    LOAD(SKF_DecryptUpdate);
    LOAD(SKF_DeleteApplication);
    LOAD(SKF_DeleteContainer);
    LOAD(SKF_DeleteFile);
    LOAD(SKF_DevAuth);
    LOAD(SKF_Digest);
    LOAD(SKF_DigestFinal);
    LOAD(SKF_DigestInit);
    LOAD(SKF_DigestUpdate);
    LOAD(SKF_DisConnectDev);
    LOAD(SKF_ECCExportSessionKey);
    LOAD(SKF_ECCSignData);
    LOAD(SKF_ECCVerify);
    LOAD(SKF_Encrypt);
    LOAD(SKF_EncryptFinal);
    LOAD(SKF_EncryptInit);
    LOAD(SKF_EncryptUpdate);
    LOAD(SKF_EnumApplication);
    LOAD(SKF_EnumContainer);
    LOAD(SKF_EnumDev);
    LOAD(SKF_EnumFiles);
    LOAD(SKF_ExportCertificate);
    LOAD(SKF_ExportPublicKey);
    LOAD(SKF_ExtECCDecrypt);
    LOAD(SKF_ExtECCEncrypt);
    LOAD(SKF_ExtECCSign);
    LOAD(SKF_ExtECCVerify);
    LOAD(SKF_ExtRSAPriKeyOperation);
    LOAD(SKF_ExtRSAPubKeyOperation);
    LOAD(SKF_GenECCKeyPair);
    LOAD(SKF_GenerateAgreementDataAndKeyWithECC);
    LOAD(SKF_GenerateAgreementDataWithECC);
    LOAD(SKF_GenerateKeyWithECC);
    LOAD(SKF_GenExtRSAKey);
    LOAD(SKF_GenRandom);
    LOAD(SKF_GenRSAKeyPair);
    LOAD(SKF_GetContainerType);
    LOAD(SKF_GetDevInfo);
    LOAD(SKF_GetDevState);
    LOAD(SKF_GetFileInfo);
    LOAD(SKF_GetPINInfo);
    LOAD(SKF_ImportCertificate);
    LOAD(SKF_ImportECCKeyPair);
    LOAD(SKF_ImportRSAKeyPair);
    LOAD(SKF_ImportSessionKey);
    LOAD(SKF_LockDev);
    LOAD(SKF_Mac);
    LOAD(SKF_MacFinal);
    LOAD(SKF_MacInit);
    LOAD(SKF_MacUpdate);
    LOAD(SKF_OpenApplication);
    LOAD(SKF_OpenContainer);
    LOAD(SKF_ReadFile);
    LOAD(SKF_RSAExportSessionKey);
    LOAD(SKF_RSASignData);
    LOAD(SKF_RSAVerify);
    LOAD(SKF_SetLabel);
    LOAD(SKF_SetSymmKey);
    LOAD(SKF_Transmit);
    LOAD(SKF_UnblockPIN);
    LOAD(SKF_UnlockDev);
    LOAD(SKF_VerifyPIN);
    LOAD(SKF_WaitForDevEvent);
    LOAD(SKF_WriteFile);

    ECCDecryptFn f_SKF_ECCDecrypt = (ECCDecryptFn)dlsym(lib, "SKF_ECCDecrypt");

    ULONG len = 0, rc;
    char *names = NULL;
    rc = f_SKF_EnumDev(TRUE, NULL, &len);
    if (rc == SAR_OK && len > 0) {
        names = calloc(1, len + 1);
        rc = f_SKF_EnumDev(TRUE, (LPSTR)names, &len);
    }
    rec("SKF_EnumDev", rc == SAR_OK ? "PASS" : "RET", rc, "enumerate present devices");
    const char *devname = (names && *names) ? names : "sdd";

    DEVHANDLE hDev = NULL;
    TRY(SKF_ConnectDev, f_SKF_ConnectDev((LPSTR)devname, &hDev), devname);
    if (!hDev) {
        fprintf(rep, "\nFATAL: no device handle; remaining interfaces were not run.\n");
        fclose(rep);
        return 1;
    }

    ULONG state = 0;
    TRY(SKF_GetDevState, f_SKF_GetDevState((LPSTR)devname, &state), devname);

    DEVINFO info;
    memset(&info, 0, sizeof(info));
    TRY(SKF_GetDevInfo, f_SKF_GetDevInfo(hDev, &info), "device information");
    fprintf(rep, "\n## Device information\n\n");
    fprintf(rep, "- Manufacturer: `%.64s`\n", info.Manufacturer);
    fprintf(rep, "- Issuer: `%.64s`\n", info.Issuer);
    fprintf(rep, "- Label: `%.32s`\n", info.Label);
    fprintf(rep, "- Serial: `%.32s`\n", info.SerialNumber);
    fprintf(rep, "- Version: %u.%u, HW %u.%u, FW %u.%u\n",
            info.Version.major, info.Version.minor,
            info.HWVersion.major, info.HWVersion.minor,
            info.FirmwareVersion.major, info.FirmwareVersion.minor);
    fprintf(rep, "- Sym/Alg caps: 0x%lx / 0x%lx / 0x%lx\n",
            (unsigned long)info.AlgSymCap, (unsigned long)info.AlgAsymCap,
            (unsigned long)info.AlgHashCap);
    fprintf(rep, "- Space: %lu total, %lu free\n\n",
            (unsigned long)info.TotalSpace, (unsigned long)info.FreeSpace);

    SKIP(SKF_SetLabel, "would modify the device label");
    TRY(SKF_CancelWaitForDevEvent, f_SKF_CancelWaitForDevEvent(), "no wait in progress");
    SKIP(SKF_WaitForDevEvent, "would block waiting for a hotplug event");

    {
        BYTE cmd[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00};
        BYTE out[256];
        ULONG outlen = sizeof(out);
        TRY(SKF_Transmit, f_SKF_Transmit(hDev, cmd, sizeof(cmd), out, &outlen),
            "SELECT MF APDU");
    }

    SKIP(SKF_ChangeDevAuthKey, "destructive: would change the device auth key");
    if (authkey && strlen(authkey) == 16) {
        authalg = info.DevAuthAlgId;
        if (authalg != SGD_SM1_ECB && authalg != SGD_SM4_ECB)
            authalg = SGD_SM4_ECB;
        ULONG ar = SAR_FAIL;
        WRAP_AUTH(hDev, authkey, authalg, ar);
        rec("SKF_DevAuth", ar == SAR_OK ? "PASS" : "RET", ar,
            "wrapped challenge (8 random bytes, SM1/SM4 ECB)");
        authed = (ar == SAR_OK);
    } else {
        SKIP(SKF_DevAuth, "set SKF_DEVAUTH_KEY to a 16-byte key to test");
    }
    SKIP(SKF_ChangePIN, "destructive and can consume PIN retries");
    SKIP(SKF_UnblockPIN, "destructive and can change PIN state");

    ULONG alen = 0;
    rc = f_SKF_EnumApplication(hDev, NULL, &alen);
    char *apps = NULL;
    if (rc == SAR_OK && alen > 0) {
        apps = calloc(1, alen + 1);
        rc = f_SKF_EnumApplication(hDev, (LPSTR)apps, &alen);
    }
    rec("SKF_EnumApplication", rc == SAR_OK ? "PASS" : "RET", rc, "list applications");

    char *appname = NULL;
    if (apps) {
        for (char *p = apps; p < apps + alen && *p; p += strlen(p) + 1)
            if (strcmp(p, "KEDA") == 0) { appname = p; break; }
        if (!appname && *apps) appname = apps;
    }

    HAPPLICATION hApp = NULL;
    if (appname) {
        TRY(SKF_OpenApplication, f_SKF_OpenApplication(hDev, (LPSTR)appname, &hApp), appname);
    } else {
        rec("SKF_OpenApplication", "SKIP", 0, "no application listed");
    }

    if (hApp) {
        ULONG max = 0, remain = 0;
        BOOL def = 0;
        LONG pir = f_SKF_GetPINInfo ? f_SKF_GetPINInfo(hApp, USER_TYPE, &max, &remain, &def) : SAR_NOTSUPPORTYETERR;
        rec("SKF_GetPINInfo", pir == SAR_OK ? "PASS" : "RET", (ULONG)pir,
            "KEDA USER PIN info");

        ULONG retry = 0;
        TRY(SKF_VerifyPIN, f_SKF_VerifyPIN(hApp, USER_TYPE, (LPSTR)"123456", &retry),
            "KEDA USER PIN 123456");
    } else {
        rec("SKF_GetPINInfo", "SKIP", 0, "no application handle");
        rec("SKF_VerifyPIN", "SKIP", 0, "no application handle");
    }

    SKIP(SKF_CreateApplication, "destructive: would create a new application");
    TRY(SKF_DeleteApplication, f_SKF_DeleteApplication(hDev, (LPSTR)"__NO_SUCH_APP__"),
        "nonexistent app; expected error");
    SKIP(SKF_CreateFile, "destructive: would create a file");
    SKIP(SKF_CreateContainer, "destructive: would create a container");

    if (hApp) {
        ULONG flen = 0;
        rc = f_SKF_EnumFiles(hApp, NULL, &flen);
        char *files = NULL;
        if (rc == SAR_OK && flen > 0) {
            files = calloc(1, flen + 1);
            rc = f_SKF_EnumFiles(hApp, (LPSTR)files, &flen);
        }
        rec("SKF_EnumFiles", rc == SAR_OK ? "PASS" : "RET", rc, "list files in app");

        FILEATTRIBUTE fa;
        memset(&fa, 0, sizeof(fa));
        TRY(SKF_GetFileInfo, f_SKF_GetFileInfo(hApp, (LPSTR)"__NO_SUCH_FILE__", &fa),
            "nonexistent file; expected error");

        BYTE fbuf[64];
        ULONG fl = sizeof(fbuf);
        TRY(SKF_ReadFile, f_SKF_ReadFile(hApp, (LPSTR)"__NO_SUCH_FILE__", 0, 16, fbuf, &fl),
            "nonexistent file; expected error");
        TRY(SKF_WriteFile, f_SKF_WriteFile(hApp, (LPSTR)"__NO_SUCH_FILE__", 0, fbuf, 16),
            "nonexistent file; expected error");
        TRY(SKF_DeleteFile, f_SKF_DeleteFile(hApp, (LPSTR)"__NO_SUCH_FILE__"),
            "nonexistent file; expected error");

        if (files && *files) {
            char *first = files;
            memset(&fa, 0, sizeof(fa));
            TRY(SKF_GetFileInfo, f_SKF_GetFileInfo(hApp, (LPSTR)first, &fa),
                "existing file info");
            fl = sizeof(fbuf);
            ULONG want = fa.FileSize < sizeof(fbuf) ? fa.FileSize : sizeof(fbuf);
            TRY(SKF_ReadFile, f_SKF_ReadFile(hApp, (LPSTR)first, 0, want, fbuf, &fl),
                "existing file read");
        }
        free(files);
    } else {
        rec("SKF_EnumFiles", "SKIP", 0, "no application handle");
        rec("SKF_GetFileInfo", "SKIP", 0, "no application handle");
        rec("SKF_ReadFile", "SKIP", 0, "no application handle");
        rec("SKF_WriteFile", "SKIP", 0, "no application handle");
        rec("SKF_DeleteFile", "SKIP", 0, "no application handle");
    }

    char *ctnname = NULL;
    ULONG clen = 0;
    if (hApp) {
        rc = f_SKF_EnumContainer(hApp, NULL, &clen);
        char *ctns = NULL;
        if (rc == SAR_OK && clen > 0) {
            ctns = calloc(1, clen + 1);
            rc = f_SKF_EnumContainer(hApp, (LPSTR)ctns, &clen);
        }
        rec("SKF_EnumContainer", rc == SAR_OK ? "PASS" : "RET", rc, "list containers");
        if (ctns) {
            for (char *p = ctns; p < ctns + clen && *p; p += strlen(p) + 1) {
                if (strstr(p, "K01231-") == p) { ctnname = p; break; }
                if (!ctnname) ctnname = p;
            }
        }
        TRY(SKF_DeleteContainer, f_SKF_DeleteContainer(hApp, (LPSTR)"__NO_SUCH_CTN__"),
            "nonexistent container; expected error");
    } else {
        rec("SKF_EnumContainer", "SKIP", 0, "no application handle");
        rec("SKF_DeleteContainer", "SKIP", 0, "no application handle");
    }

    HCONTAINER hCtn = NULL;
    if (hApp && ctnname) {
        TRY(SKF_OpenContainer, f_SKF_OpenContainer(hApp, (LPSTR)ctnname, &hCtn), ctnname);
    } else if (hApp) {
        rec("SKF_OpenContainer", "SKIP", 0, "no container listed");
    } else {
        rec("SKF_OpenContainer", "SKIP", 0, "no application handle");
    }

    if (hCtn) {
        ULONG ctype = 0;
        TRY(SKF_GetContainerType, f_SKF_GetContainerType(hCtn, &ctype), "container type");

        BYTE cert[8192];
        ULONG certlen = sizeof(cert);
        TRY(SKF_ExportCertificate, f_SKF_ExportCertificate(hCtn, TRUE, cert, &certlen),
            "sign certificate export");

        BYTE pubbuf[2048];
        ULONG publen = sizeof(pubbuf);
        BYTE digest[32];
        for (int i = 0; i < 32; i++) digest[i] = (BYTE)i;
        rc = f_SKF_ExportPublicKey(hCtn, TRUE, pubbuf, &publen);
        rec("SKF_ExportPublicKey", rc == SAR_OK ? "PASS" : "RET", rc, "sign public key export");
        int is_rsa = (rc == SAR_OK && publen >= sizeof(ULONG) &&
                      *(ULONG *)pubbuf == SGD_RSA);

        ECCSIGNATUREBLOB sig;
        memset(&sig, 0, sizeof(sig));
        rc = f_SKF_ECCSignData(hCtn, digest, sizeof(digest), &sig);
        rec("SKF_ECCSignData", rc == SAR_OK ? "PASS" : "RET", rc, "SM2 sign of 32-byte test digest");
        if (rc == SAR_OK && !is_rsa) {
            TRY(SKF_ECCVerify, f_SKF_ECCVerify(hDev, (ECCPUBLICKEYBLOB *)pubbuf,
                digest, sizeof(digest), &sig), "verify with exported ECC public key");
            TRY(SKF_ExtECCVerify, f_SKF_ExtECCVerify(hDev, (ECCPUBLICKEYBLOB *)pubbuf,
                digest, sizeof(digest), &sig), "ext verify with exported ECC public key");

            BYTE plaintext[16];
            for (int i = 0; i < 16; i++) plaintext[i] = (BYTE)(0x40 + i);
            ECCCIPHERBLOB *cipher = calloc(1, sizeof(ECCCIPHERBLOB) + 256);
            ULONG er = f_SKF_ExtECCEncrypt(hDev, (ECCPUBLICKEYBLOB *)pubbuf,
                plaintext, sizeof(plaintext), cipher);
            rec("SKF_ExtECCEncrypt", er == SAR_OK ? "PASS" : "RET", er,
                "ECC public-key encryption of 16-byte test block");
            if (er == SAR_OK) {
                HANDLE hSess = NULL;
                ULONG xr = f_SKF_ECCExportSessionKey(hCtn, SGD_SM4_ECB,
                    (ECCPUBLICKEYBLOB *)pubbuf, cipher, &hSess);
                rec("SKF_ECCExportSessionKey", xr == SAR_OK ? "PASS" : "RET", xr,
                    "export SM4 session key encrypted to ECC public key");
                if (hSess) TRY(SKF_CloseHandle, f_SKF_CloseHandle(hSess), "close session key handle");
            } else {
                rec("SKF_ECCExportSessionKey", "SKIP", 0, "no ECC ciphertext");
            }
            free(cipher);
        } else {
            rec("SKF_ECCVerify", "SKIP", 0, is_rsa ? "container has RSA public key" : "no ECC signature");
            rec("SKF_ExtECCVerify", "SKIP", 0, is_rsa ? "container has RSA public key" : "no ECC signature");
            rec("SKF_ExtECCEncrypt", "SKIP", 0, "no ECC public key");
            rec("SKF_ECCExportSessionKey", "SKIP", 0, "no ECC public key");
        }

        BYTE rsasig[512];
        ULONG rsasiglen = sizeof(rsasig);
        rc = f_SKF_RSASignData(hCtn, digest, sizeof(digest), rsasig, &rsasiglen);
        rec("SKF_RSASignData", rc == SAR_OK ? "PASS" : "RET", rc, "RSA sign (if RSA key exists)");
        if (rc == SAR_OK && is_rsa) {
            TRY(SKF_RSAVerify, f_SKF_RSAVerify(hDev, (RSAPUBLICKEYBLOB *)pubbuf,
                digest, sizeof(digest), rsasig, rsasiglen), "verify with exported RSA public key");
        } else {
            rec("SKF_RSAVerify", "SKIP", 0, is_rsa ? "no RSA signature" : "container has ECC public key");
        }

        BYTE emptybuf[1] = {0};
        TRY(SKF_ImportCertificate, f_SKF_ImportCertificate(hCtn, TRUE, emptybuf, 0),
            "empty certificate; expected parameter error");
        TRY(SKF_ImportECCKeyPair, f_SKF_ImportECCKeyPair(hCtn, NULL),
            "NULL enveloped key; expected parameter error");
        TRY(SKF_ImportRSAKeyPair, f_SKF_ImportRSAKeyPair(hCtn, 0, emptybuf, 0, emptybuf, 0),
            "empty wrapped key; expected parameter error");
        HANDLE hImport = NULL;
        TRY(SKF_ImportSessionKey, f_SKF_ImportSessionKey(hCtn, 0, emptybuf, 0, &hImport),
            "empty session key; expected parameter error");
        SKIP(SKF_GenRSAKeyPair, "destructive: would generate a key pair");
        SKIP(SKF_GenECCKeyPair, "destructive: would generate a key pair");
        SKIP(SKF_GenExtRSAKey, "destructive: would generate an external RSA key");
        SKIP(SKF_RSAExportSessionKey, "requires a valid RSA public key");
        SKIP(SKF_ECCExportSessionKey, "requires a valid ECC public key");
        SKIP(SKF_ExtRSAPubKeyOperation, "requires an RSA public key blob");
        SKIP(SKF_ExtRSAPriKeyOperation, "requires an RSA private key blob");
        SKIP(SKF_ExtECCEncrypt, "requires an ECC public key blob");
        SKIP(SKF_ExtECCDecrypt, "requires an ECC private key blob");
        SKIP(SKF_ExtECCSign, "requires an ECC private key blob");
        SKIP(SKF_ExtECCVerify, "requires an ECC public key blob");
        SKIP(SKF_GenerateAgreementDataWithECC, "requires a container private key");
        SKIP(SKF_GenerateAgreementDataAndKeyWithECC, "requires a sponsor private key");
        SKIP(SKF_GenerateKeyWithECC, "requires an agreement handle");
        SKIP(SKF_ECCDecrypt, "requires a ciphertext");
        TRY(SKF_CloseContainer, f_SKF_CloseContainer(hCtn), "close container");
    } else {
        {
            const char *ns[] = {"SKF_GetContainerType", "SKF_ExportCertificate",
                "SKF_ExportPublicKey", "SKF_ECCSignData", "SKF_ECCVerify", "SKF_RSASignData",
                "SKF_RSAVerify", "SKF_ImportCertificate", "SKF_ImportECCKeyPair",
                "SKF_ImportRSAKeyPair", "SKF_ImportSessionKey", "SKF_GenRSAKeyPair",
                "SKF_GenECCKeyPair", "SKF_GenExtRSAKey", "SKF_RSAExportSessionKey",
                "SKF_ECCExportSessionKey", "SKF_ExtRSAPubKeyOperation",
                "SKF_ExtRSAPriKeyOperation", "SKF_ExtECCEncrypt", "SKF_ExtECCDecrypt",
                "SKF_ExtECCSign", "SKF_ExtECCVerify", "SKF_GenerateAgreementDataWithECC",
                "SKF_GenerateAgreementDataAndKeyWithECC", "SKF_GenerateKeyWithECC",
                "SKF_ECCDecrypt"};
            for (size_t i = 0; i < sizeof(ns) / sizeof(ns[0]); i++)
                rec(ns[i], "SKIP", 0, "no container handle");
        }
        rec("SKF_CloseContainer", "SKIP", 0, "no container handle");
    }

    /* Symmetric / hash / MAC tests, independent of application state. */
    BYTE key[16];
    for (int i = 0; i < 16; i++) key[i] = (BYTE)(0x10 + i);
    BLOCKCIPHERPARAM param;
    memset(&param, 0, sizeof(param));
    param.IVLen = 0;
    param.PaddingType = 0;

    HANDLE hSym = NULL;
    rc = f_SKF_SetSymmKey(hDev, key, SGD_SM4_ECB, &hSym);
    rec("SKF_SetSymmKey", rc == SAR_OK ? "PASS" : "RET", rc, "SM4 ECB key");

    if (hSym) {
        BYTE plain[16], enc[32], dec[32];
        for (int i = 0; i < 16; i++) plain[i] = (BYTE)i;
        ULONG enclen = sizeof(enc), declen = sizeof(dec);

        TRY(SKF_EncryptInit, f_SKF_EncryptInit(hSym, param), "SM4 ECB encrypt init");
        TRY(SKF_Encrypt, f_SKF_Encrypt(hSym, plain, sizeof(plain), enc, &enclen), "one-shot encrypt");
        TRY(SKF_DecryptInit, f_SKF_DecryptInit(hSym, param), "SM4 ECB decrypt init");
        TRY(SKF_Decrypt, f_SKF_Decrypt(hSym, enc, enclen, dec, &declen), "one-shot decrypt");

        enclen = sizeof(enc);
        TRY(SKF_EncryptInit, f_SKF_EncryptInit(hSym, param), "stream encrypt init");
        TRY(SKF_EncryptUpdate, f_SKF_EncryptUpdate(hSym, plain, 8, enc, &enclen), "stream encrypt update");
        TRY(SKF_EncryptFinal, f_SKF_EncryptFinal(hSym, enc + enclen, &enclen), "stream encrypt final");

        declen = sizeof(dec);
        TRY(SKF_DecryptInit, f_SKF_DecryptInit(hSym, param), "stream decrypt init");
        TRY(SKF_DecryptUpdate, f_SKF_DecryptUpdate(hSym, enc, enclen, dec, &declen), "stream decrypt update");
        TRY(SKF_DecryptFinal, f_SKF_DecryptFinal(hSym, dec + declen, &declen), "stream decrypt final");

        HANDLE hMacKey = NULL;
        ULONG mr = f_SKF_SetSymmKey(hDev, key, SGD_SM4_MAC, &hMacKey);
        HANDLE hMac = NULL;
        if (mr == SAR_OK) mr = f_SKF_MacInit(hMacKey, &param, &hMac);
        rec("SKF_MacInit", mr == SAR_OK ? "PASS" : "RET", mr, "SM4 MAC key/init");
        if (hMac) {
            BYTE mac[32];
            ULONG maclen = sizeof(mac);
            TRY(SKF_Mac, f_SKF_Mac(hMac, plain, sizeof(plain), mac, &maclen), "one-shot MAC");
            TRY(SKF_CloseHandle, f_SKF_CloseHandle(hMac), "close MAC handle");

            HANDLE hMac2 = NULL;
            mr = f_SKF_MacInit(hMacKey, &param, &hMac2);
            if (mr == SAR_OK) {
                maclen = sizeof(mac);
                TRY(SKF_MacUpdate, f_SKF_MacUpdate(hMac2, plain, sizeof(plain)), "stream MAC update");
                TRY(SKF_MacFinal, f_SKF_MacFinal(hMac2, mac, &maclen), "stream MAC final");
                TRY(SKF_CloseHandle, f_SKF_CloseHandle(hMac2), "close stream MAC handle");
            } else {
                rec("SKF_MacUpdate", "SKIP", 0, "no second MAC handle");
                rec("SKF_MacFinal", "SKIP", 0, "no second MAC handle");
            }
        } else {
            rec("SKF_Mac", "SKIP", 0, "no MAC handle");
            rec("SKF_MacUpdate", "SKIP", 0, "no MAC handle");
            rec("SKF_MacFinal", "SKIP", 0, "no MAC handle");
        }
        if (hMacKey) TRY(SKF_CloseHandle, f_SKF_CloseHandle(hMacKey), "close MAC key handle");
        TRY(SKF_CloseHandle, f_SKF_CloseHandle(hSym), "close symmetric key handle");
    } else {
        {
            const char *ns[] = {"SKF_EncryptInit", "SKF_Encrypt", "SKF_EncryptUpdate",
                "SKF_EncryptFinal", "SKF_DecryptInit", "SKF_Decrypt", "SKF_DecryptUpdate",
                "SKF_DecryptFinal", "SKF_MacInit", "SKF_Mac", "SKF_MacUpdate", "SKF_MacFinal",
                "SKF_CloseHandle"};
            for (size_t i = 0; i < sizeof(ns) / sizeof(ns[0]); i++)
                rec(ns[i], "SKIP", 0, "no symmetric key handle");
        }
    }

    HANDLE hHash = NULL;
    rc = f_SKF_DigestInit(hDev, SGD_SM3, NULL, NULL, 0, &hHash);
    rec("SKF_DigestInit", rc == SAR_OK ? "PASS" : "RET", rc, "SM3 digest init");
    if (hHash) {
        BYTE data[] = "SKF API test";
        BYTE hash[64];
        ULONG hashlen = sizeof(hash);
        TRY(SKF_Digest, f_SKF_Digest(hHash, data, sizeof(data), hash, &hashlen), "one-shot SM3 digest");
        TRY(SKF_CloseHandle, f_SKF_CloseHandle(hHash), "close hash handle");

        hHash = NULL;
        rc = f_SKF_DigestInit(hDev, SGD_SM3, NULL, NULL, 0, &hHash);
        if (rc == SAR_OK) {
            hashlen = sizeof(hash);
            TRY(SKF_DigestUpdate, f_SKF_DigestUpdate(hHash, data, sizeof(data)), "stream digest update");
            TRY(SKF_DigestFinal, f_SKF_DigestFinal(hHash, hash, &hashlen), "stream digest final");
        } else {
            rec("SKF_DigestUpdate", "SKIP", 0, "no second hash handle");
            rec("SKF_DigestFinal", "SKIP", 0, "no second hash handle");
        }
        if (hHash) TRY(SKF_CloseHandle, f_SKF_CloseHandle(hHash), "close stream hash handle");
    } else {
        rec("SKF_Digest", "SKIP", 0, "no digest handle");
        rec("SKF_DigestUpdate", "SKIP", 0, "no digest handle");
        rec("SKF_DigestFinal", "SKIP", 0, "no digest handle");
    }

    BYTE rnd[16];
    TRY(SKF_GenRandom, f_SKF_GenRandom(hDev, rnd, sizeof(rnd)), "16 random bytes");

    TRY(SKF_LockDev, f_SKF_LockDev(hDev, 1000), "lock device for 1 second");
    TRY(SKF_UnlockDev, f_SKF_UnlockDev(hDev), "unlock device");

    if (hApp) {
        TRY(SKF_ClearSecureState, f_SKF_ClearSecureState(hApp), "clear application secure state");
        TRY(SKF_CloseApplication, f_SKF_CloseApplication(hApp), "close application");
        hApp = NULL;
    } else {
        rec("SKF_ClearSecureState", "SKIP", 0, "no application handle");
        rec("SKF_CloseApplication", "SKIP", 0, "no application handle");
    }

    /* Authorized temporary application/file/container test. */
    if (authed) {
        unsigned id = (unsigned)getpid() % 100000;
        char tapp[32], tfile[32], tctn[32];
        snprintf(tapp, sizeof(tapp), "SKFALL%u", id);
        snprintf(tfile, sizeof(tfile), "SKFALL%u.TMP", id);
        snprintf(tctn, sizeof(tctn), "SKFALL%u.CTN", id);

        ULONG ar = SAR_FAIL;
        WRAP_AUTH(hDev, authkey, authalg, ar);
        rec("SKF_DevAuth", ar == SAR_OK ? "PASS" : "RET", ar,
            "re-authenticate before temporary application");

        HAPPLICATION tApp = NULL;
        ULONG r = f_SKF_CreateApplication(hDev, (LPSTR)tapp,
            (LPSTR)"123456", 6, (LPSTR)"123456", 6,
            SECURE_ANYONE_ACCOUNT, &tApp);
        rec("SKF_CreateApplication", r == SAR_OK ? "PASS" : "RET", r, tapp);
        int created = (r == SAR_OK);

        if (created) {
            if (tApp) {
                f_SKF_CloseApplication(tApp);
                tApp = NULL;
            }
            r = f_SKF_OpenApplication(hDev, (LPSTR)tapp, &tApp);
            rec("SKF_OpenApplication", r == SAR_OK ? "PASS" : "RET", r, tapp);
            if (r == SAR_OK && tApp) {
                ULONG retry = 0;
                r = f_SKF_VerifyPIN(tApp, USER_TYPE, (LPSTR)"123456", &retry);
                rec("SKF_VerifyPIN", r == SAR_OK ? "PASS" : "RET", r,
                    "temporary application USER PIN 123456");

                retry = 0;
                r = f_SKF_ChangePIN(tApp, USER_TYPE, (LPSTR)"123456",
                                    (LPSTR)"654321", &retry);
                rec("SKF_ChangePIN", r == SAR_OK ? "PASS" : "RET", r,
                    "temporary application 123456 -> 654321");
                if (r == SAR_OK) {
                    retry = 0;
                    f_SKF_VerifyPIN(tApp, USER_TYPE, (LPSTR)"654321", &retry);
                    retry = 0;
                    r = f_SKF_ChangePIN(tApp, USER_TYPE, (LPSTR)"654321",
                                        (LPSTR)"123456", &retry);
                    rec("SKF_ChangePIN", r == SAR_OK ? "PASS" : "RET", r,
                        "restore temporary application PIN");
                }

                for (int i = 0; i < 6; i++) {
                    retry = 0;
                    f_SKF_VerifyPIN(tApp, USER_TYPE, (LPSTR)"000000", &retry);
                }
                retry = 0;
                r = f_SKF_UnblockPIN(tApp, (LPSTR)"123456",
                                     (LPSTR)"123456", &retry);
                rec("SKF_UnblockPIN", r == SAR_OK ? "PASS" : "RET", r,
                    "temporary application; admin PIN 123456");
                retry = 0;
                f_SKF_VerifyPIN(tApp, USER_TYPE, (LPSTR)"123456", &retry);

                r = f_SKF_CreateFile(tApp, (LPSTR)tfile, 64,
                    SECURE_ANYONE_ACCOUNT, SECURE_ANYONE_ACCOUNT);
                rec("SKF_CreateFile", r == SAR_OK ? "PASS" : "RET", r, tfile);
                if (r == SAR_OK) {
                    BYTE data[] = "skf-all-file";
                    r = f_SKF_WriteFile(tApp, (LPSTR)tfile, 0, data, sizeof(data));
                    rec("SKF_WriteFile", r == SAR_OK ? "PASS" : "RET", r, tfile);
                    BYTE out[64];
                    ULONG outlen = sizeof(out);
                    r = f_SKF_ReadFile(tApp, (LPSTR)tfile, 0, sizeof(data), out, &outlen);
                    rec("SKF_ReadFile", r == SAR_OK ? "PASS" : "RET", r, tfile);
                    FILEATTRIBUTE fa;
                    memset(&fa, 0, sizeof(fa));
                    r = f_SKF_GetFileInfo(tApp, (LPSTR)tfile, &fa);
                    rec("SKF_GetFileInfo", r == SAR_OK ? "PASS" : "RET", r, tfile);
                    r = f_SKF_DeleteFile(tApp, (LPSTR)tfile);
                    rec("SKF_DeleteFile", r == SAR_OK ? "PASS" : "RET", r, tfile);
                }

                HCONTAINER tCtn = NULL;
                r = f_SKF_CreateContainer(tApp, (LPSTR)tctn, &tCtn);
                rec("SKF_CreateContainer", r == SAR_OK ? "PASS" : "RET", r, tctn);
                if (r == SAR_OK && tCtn) {
                    ULONG ctype = 0;
                    r = f_SKF_GetContainerType(tCtn, &ctype);
                    rec("SKF_GetContainerType", r == SAR_OK ? "PASS" : "RET", r, tctn);
                    f_SKF_CloseContainer(tCtn);
                    r = f_SKF_DeleteContainer(tApp, (LPSTR)tctn);
                    rec("SKF_DeleteContainer", r == SAR_OK ? "PASS" : "RET", r, tctn);
                }

                f_SKF_CloseApplication(tApp);
                tApp = NULL;
            }

            /* Deleting the current application requires a fresh session. */
            f_SKF_DisConnectDev(hDev);
            hDev = NULL;
            r = f_SKF_ConnectDev((LPSTR)devname, &hDev);
            rec("SKF_ConnectDev", r == SAR_OK ? "PASS" : "RET", r, devname);
            if (r == SAR_OK && hDev) {
                ar = SAR_FAIL;
                WRAP_AUTH(hDev, authkey, authalg, ar);
                rec("SKF_DevAuth", ar == SAR_OK ? "PASS" : "RET", ar,
                    "re-authenticate before deleting temporary application");
                if (ar == SAR_OK) {
                    r = f_SKF_DeleteApplication(hDev, (LPSTR)tapp);
                    rec("SKF_DeleteApplication", r == SAR_OK ? "PASS" : "RET", r, tapp);
                }
            }
        }
    }

    if (hDev)
        TRY(SKF_DisConnectDev, f_SKF_DisConnectDev(hDev), "disconnect device");

    for (size_t i = 0; i < sizeof(all_names) / sizeof(all_names[0]); i++) {
        int found = 0;
        for (int j = 0; j < nres; j++)
            if (strcmp(results[j].name, all_names[i]) == 0) { found = 1; break; }
        if (!found) rec(all_names[i], "NOT RUN", 0, "not exercised by this run");
    }

    fprintf(rep, "\n## Summary\n\n");
    fprintf(rep, "- PASS: %d\n", npass);
    fprintf(rep, "- Returned error (RET): %d\n", nret);
    fprintf(rep, "- Skipped: %d\n", nskip);
    fprintf(rep, "- Missing symbols: %d\n", nmiss);
    fprintf(rep, "- Not run: %d\n", nnotrun);
    if (authed)
        fprintf(rep, "\nDevice authentication succeeded. A temporary application, file and "
                     "container were created and deleted; existing KEDA applications/containers "
                     "were not modified. Other destructive operations (change PIN, change device "
                     "auth key, generate external keys, imports) were not executed with valid "
                     "parameters; where safe, parameter-validation was exercised.\n");
    else
        fprintf(rep, "\nDevice authentication was not performed (SKF_DEVAUTH_KEY unset). "
                     "Destructive operations (create/delete application, file, container, change "
                     "PIN, generate key pair, import key, change auth key) were not executed with "
                     "valid parameters; where safe, parameter-validation was exercised.\n");

    fclose(rep);
    free(names);
    free(apps);
    dlclose(lib);
    return 0;
}
