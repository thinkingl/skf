/*
 * Differential test: run the same scenarios against the vendor libskf.so
 * and the native reimplementation, then compare normalized output.
 *
 * Usage:
 *   SKF_DEVAUTH_KEY='<device-auth-key>' ./skf_diff_test \
 *       ./lib/libskf.so ./reimpl/libskf_native.so
 *
 * The test never touches DEFAULT/KEDA objects except a temporary container
 * created and deleted again.  Application/file tests use a temporary app.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skf.h"

typedef struct lib {
    void *h;
    typeof(&SKF_EnumDev) EnumDev;
    typeof(&SKF_ConnectDev) ConnectDev;
    typeof(&SKF_DisConnectDev) DisConnectDev;
    typeof(&SKF_GetDevState) GetDevState;
    typeof(&SKF_GetDevInfo) GetDevInfo;
    typeof(&SKF_SetLabel) SetLabel;
    typeof(&SKF_GenRandom) GenRandom;
    typeof(&SKF_LockDev) LockDev;
    typeof(&SKF_UnlockDev) UnlockDev;
    typeof(&SKF_CancelWaitForDevEvent) CancelWaitForDevEvent;
    typeof(&SKF_DevAuth) DevAuth;
    typeof(&SKF_ChangeDevAuthKey) ChangeDevAuthKey;
    typeof(&SKF_OpenApplication) OpenApplication;
    typeof(&SKF_CloseApplication) CloseApplication;
    typeof(&SKF_VerifyPIN) VerifyPIN;
    typeof(&SKF_ChangePIN) ChangePIN;
    typeof(&SKF_GetPINInfo) GetPINInfo;
    typeof(&SKF_CreateApplication) CreateApplication;
    typeof(&SKF_DeleteApplication) DeleteApplication;
    typeof(&SKF_EnumApplication) EnumApplication;
    typeof(&SKF_CreateFile) CreateFile;
    typeof(&SKF_DeleteFile) DeleteFile;
    typeof(&SKF_ReadFile) ReadFile;
    typeof(&SKF_WriteFile) WriteFile;
    typeof(&SKF_GetFileInfo) GetFileInfo;
    typeof(&SKF_EnumFiles) EnumFiles;
    typeof(&SKF_CreateContainer) CreateContainer;
    typeof(&SKF_DeleteContainer) DeleteContainer;
    typeof(&SKF_OpenContainer) OpenContainer;
    typeof(&SKF_CloseContainer) CloseContainer;
    typeof(&SKF_GetContainerType) GetContainerType;
    typeof(&SKF_EnumContainer) EnumContainer;
    typeof(&SKF_ImportCertificate) ImportCertificate;
    typeof(&SKF_ExportCertificate) ExportCertificate;
    typeof(&SKF_ImportECCKeyPair) ImportECCKeyPair;
    typeof(&SKF_ImportRSAKeyPair) ImportRSAKeyPair;
    typeof(&SKF_ImportSessionKey) ImportSessionKey;
    typeof(&SKF_SetSymmKey) SetSymmKey;
    typeof(&SKF_EncryptInit) EncryptInit;
    typeof(&SKF_Encrypt) Encrypt;
    typeof(&SKF_Decrypt) Decrypt;
    typeof(&SKF_CloseHandle) CloseHandle;
    typeof(&SKF_Transmit) Transmit;
} LIB;

static void *must_sym(LIB *l, const char *name)
{
    void *p = dlsym(l->h, name);
    if (!p) {
        fprintf(stderr, "missing symbol %s in %s\n", name, name);
        exit(2);
    }
    return p;
}

#define LOAD(l, n) do { (l)->n = (typeof(&SKF_##n))must_sym(l, "SKF_" #n); } while (0)

static int load_lib(LIB *l, const char *path)
{
    memset(l, 0, sizeof(*l));
    l->h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!l->h) {
        fprintf(stderr, "dlopen %s: %s\n", path, dlerror());
        return -1;
    }
    LOAD(l, EnumDev); LOAD(l, ConnectDev); LOAD(l, DisConnectDev);
    LOAD(l, GetDevState); LOAD(l, GetDevInfo); LOAD(l, SetLabel);
    LOAD(l, GenRandom); LOAD(l, LockDev); LOAD(l, UnlockDev);
    LOAD(l, CancelWaitForDevEvent); LOAD(l, DevAuth);
    LOAD(l, ChangeDevAuthKey);
    LOAD(l, OpenApplication); LOAD(l, CloseApplication);
    LOAD(l, VerifyPIN); LOAD(l, ChangePIN); LOAD(l, GetPINInfo);
    LOAD(l, CreateApplication); LOAD(l, DeleteApplication);
    LOAD(l, EnumApplication);
    LOAD(l, CreateFile); LOAD(l, DeleteFile); LOAD(l, ReadFile);
    LOAD(l, WriteFile); LOAD(l, GetFileInfo); LOAD(l, EnumFiles);
    LOAD(l, CreateContainer); LOAD(l, DeleteContainer);
    LOAD(l, OpenContainer); LOAD(l, CloseContainer);
    LOAD(l, GetContainerType); LOAD(l, EnumContainer);
    LOAD(l, ImportCertificate); LOAD(l, ExportCertificate);
    LOAD(l, ImportECCKeyPair); LOAD(l, ImportRSAKeyPair);
    LOAD(l, ImportSessionKey);
    LOAD(l, SetSymmKey); LOAD(l, EncryptInit); LOAD(l, Encrypt);
    LOAD(l, Decrypt); LOAD(l, CloseHandle); LOAD(l, Transmit);
    return 0;
}

static void put(char *out, size_t cap, const char *fmt, ...)
{
    size_t n = strlen(out);
    if (n >= cap)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(out + n, cap - n, fmt, ap);
    va_end(ap);
}

static int devauth(LIB *l, DEVHANDLE d, const char *key)
{
    DEVINFO i;
    memset(&i, 0, sizeof(i));
    if (l->GetDevInfo(d, &i) != SAR_OK)
        return -1;
    ULONG alg = i.DevAuthAlgId;
    if (alg != SGD_SM1_ECB && alg != SGD_SM4_ECB)
        alg = SGD_SM4_ECB;
    BYTE ch[16];
    memset(ch, 0, sizeof(ch));
    if (l->GenRandom(d, ch, 8) != SAR_OK)
        return -1;
    HANDLE h = NULL;
    if (l->SetSymmKey(d, (BYTE *)key, alg, &h) != SAR_OK)
        return -1;
    BLOCKCIPHERPARAM p;
    memset(&p, 0, sizeof(p));
    if (l->EncryptInit(h, p) != SAR_OK)
        return -1;
    BYTE out[32];
    ULONG outlen = sizeof(out);
    if (l->Encrypt(h, ch, 16, out, &outlen) != SAR_OK)
        return -1;
    l->CloseHandle(h);
    return l->DevAuth(d, out, outlen) == SAR_OK ? 0 : -1;
}

static void run(LIB *l, char *out, size_t cap, const char *authkey)
{
    ULONG len = 0, rc;
    l->EnumDev(TRUE, NULL, &len);
    char *names = calloc(1, len + 1);
    rc = l->EnumDev(TRUE, (LPSTR)names, &len);
    put(out, cap, "EnumDev rc=%lx len=%lu names=%s\n", (unsigned long)rc,
        (unsigned long)len, names ? names : "");
    DEVHANDLE d = NULL;
    rc = l->ConnectDev((LPSTR)names, &d);
    put(out, cap, "ConnectDev rc=%lx\n", (unsigned long)rc);
    if (rc != SAR_OK)
        return;
    ULONG state = 0;
    rc = l->GetDevState((LPSTR)names, &state);
    put(out, cap, "GetDevState rc=%lx state=%lu\n", (unsigned long)rc,
        (unsigned long)state);
    DEVINFO info;
    memset(&info, 0, sizeof(info));
    rc = l->GetDevInfo(d, &info);
    put(out, cap, "GetDevInfo rc=%lx label='%s' serial='%s' fw=%u.%u total=%lu free=%lu\n",
        (unsigned long)rc, info.Label, info.SerialNumber,
        info.FirmwareVersion.major, info.FirmwareVersion.minor,
        (unsigned long)info.TotalSpace, (unsigned long)info.FreeSpace);

    char oldlabel[33];
    snprintf(oldlabel, sizeof(oldlabel), "%s", info.Label);
    rc = l->SetLabel(d, (LPSTR)"DIFFLBL");
    put(out, cap, "SetLabel rc=%lx\n", (unsigned long)rc);
    memset(&info, 0, sizeof(info));
    l->GetDevInfo(d, &info);
    put(out, cap, "SetLabel read label='%s'\n", info.Label);
    rc = l->SetLabel(d, (LPSTR)oldlabel);
    put(out, cap, "SetLabel restore rc=%lx\n", (unsigned long)rc);
    memset(&info, 0, sizeof(info));
    l->GetDevInfo(d, &info);
    put(out, cap, "SetLabel restored label='%s'\n", info.Label);

    BYTE rnd[16];
    memset(rnd, 0, sizeof(rnd));
    rc = l->GenRandom(d, rnd, sizeof(rnd));
    put(out, cap, "GenRandom rc=%lx\n", (unsigned long)rc);
    rc = l->LockDev(d, 1000);
    put(out, cap, "LockDev rc=%lx\n", (unsigned long)rc);
    rc = l->UnlockDev(d);
    put(out, cap, "UnlockDev rc=%lx\n", (unsigned long)rc);
    rc = l->CancelWaitForDevEvent();
    put(out, cap, "CancelWait rc=%lx\n", (unsigned long)rc);

    if (authkey && *authkey) {
        rc = devauth(l, d, authkey) == 0 ? SAR_OK : SAR_FAIL;
        put(out, cap, "DevAuth rc=%lx\n", (unsigned long)rc);
    }

    HAPPLICATION app = NULL;
    rc = l->OpenApplication(d, (LPSTR)"KEDA", &app);
    put(out, cap, "OpenKEDA rc=%lx\n", (unsigned long)rc);
    if (rc == SAR_OK) {
        ULONG retry = 0;
        rc = l->VerifyPIN(app, USER_TYPE, (LPSTR)"123456", &retry);
        put(out, cap, "VerifyKEDA rc=%lx retry=%lu\n", (unsigned long)rc,
            (unsigned long)retry);
        for (int t = 0; t < 2; t++) {
            ULONG mx = 0, rem = 0;
            BOOL def = 0;
            rc = l->GetPINInfo(app, t ? ADMIN_TYPE : USER_TYPE, &mx, &rem, &def);
            put(out, cap, "PINInfo type=%d rc=%lx max=%lu remain=%lu def=%d\n",
                t, (unsigned long)rc, (unsigned long)mx,
                (unsigned long)rem, (int)def);
        }
        l->CloseApplication(app);
        app = NULL;
    }

    if (authkey && *authkey) {
        l->DeleteApplication(d, (LPSTR)"SKFDIFFA");
        HAPPLICATION ta = NULL;
        rc = l->CreateApplication(d, (LPSTR)"SKFDIFFA", (LPSTR)"123456", 6,
                                  (LPSTR)"123456", 6, SECURE_ANYONE_ACCOUNT, &ta);
        put(out, cap, "CreateApp rc=%lx\n", (unsigned long)rc);
        if (ta)
            l->CloseApplication(ta);
        ta = NULL;
        if (rc == SAR_OK) {
            rc = l->OpenApplication(d, (LPSTR)"SKFDIFFA", &ta);
            put(out, cap, "OpenApp rc=%lx\n", (unsigned long)rc);
        }
        if (ta) {
            ULONG retry = 0;
            rc = l->VerifyPIN(ta, USER_TYPE, (LPSTR)"123456", &retry);
            put(out, cap, "VerifyApp rc=%lx retry=%lu\n", (unsigned long)rc,
                (unsigned long)retry);
            rc = l->CreateFile(ta, (LPSTR)"DIFF.TMP", 64,
                               SECURE_ANYONE_ACCOUNT, SECURE_ANYONE_ACCOUNT);
            put(out, cap, "CreateFile rc=%lx\n", (unsigned long)rc);
            if (rc == SAR_OK) {
                BYTE data[] = "diff-data";
                rc = l->WriteFile(ta, (LPSTR)"DIFF.TMP", 0, data, sizeof(data));
                put(out, cap, "WriteFile rc=%lx\n", (unsigned long)rc);
                BYTE rd[64];
                ULONG rl = sizeof(rd);
                rc = l->ReadFile(ta, (LPSTR)"DIFF.TMP", 0, sizeof(data), rd, &rl);
                put(out, cap, "ReadFile rc=%lx len=%lu data=", (unsigned long)rc,
                    (unsigned long)rl);
                for (ULONG i = 0; i < rl; i++)
                    put(out, cap, "%02x", rd[i]);
                put(out, cap, "\n");
                FILEATTRIBUTE fa;
                memset(&fa, 0, sizeof(fa));
                rc = l->GetFileInfo(ta, (LPSTR)"DIFF.TMP", &fa);
                put(out, cap, "FileInfo rc=%lx size=%lu r=%lx w=%lx name='%s'\n",
                    (unsigned long)rc, (unsigned long)fa.FileSize,
                    (unsigned long)fa.ReadRights, (unsigned long)fa.WriteRights,
                    fa.FileName);
                rc = l->DeleteFile(ta, (LPSTR)"DIFF.TMP");
                put(out, cap, "DeleteFile rc=%lx\n", (unsigned long)rc);
            }
            HCONTAINER tc = NULL;
            l->DeleteContainer(ta, (LPSTR)"SKFDIFFC");
            rc = l->CreateContainer(ta, (LPSTR)"SKFDIFFC", &tc);
            put(out, cap, "CreateContainer rc=%lx\n", (unsigned long)rc);
            if (tc) {
                ULONG ct = 0;
                rc = l->GetContainerType(tc, &ct);
                put(out, cap, "ContainerType rc=%lx type=%lu\n",
                    (unsigned long)rc, (unsigned long)ct);
                l->CloseContainer(tc);
                rc = l->DeleteContainer(ta, (LPSTR)"SKFDIFFC");
                put(out, cap, "DeleteContainer rc=%lx\n", (unsigned long)rc);
            }
            l->CloseApplication(ta);
        }
        l->DisConnectDev(d);
        d = NULL;
        rc = l->ConnectDev((LPSTR)names, &d);
        put(out, cap, "Reconnect rc=%lx\n", (unsigned long)rc);
        if (d && authkey && *authkey) {
            rc = devauth(l, d, authkey) == 0 ? SAR_OK : SAR_FAIL;
            put(out, cap, "ReDevAuth rc=%lx\n", (unsigned long)rc);
            rc = l->DeleteApplication(d, (LPSTR)"SKFDIFFA");
            put(out, cap, "DeleteApp rc=%lx\n", (unsigned long)rc);
        }
    }

    if (d) {
        BYTE empty[1] = {0};
        /* Never change a real auth key here: only exercise the length check. */
        rc = l->ChangeDevAuthKey(d, empty, 17);
        put(out, cap, "ChangeDevAuthKey(len17) rc=%lx\n", (unsigned long)rc);
        rc = l->Transmit(d, empty, 0, NULL, NULL);
        put(out, cap, "Transmit(bad) rc=%lx\n", (unsigned long)rc);
        rc = l->ImportECCKeyPair(NULL, NULL);
        put(out, cap, "ImportECC(NULL) rc=%lx\n", (unsigned long)rc);
        rc = l->ImportRSAKeyPair(NULL, 0, NULL, 0, NULL, 0);
        put(out, cap, "ImportRSA(NULL) rc=%lx\n", (unsigned long)rc);
        rc = l->ImportSessionKey(NULL, 0, NULL, 0, NULL);
        put(out, cap, "ImportSession(NULL) rc=%lx\n", (unsigned long)rc);
        l->DisConnectDev(d);
    } else if (d) {
        l->DisConnectDev(d);
    }
    free(names);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <vendor-lib> <native-lib>\n", argv[0]);
        return 2;
    }
    const char *auth = getenv("SKF_DEVAUTH_KEY");
    LIB a, b;
    if (load_lib(&a, argv[1]) || load_lib(&b, argv[2]))
        return 2;
    char outa[32768] = {0}, outb[32768] = {0};
    run(&a, outa, sizeof(outa), auth);
    run(&b, outb, sizeof(outb), auth);
    if (strcmp(outa, outb) == 0) {
        printf("[PASS] differential test: vendor == native\n");
        fputs(outa, stdout);
        return 0;
    }
    printf("[DIFF] vendor != native\n");
    printf("--- vendor ---\n%s", outa);
    printf("--- native ---\n%s", outb);
    return 1;
}
