/*
 * Cross-validation harness: vendor hardware SKF vs SoftSKF.
 *
 * Must be run as root (or with CAP_SYS_RAWIO) because the vendor library uses
 * SG_IO on /dev/sdd.  It only performs read/verify/sign/encrypt operations on
 * the hardware key; it does not create or delete hardware applications or
 * containers and does not change PINs.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include "skf.h"

typedef struct {
    void *lib;
    typeof(&SKF_EnumDev) EnumDev;
    typeof(&SKF_ConnectDev) ConnectDev;
    typeof(&SKF_DisConnectDev) DisConnectDev;
    typeof(&SKF_GetDevState) GetDevState;
    typeof(&SKF_GetDevInfo) GetDevInfo;
    typeof(&SKF_GenRandom) GenRandom;
    typeof(&SKF_LockDev) LockDev;
    typeof(&SKF_UnlockDev) UnlockDev;
    typeof(&SKF_EnumApplication) EnumApplication;
    typeof(&SKF_OpenApplication) OpenApplication;
    typeof(&SKF_CloseApplication) CloseApplication;
    typeof(&SKF_GetPINInfo) GetPINInfo;
    typeof(&SKF_VerifyPIN) VerifyPIN;
    typeof(&SKF_EnumContainer) EnumContainer;
    typeof(&SKF_OpenContainer) OpenContainer;
    typeof(&SKF_CloseContainer) CloseContainer;
    typeof(&SKF_GetContainerType) GetContainerType;
    typeof(&SKF_CreateContainer) CreateContainer;
    typeof(&SKF_DeleteContainer) DeleteContainer;
    typeof(&SKF_ExportPublicKey) ExportPublicKey;
    typeof(&SKF_GenECCKeyPair) GenECCKeyPair;
    typeof(&SKF_GenRSAKeyPair) GenRSAKeyPair;
    typeof(&SKF_ECCSignData) ECCSignData;
    typeof(&SKF_ECCVerify) ECCVerify;
    typeof(&SKF_RSASignData) RSASignData;
    typeof(&SKF_RSAVerify) RSAVerify;
    typeof(&SKF_ExtECCEncrypt) ExtECCEncrypt;
    typeof(&SKF_ExtECCDecrypt) ExtECCDecrypt;
    typeof(&SKF_ExtECCSign) ExtECCSign;
    typeof(&SKF_ExtECCVerify) ExtECCVerify;
    typeof(&SKF_SetSymmKey) SetSymmKey;
    typeof(&SKF_EncryptInit) EncryptInit;
    typeof(&SKF_Encrypt) Encrypt;
    typeof(&SKF_DecryptInit) DecryptInit;
    typeof(&SKF_Decrypt) Decrypt;
    typeof(&SKF_MacInit) MacInit;
    typeof(&SKF_Mac) Mac;
    typeof(&SKF_DigestInit) DigestInit;
    typeof(&SKF_Digest) Digest;
    typeof(&SKF_CloseHandle) CloseHandle;
} API;

static int passes, fails, diffs, nas;

static void report(const char *name, const char *status, const char *detail)
{
    printf("[%-4s] %-42s %s\n", status, name, detail ? detail : "");
    if (strcmp(status, "PASS") == 0)
        passes++;
    else if (strcmp(status, "FAIL") == 0)
        fails++;
    else if (strcmp(status, "DIFF") == 0)
        diffs++;
    else
        nas++;
}

static void hexdump(const char *label, const unsigned char *p, size_t n)
{
    printf("%s=", label);
    for (size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

static int load_api(const char *path, API *a)
{
    memset(a, 0, sizeof(*a));
    a->lib = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!a->lib) {
        fprintf(stderr, "dlopen(%s): %s\n", path, dlerror());
        return -1;
    }
#define LOAD(n) do { \
    *(void **)(&a->n) = dlsym(a->lib, "SKF_" #n); \
    if (!a->n) { fprintf(stderr, "missing SKF_%s in %s\n", #n, path); return -1; } \
} while (0)
    LOAD(EnumDev); LOAD(ConnectDev); LOAD(DisConnectDev);
    LOAD(GetDevState); LOAD(GetDevInfo); LOAD(GenRandom);
    LOAD(LockDev); LOAD(UnlockDev);
    LOAD(EnumApplication); LOAD(OpenApplication); LOAD(CloseApplication);
    LOAD(GetPINInfo); LOAD(VerifyPIN);
    LOAD(EnumContainer); LOAD(OpenContainer); LOAD(CloseContainer);
    LOAD(GetContainerType); LOAD(CreateContainer); LOAD(DeleteContainer);
    LOAD(ExportPublicKey); LOAD(GenECCKeyPair); LOAD(GenRSAKeyPair);
    LOAD(ECCSignData); LOAD(ECCVerify); LOAD(RSASignData); LOAD(RSAVerify);
    LOAD(ExtECCEncrypt); LOAD(ExtECCDecrypt); LOAD(ExtECCSign); LOAD(ExtECCVerify);
    LOAD(SetSymmKey); LOAD(EncryptInit); LOAD(Encrypt);
    LOAD(DecryptInit); LOAD(Decrypt); LOAD(MacInit); LOAD(Mac);
    LOAD(DigestInit); LOAD(Digest); LOAD(CloseHandle);
#undef LOAD
    return 0;
}

static const char *pick_device(API *a, int hardware, char *out, size_t outlen)
{
    ULONG len = 0;
    if (a->EnumDev(TRUE, NULL, &len) != SAR_OK || len == 0)
        return NULL;
    char *names = calloc(1, len + 1);
    if (!names)
        return NULL;
    if (a->EnumDev(TRUE, (LPSTR)names, &len) != SAR_OK) {
        free(names);
        return NULL;
    }
    const char *pick = NULL;
    for (char *p = names; p < names + len && *p; p += strlen(p) + 1) {
        if (hardware) {
            if (!pick && (strstr(p, "sdd") || strstr(p, "sg")))
                pick = p;
        } else {
            if (!pick)
                pick = p;
        }
    }
    if (!pick && *names)
        pick = names;
    if (pick)
        snprintf(out, outlen, "%s", pick);
    free(names);
    return pick ? out : NULL;
}


static const char *find_container(API *a, HAPPLICATION app, char *out,
                                  size_t outlen)
{
    ULONG len = 0;
    if (a->EnumContainer(app, NULL, &len) != SAR_OK || len == 0)
        return NULL;
    char *names = calloc(1, len + 1);
    if (!names)
        return NULL;
    if (a->EnumContainer(app, (LPSTR)names, &len) != SAR_OK) {
        free(names);
        return NULL;
    }
    const char *pick = NULL;
    for (char *p = names; p < names + len && *p; p += strlen(p) + 1) {
        if (strncmp(p, "K01231-", 7) == 0) { pick = p; break; }
        if (!pick && strcmp(p, "DEFAULT") != 0) pick = p;
    }
    if (!pick && *names)
        pick = names;
    if (pick)
        snprintf(out, outlen, "%s", pick);
    free(names);
    return pick ? out : NULL;
}

static int list_has_app(API *a, DEVHANDLE dev, const char *name)
{
    ULONG len = 0;
    if (a->EnumApplication(dev, NULL, &len) != SAR_OK || len == 0)
        return 0;
    char *list = calloc(1, len + 1);
    if (!list)
        return 0;
    if (a->EnumApplication(dev, (LPSTR)list, &len) != SAR_OK) {
        free(list);
        return 0;
    }
    int found = 0;
    for (char *p = list; p < list + len && *p; p += strlen(p) + 1) {
        if (strcmp(p, name) == 0) {
            found = 1;
            break;
        }
    }
    free(list);
    return found;
}

static void fill_ecc_pub(EC_KEY *k, ECCPUBLICKEYBLOB *pub)
{
    memset(pub, 0, sizeof(*pub));
    pub->BitLen = 256;
    const EC_GROUP *g = EC_KEY_get0_group(k);
    const EC_POINT *p = EC_KEY_get0_public_key(k);
    BIGNUM *x = BN_new(), *y = BN_new();
    EC_POINT_get_affine_coordinates(g, p, x, y, NULL);
    BN_bn2binpad(x, pub->XCoordinate + 32, 32);
    BN_bn2binpad(y, pub->YCoordinate + 32, 32);
    BN_free(x); BN_free(y);
}

static void fill_ecc_priv(EC_KEY *k, ECCPRIVATEKEYBLOB *pri)
{
    memset(pri, 0, sizeof(*pri));
    pri->BitLen = 256;
    BN_bn2binpad(EC_KEY_get0_private_key(k), pri->PrivateKey + 32, 32);
}

static void test_sym(API *hw, API *sw, DEVHANDLE hdev, DEVHANDLE sdev,
                     ULONG alg, const char *name)
{
    unsigned char key[16], iv[16], plain[16];
    for (int i = 0; i < 16; i++) {
        key[i] = (unsigned char)(0x10 + i);
        iv[i] = (unsigned char)(0x30 + i);
        plain[i] = (unsigned char)(0x50 + i);
    }
    BLOCKCIPHERPARAM p;
    memset(&p, 0, sizeof(p));
    p.PaddingType = 0;
    if (alg != SGD_SM4_ECB) {
        memcpy(p.IV, iv, 16);
        p.IVLen = 16;
    }

    HANDLE hh = NULL, hs = NULL;
    ULONG r1 = hw->SetSymmKey(hdev, key, alg, &hh);
    ULONG r2 = sw->SetSymmKey(sdev, key, alg, &hs);
    if (r1 == SAR_NOTSUPPORTYETERR || r2 == SAR_NOTSUPPORTYETERR) {
        char msg[160];
        snprintf(msg, sizeof(msg), "hw=0x%08lx soft=0x%08lx (not comparable)",
                 (unsigned long)r1, (unsigned long)r2);
        report(name, "NA", msg);
        if (hh) hw->CloseHandle(hh);
        if (hs) sw->CloseHandle(hs);
        return;
    }
    if (r1 != SAR_OK || r2 != SAR_OK) {
        char msg[160];
        snprintf(msg, sizeof(msg), "hw=0x%08lx soft=0x%08lx",
                 (unsigned long)r1, (unsigned long)r2);
        report(name, "DIFF", msg);
        if (hh) hw->CloseHandle(hh);
        if (hs) sw->CloseHandle(hs);
        return;
    }

    unsigned char he[64], se[64], hd[64], sd[64];
    ULONG hel = sizeof(he), sel = sizeof(se), hdl = sizeof(hd), sdl = sizeof(sd);
    r1 = hw->EncryptInit(hh, p);
    r2 = sw->EncryptInit(hs, p);
    if (r1 == SAR_OK) r1 = hw->Encrypt(hh, plain, 16, he, &hel);
    if (r2 == SAR_OK) r2 = sw->Encrypt(hs, plain, 16, se, &sel);

    int eq = r1 == SAR_OK && r2 == SAR_OK && hel == sel &&
             hel == 16 && memcmp(he, se, hel) == 0;
    char msg[256];
    if (eq) {
        snprintf(msg, sizeof(msg), "ciphertext match (%lu bytes)",
                 (unsigned long)hel);
        report(name, "PASS", msg);
    } else {
        snprintf(msg, sizeof(msg),
                 "hw rc=0x%08lx len=%lu soft rc=0x%08lx len=%lu",
                 (unsigned long)r1, (unsigned long)hel,
                 (unsigned long)r2, (unsigned long)sel);
        report(name, "DIFF", msg);
        if (r1 == SAR_OK) hexdump("hw", he, hel);
        if (r2 == SAR_OK) hexdump("sw", se, sel);
    }

    /* Cross-decrypt: each library decrypts the other's ciphertext. */
    if (r1 == SAR_OK && r2 == SAR_OK && hel == sel) {
        hdl = sizeof(hd);
        sdl = sizeof(sd);
        ULONG dh = hw->DecryptInit(hh, p);
        ULONG ds = sw->DecryptInit(hs, p);
        if (dh == SAR_OK) dh = hw->Decrypt(hh, se, sel, hd, &hdl);
        if (ds == SAR_OK) ds = sw->Decrypt(hs, he, hel, sd, &sdl);
        int ok = dh == SAR_OK && ds == SAR_OK &&
                 hdl == 16 && sdl == 16 &&
                 memcmp(hd, plain, 16) == 0 && memcmp(sd, plain, 16) == 0;
        snprintf(msg, sizeof(msg), "hw<-soft=%s soft<-hw=%s",
                 (dh == SAR_OK && hdl == 16 && memcmp(hd, plain, 16) == 0)
                     ? "OK" : "FAIL",
                 (ds == SAR_OK && sdl == 16 && memcmp(sd, plain, 16) == 0)
                     ? "OK" : "FAIL");
        report("SM4 cross-decrypt", ok ? "PASS" : "DIFF", msg);
    }

    if (hh) hw->CloseHandle(hh);
    if (hs) sw->CloseHandle(hs);
}

static void test_digest(API *hw, API *sw, DEVHANDLE hdev, DEVHANDLE sdev,
                        ULONG alg, const char *name)
{
    HANDLE hh = NULL, hs = NULL;
    ULONG r1 = hw->DigestInit(hdev, alg, NULL, NULL, 0, &hh);
    ULONG r2 = sw->DigestInit(sdev, alg, NULL, NULL, 0, &hs);
    if (r1 != SAR_OK || r2 != SAR_OK) {
        char msg[128];
        snprintf(msg, sizeof(msg), "hw=0x%08lx soft=0x%08lx",
                 (unsigned long)r1, (unsigned long)r2);
        report(name, r1 == r2 ? "PASS" : "DIFF", msg);
        if (hh) hw->CloseHandle(hh);
        if (hs) sw->CloseHandle(hs);
        return;
    }
    unsigned char ho[64], so[64];
    ULONG hol = sizeof(ho), sol = sizeof(so);
    r1 = hw->Digest(hh, (BYTE *)"abc", 3, ho, &hol);
    r2 = sw->Digest(hs, (BYTE *)"abc", 3, so, &sol);
    int ok = r1 == SAR_OK && r2 == SAR_OK && hol == sol &&
             memcmp(ho, so, hol) == 0;
    char msg[160];
    snprintf(msg, sizeof(msg), "len hw=%lu soft=%lu", (unsigned long)hol,
             (unsigned long)sol);
    report(name, ok ? "PASS" : "DIFF", msg);
    if (!ok && hol == sol)
        hexdump("hw", ho, hol);
    if (!ok && hol == sol)
        hexdump("sw", so, sol);
    if (hh) hw->CloseHandle(hh);
    if (hs) sw->CloseHandle(hs);
}

static void test_mac(API *hw, API *sw, DEVHANDLE hdev, DEVHANDLE sdev)
{
    unsigned char key[16], data[32];
    for (int i = 0; i < 16; i++) key[i] = (unsigned char)(0x70 + i);
    for (int i = 0; i < 32; i++) data[i] = (unsigned char)i;
    HANDLE hkh = NULL, hks = NULL, hmh = NULL, hms = NULL;
    ULONG r1 = hw->SetSymmKey(hdev, key, SGD_SM4_MAC, &hkh);
    ULONG r2 = sw->SetSymmKey(sdev, key, SGD_SM4_MAC, &hks);
    BLOCKCIPHERPARAM p;
    memset(&p, 0, sizeof(p));
    p.PaddingType = 1;  /* vendor MAC returns data only with padding enabled */
    if (r1 == SAR_OK) r1 = hw->MacInit(hkh, &p, &hmh);
    if (r2 == SAR_OK) r2 = sw->MacInit(hks, &p, &hms);
    unsigned char hmac[32], smac[32];
    ULONG hml = sizeof(hmac), sml = sizeof(smac);
    if (r1 == SAR_OK) r1 = hw->Mac(hmh, data, sizeof(data), hmac, &hml);
    if (r2 == SAR_OK) r2 = sw->Mac(hms, data, sizeof(data), smac, &sml);
    int ok = r1 == SAR_OK && r2 == SAR_OK && hml == sml &&
             hml == 16 && memcmp(hmac, smac, hml) == 0;
    char msg[160];
    snprintf(msg, sizeof(msg), "hw rc=0x%08lx len=%lu soft rc=0x%08lx len=%lu",
             (unsigned long)r1, (unsigned long)hml, (unsigned long)r2,
             (unsigned long)sml);
    report("SM4 CBC-MAC", ok ? "PASS" : "DIFF", msg);
    if (!ok && hml == sml) {
        hexdump("hw", hmac, hml);
        hexdump("sw", smac, sml);
    }
    if (hmh) hw->CloseHandle(hmh);
    if (hms) sw->CloseHandle(hms);
    if (hkh) hw->CloseHandle(hkh);
    if (hks) sw->CloseHandle(hks);
}

int main(int argc, char **argv)
{
    const char *hwpath = argc > 1 ? argv[1] : getenv("VENDOR_SKF_LIB");
    const char *swpath = argc > 2 ? argv[2] : "./libsoftskf.so";
    if (!hwpath || !*hwpath) {
        fprintf(stderr,
            "usage: %s <vendor-libskf.so> [libsoftskf.so]\n"
            "   or: VENDOR_SKF_LIB=/path/to/vendor/libskf.so %s\n",
            argv[0], argv[0]);
        return 2;
    }

    API hw, sw;
    if (load_api(hwpath, &hw) != 0 || load_api(swpath, &sw) != 0)
        return 1;

    char hwname[128], swname[128];
    if (!pick_device(&hw, 1, hwname, sizeof(hwname)) ||
        !pick_device(&sw, 0, swname, sizeof(swname))) {
        fprintf(stderr, "device enumeration failed\n");
        return 1;
    }
    printf("hardware device: %s\nsoftware device: %s\n\n", hwname, swname);

    DEVHANDLE hdev = NULL, sdev = NULL;
    ULONG r1 = hw.ConnectDev((LPSTR)hwname, &hdev);
    ULONG r2 = sw.ConnectDev((LPSTR)swname, &sdev);
    char msg[256];
    snprintf(msg, sizeof(msg), "hw=0x%08lx soft=0x%08lx",
             (unsigned long)r1, (unsigned long)r2);
    report("SKF_ConnectDev", r1 == SAR_OK && r2 == SAR_OK ? "PASS" : "FAIL",
           msg);
    if (!hdev || !sdev)
        return 1;

    ULONG hs = 0, ss = 0;
    r1 = hw.GetDevState((LPSTR)hwname, &hs);
    r2 = sw.GetDevState((LPSTR)swname, &ss);
    snprintf(msg, sizeof(msg), "hw=0x%08lx/%lu soft=0x%08lx/%lu",
             (unsigned long)r1, (unsigned long)hs, (unsigned long)r2,
             (unsigned long)ss);
    report("SKF_GetDevState", r1 == SAR_OK && r2 == SAR_OK &&
           hs && ss ? "PASS" : "FAIL", msg);

    DEVINFO hi, si;
    memset(&hi, 0, sizeof(hi));
    memset(&si, 0, sizeof(si));
    r1 = hw.GetDevInfo(hdev, &hi);
    r2 = sw.GetDevInfo(sdev, &si);
    snprintf(msg, sizeof(msg), "hw=%s/%s caps=0x%lx soft=%s/%s caps=0x%lx",
             (char *)hi.Manufacturer, (char *)hi.SerialNumber,
             (unsigned long)hi.AlgSymCap, (char *)si.Manufacturer,
             (char *)si.SerialNumber, (unsigned long)si.AlgSymCap);
    report("SKF_GetDevInfo", r1 == SAR_OK && r2 == SAR_OK ? "PASS" : "FAIL",
           msg);

    int hk = list_has_app(&hw, hdev, "KEDA");
    int sk = list_has_app(&sw, sdev, "KEDA");
    snprintf(msg, sizeof(msg), "hw=%d soft=%d", hk, sk);
    report("SKF_EnumApplication contains KEDA",
           hk && sk ? "PASS" : "DIFF", msg);

    HAPPLICATION happ = NULL, sapp = NULL;
    r1 = hw.OpenApplication(hdev, (LPSTR)"KEDA", &happ);
    r2 = sw.OpenApplication(sdev, (LPSTR)"KEDA", &sapp);
    snprintf(msg, sizeof(msg), "hw=0x%08lx soft=0x%08lx",
             (unsigned long)r1, (unsigned long)r2);
    report("SKF_OpenApplication(KEDA)",
           r1 == SAR_OK && r2 == SAR_OK ? "PASS" : "FAIL", msg);
    if (!happ || !sapp)
        return 1;

    ULONG hmax = 0, hrem = 0, smax = 0, srem = 0;
    BOOL hdef = 0, sdef = 0;
    LONG hp = hw.GetPINInfo(happ, USER_TYPE, &hmax, &hrem, &hdef);
    LONG sp = sw.GetPINInfo(sapp, USER_TYPE, &smax, &srem, &sdef);
    snprintf(msg, sizeof(msg),
             "hw max=%lu rem=%lu def=%ld soft max=%lu rem=%lu def=%ld",
             (unsigned long)hmax, (unsigned long)hrem, (long)hdef,
             (unsigned long)smax, (unsigned long)srem, (long)sdef);
    report("SKF_GetPINInfo",
           hp == SAR_OK && sp == SAR_OK &&
           hmax == smax && hrem == srem && hdef == sdef ? "PASS" : "DIFF",
           msg);

    ULONG hretry = 0, sretry = 0;
    r1 = hw.VerifyPIN(happ, USER_TYPE, (LPSTR)"123456", &hretry);
    r2 = sw.VerifyPIN(sapp, USER_TYPE, (LPSTR)"123456", &sretry);
    snprintf(msg, sizeof(msg), "hw=0x%08lx soft=0x%08lx",
             (unsigned long)r1, (unsigned long)r2);
    report("SKF_VerifyPIN(KEDA/123456)",
           r1 == SAR_OK && r2 == SAR_OK ? "PASS" : "FAIL", msg);

    unsigned char hrnd[16], srnd[16];
    r1 = hw.GenRandom(hdev, hrnd, sizeof(hrnd));
    r2 = sw.GenRandom(sdev, srnd, sizeof(srnd));
    int hnonzero = 0, snonzero = 0;
    for (int i = 0; i < 16; i++) {
        hnonzero |= hrnd[i];
        snonzero |= srnd[i];
    }
    snprintf(msg, sizeof(msg), "hw=0x%08lx soft=0x%08lx",
             (unsigned long)r1, (unsigned long)r2);
    report("SKF_GenRandom", r1 == SAR_OK && r2 == SAR_OK &&
           hnonzero && snonzero ? "PASS" : "FAIL", msg);

    r1 = hw.LockDev(hdev, 1000);
    r2 = sw.LockDev(sdev, 1000);
    ULONG u1 = hw.UnlockDev(hdev);
    ULONG u2 = sw.UnlockDev(sdev);
    snprintf(msg, sizeof(msg), "lock=0x%08lx/0x%08lx unlock=0x%08lx/0x%08lx",
             (unsigned long)r1, (unsigned long)r2, (unsigned long)u1,
             (unsigned long)u2);
    report("SKF_LockDev/UnlockDev",
           r1 == SAR_OK && r2 == SAR_OK && u1 == SAR_OK && u2 == SAR_OK
               ? "PASS" : "FAIL", msg);

    /* SM4 deterministic cross-check. */
    test_sym(&hw, &sw, hdev, sdev, SGD_SM4_ECB, "SM4-ECB ciphertext");
    test_sym(&hw, &sw, hdev, sdev, SGD_SM4_CBC, "SM4-CBC ciphertext");
    test_sym(&hw, &sw, hdev, sdev, SGD_SM4_CFB, "SM4-CFB128 ciphertext");
    test_sym(&hw, &sw, hdev, sdev, SGD_SM4_OFB, "SM4-OFB ciphertext");
    test_mac(&hw, &sw, hdev, sdev);

    /* Digest cross-check. */
    test_digest(&hw, &sw, hdev, sdev, SGD_SM3, "SM3 digest");
    test_digest(&hw, &sw, hdev, sdev, SGD_SHA1, "SHA1 digest");
    test_digest(&hw, &sw, hdev, sdev, SGD_SHA256, "SHA256 digest");

    /* SM1 / SSF33: expected difference. */
    unsigned char key[16] = {0};
    HANDLE hh = NULL;
    HANDLE sh = NULL;
    r1 = hw.SetSymmKey(hdev, key, SGD_SM1_ECB, &hh);
    r2 = sw.SetSymmKey(sdev, key, SGD_SM1_ECB, &sh);
    if (hh) hw.CloseHandle(hh);
    snprintf(msg, sizeof(msg), "hw=0x%08lx soft=0x%08lx", (unsigned long)r1,
             (unsigned long)r2);
    report("SM1 expected difference",
           r1 == SAR_OK && r2 == SAR_NOTSUPPORTYETERR ? "DIFF" : "PASS", msg);
    if (sh) sw.CloseHandle(sh);

    /* Hardware KEDA container: hardware sign -> soft verify. */
    char hwctn[128];
    const char *ctn = find_container(&hw, happ, hwctn, sizeof(hwctn));
    HCONTAINER hctn = NULL;
    ECCPUBLICKEYBLOB hwpub;
    int have_hw_ecc = 0;
    if (ctn) {
        r1 = hw.OpenContainer(happ, (LPSTR)ctn, &hctn);
        ULONG ctype = 0;
        if (r1 == SAR_OK)
            r1 = hw.GetContainerType(hctn, &ctype);
        if (r1 == SAR_OK) {
            ULONG publen = sizeof(hwpub);
            r1 = hw.ExportPublicKey(hctn, TRUE, (BYTE *)&hwpub, &publen);
            have_hw_ecc = (r1 == SAR_OK && publen == sizeof(hwpub) &&
                           hwpub.BitLen == 256);
        }
    }
    unsigned char digest[32];
    for (int i = 0; i < 32; i++) digest[i] = (unsigned char)i;

    if (have_hw_ecc) {
        ECCSIGNATUREBLOB hwsig;
        r1 = hw.ECCSignData(hctn, digest, sizeof(digest), &hwsig);
        r2 = sw.ECCVerify(sdev, &hwpub, digest, sizeof(digest), &hwsig);
        snprintf(msg, sizeof(msg), "hw sign=0x%08lx soft verify=0x%08lx",
                 (unsigned long)r1, (unsigned long)r2);
        report("HW SM2 sign -> soft verify",
               r1 == SAR_OK && r2 == SAR_OK ? "PASS" : "DIFF", msg);
    } else {
        report("HW SM2 sign -> soft verify", "NA",
               "no hardware ECC container");
    }

    /* Soft ECC container: soft sign -> hardware verify. */
    sw.DeleteContainer(sapp, (LPSTR)"XVAL_ECC");
    HCONTAINER sctn = NULL;
    r2 = sw.CreateContainer(sapp, (LPSTR)"XVAL_ECC", &sctn);
    ECCPUBLICKEYBLOB swpub;
    if (r2 == SAR_OK)
        r2 = sw.GenECCKeyPair(sctn, SGD_SM2, &swpub);
    ECCSIGNATUREBLOB swsig;
    if (r2 == SAR_OK)
        r2 = sw.ECCSignData(sctn, digest, sizeof(digest), &swsig);
    r1 = SAR_FAIL;
    if (r2 == SAR_OK)
        r1 = hw.ECCVerify(hdev, &swpub, digest, sizeof(digest), &swsig);
    snprintf(msg, sizeof(msg), "soft sign=0x%08lx hw verify=0x%08lx",
             (unsigned long)r2, (unsigned long)r1);
    report("Soft SM2 sign -> HW verify",
           r2 == SAR_OK && r1 == SAR_OK ? "PASS" : "DIFF", msg);
    if (sctn) sw.CloseContainer(sctn);
    sw.DeleteContainer(sapp, (LPSTR)"XVAL_ECC");

    /* External SM2 key pair: cross sign/verify and encrypt/decrypt. */
    EC_KEY *ik = EC_KEY_new_by_curve_name(NID_sm2);
    EC_KEY_generate_key(ik);
    ECCPUBLICKEYBLOB xpub;
    ECCPRIVATEKEYBLOB xpri;
    fill_ecc_pub(ik, &xpub);
    fill_ecc_priv(ik, &xpri);

    ECCSIGNATUREBLOB xsig;
    r1 = hw.ExtECCSign(hdev, &xpri, digest, sizeof(digest), &xsig);
    r2 = sw.ExtECCVerify(sdev, &xpub, digest, sizeof(digest), &xsig);
    snprintf(msg, sizeof(msg), "hw sign=0x%08lx soft verify=0x%08lx",
             (unsigned long)r1, (unsigned long)r2);
    report("ExtECCSign HW -> soft verify",
           r1 == SAR_OK && r2 == SAR_OK ? "PASS" : "DIFF", msg);

    r2 = sw.ExtECCSign(sdev, &xpri, digest, sizeof(digest), &xsig);
    r1 = hw.ExtECCVerify(hdev, &xpub, digest, sizeof(digest), &xsig);
    snprintf(msg, sizeof(msg), "soft sign=0x%08lx hw verify=0x%08lx",
             (unsigned long)r2, (unsigned long)r1);
    report("ExtECCSign soft -> HW verify",
           r2 == SAR_OK && r1 == SAR_OK ? "PASS" : "DIFF", msg);

    unsigned char plain[16], back[32];
    for (int i = 0; i < 16; i++) plain[i] = (unsigned char)(0x90 + i);
    ECCCIPHERBLOB *hc = calloc(1, sizeof(ECCCIPHERBLOB) + 16);
    ECCCIPHERBLOB *sc = calloc(1, sizeof(ECCCIPHERBLOB) + 16);
    ULONG blen = sizeof(back);
    r1 = hw.ExtECCEncrypt(hdev, &xpub, plain, sizeof(plain), hc);
    ULONG d1 = sw.ExtECCDecrypt(sdev, &xpri, hc, back, &blen);
    int ok1 = r1 == SAR_OK && d1 == SAR_OK && blen == 16 &&
              memcmp(back, plain, 16) == 0;
    snprintf(msg, sizeof(msg), "hw enc=0x%08lx soft dec=0x%08lx",
             (unsigned long)r1, (unsigned long)d1);
    report("ExtECCEncrypt HW -> soft decrypt", ok1 ? "PASS" : "DIFF", msg);

    /* The soft private blob layout uses PrivateKey+32; hw expects the same. */
    blen = sizeof(back);
    r2 = sw.ExtECCEncrypt(sdev, &xpub, plain, sizeof(plain), sc);
    ULONG d2 = hw.ExtECCDecrypt(hdev, &xpri, sc, back, &blen);
    int ok2 = r2 == SAR_OK && d2 == SAR_OK && blen == 16 &&
              memcmp(back, plain, 16) == 0;
    snprintf(msg, sizeof(msg), "soft enc=0x%08lx hw dec=0x%08lx",
             (unsigned long)r2, (unsigned long)d2);
    report("ExtECCEncrypt soft -> HW decrypt", ok2 ? "PASS" : "DIFF", msg);
    free(hc);
    free(sc);
    EC_KEY_free(ik);

    /* Soft RSA sign -> hardware external RSA verify (if supported). */
    sw.DeleteContainer(sapp, (LPSTR)"XVAL_RSA");
    HCONTAINER srctn = NULL;
    r2 = sw.CreateContainer(sapp, (LPSTR)"XVAL_RSA", &srctn);
    RSAPUBLICKEYBLOB rpub;
    if (r2 == SAR_OK)
        r2 = sw.GenRSAKeyPair(srctn, 1024, &rpub);
    unsigned char rsig[256];
    ULONG rsiglen = sizeof(rsig);
    if (r2 == SAR_OK)
        r2 = sw.RSASignData(srctn, digest, sizeof(digest), rsig, &rsiglen);
    r1 = SAR_FAIL;
    if (r2 == SAR_OK)
        r1 = hw.RSAVerify(hdev, &rpub, digest, sizeof(digest), rsig, rsiglen);
    snprintf(msg, sizeof(msg), "soft sign=0x%08lx hw verify=0x%08lx",
             (unsigned long)r2, (unsigned long)r1);
    report("Soft RSA sign -> HW verify",
           r2 == SAR_OK && r1 == SAR_OK ? "PASS" : "DIFF", msg);
    if (srctn) sw.CloseContainer(srctn);
    sw.DeleteContainer(sapp, (LPSTR)"XVAL_RSA");

    if (hctn) hw.CloseContainer(hctn);
    hw.CloseApplication(happ);
    sw.CloseApplication(sapp);
    hw.DisConnectDev(hdev);
    sw.DisConnectDev(sdev);
    dlclose(hw.lib);
    dlclose(sw.lib);

    printf("\nSummary: PASS=%d FAIL=%d DIFF=%d NA=%d\n",
           passes, fails, diffs, nas);
    return fails ? 1 : 0;
}
