/*
 * Differential ECC session-key export test.
 *
 * SKF_ECCExportSessionKey() must return a handle whose key is exactly the
 * key wrapped in the ECCCipherBlob.  The wrapped key is recovered with the
 * recipient's software SM2 private key via SKF_ExtECCDecrypt(), then both
 * keys are used to encrypt the same block and the ciphertexts are compared.
 *
 * This does not modify the device: it only opens KEDA, reads a container,
 * and generates an ephemeral session key.
 *
 * Usage: ./skf_session_ecc_test ./lib/libskf.so ./reimpl/libskf_native.so
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include "skf.h"

typedef struct lib {
    void *h;
    typeof(&SKF_EnumDev) EnumDev;
    typeof(&SKF_ConnectDev) ConnectDev;
    typeof(&SKF_DisConnectDev) DisConnectDev;
    typeof(&SKF_OpenApplication) OpenApplication;
    typeof(&SKF_CloseApplication) CloseApplication;
    typeof(&SKF_VerifyPIN) VerifyPIN;
    typeof(&SKF_EnumContainer) EnumContainer;
    typeof(&SKF_OpenContainer) OpenContainer;
    typeof(&SKF_CloseContainer) CloseContainer;
    typeof(&SKF_ECCExportSessionKey) ECCExportSessionKey;
    typeof(&SKF_ExtECCDecrypt) ExtECCDecrypt;
    typeof(&SKF_EncryptInit) EncryptInit;
    typeof(&SKF_Encrypt) Encrypt;
    typeof(&SKF_CloseHandle) CloseHandle;
} LIB;

static int load_lib(LIB *l, const char *path)
{
    memset(l, 0, sizeof(*l));
    l->h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!l->h) {
        fprintf(stderr, "dlopen %s: %s\n", path, dlerror());
        return -1;
    }
#define SYM(n) do { \
    l->n = (typeof(&SKF_##n))dlsym(l->h, "SKF_" #n); \
    if (!l->n) { fprintf(stderr, "missing SKF_%s\n", #n); return -1; } \
} while (0)
    SYM(EnumDev);
    SYM(ConnectDev);
    SYM(DisConnectDev);
    SYM(OpenApplication);
    SYM(CloseApplication);
    SYM(VerifyPIN);
    SYM(EnumContainer);
    SYM(OpenContainer);
    SYM(CloseContainer);
    SYM(ECCExportSessionKey);
    SYM(ExtECCDecrypt);
    SYM(EncryptInit);
    SYM(Encrypt);
    SYM(CloseHandle);
#undef SYM
    return 0;
}

static int make_key(ECCPUBLICKEYBLOB *pub, ECCPRIVATEKEYBLOB *pri)
{
    EC_KEY *k = EC_KEY_new_by_curve_name(NID_sm2);
    const EC_GROUP *g;
    const EC_POINT *p;
    BIGNUM *x = BN_new(), *y = BN_new();

    if (!k || !x || !y || EC_KEY_generate_key(k) != 1)
        return -1;
    g = EC_KEY_get0_group(k);
    p = EC_KEY_get0_public_key(k);
    memset(pub, 0, sizeof(*pub));
    memset(pri, 0, sizeof(*pri));
    pub->BitLen = 256;
    pri->BitLen = 256;
    if (EC_POINT_get_affine_coordinates(g, p, x, y, NULL) != 1 ||
        BN_bn2binpad(x, pub->XCoordinate + 32, 32) != 32 ||
        BN_bn2binpad(y, pub->YCoordinate + 32, 32) != 32 ||
        BN_bn2binpad(EC_KEY_get0_private_key(k), pri->PrivateKey + 32, 32) != 32) {
        BN_free(x); BN_free(y); EC_KEY_free(k);
        return -1;
    }
    BN_free(x); BN_free(y); EC_KEY_free(k);
    return 0;
}

static int encrypt_block(LIB *l, HANDLE h, const unsigned char *in,
                         unsigned char *out)
{
    BLOCKCIPHERPARAM p;
    ULONG n = 16;
    memset(&p, 0, sizeof(p));
    if (l->EncryptInit(h, p) != SAR_OK)
        return -1;
    return l->Encrypt(h, (BYTE *)in, 16, out, &n) == SAR_OK && n == 16 ? 0 : -1;
}

static int sm4_ecb_encrypt(const unsigned char key[16],
                          const unsigned char in[16], unsigned char out[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, total = 0, ok = 0;
    unsigned char iv[16] = {0};
    if (ctx && EVP_EncryptInit_ex(ctx, EVP_sm4_ecb(), NULL, key, iv) == 1 &&
        EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
        EVP_EncryptUpdate(ctx, out, &n, in, 16) == 1) {
        total = n;
        n = 0;
        if (EVP_EncryptFinal_ex(ctx, out + total, &n) == 1) {
            total += n;
            ok = total == 16;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int run_lib(LIB *l, const char *name)
{
    ULONG n = 0, clen = 0;
    char *names = NULL, *ctns = NULL, *ctn = NULL;
    DEVHANDLE d = NULL;
    HAPPLICATION app = NULL;
    HCONTAINER c = NULL;
    HANDLE h1 = NULL;
    ECCPUBLICKEYBLOB pub;
    ECCPRIVATEKEYBLOB pri;
    unsigned char session[64];
    unsigned char plain[16], c1out[16], c2out[16];
    ECCCIPHERBLOB *cipher = NULL;
    int ok = 0;

    for (int i = 0; i < 16; i++)
        plain[i] = (unsigned char)(0x30 + i);
    if (make_key(&pub, &pri) != 0)
        return -1;
    cipher = calloc(1, sizeof(ECCCIPHERBLOB) + 256);
    if (!cipher)
        return -1;

    if (l->EnumDev(TRUE, NULL, &n) != SAR_OK || n == 0)
        goto out;
    names = calloc(1, n + 1);
    if (!names || l->EnumDev(TRUE, (LPSTR)names, &n) != SAR_OK ||
        l->ConnectDev((LPSTR)names, &d) != SAR_OK)
        goto out;
    if (l->OpenApplication(d, (LPSTR)"KEDA", &app) != SAR_OK)
        goto out;
    ULONG retry = 0;
    if (l->VerifyPIN(app, USER_TYPE, (LPSTR)"123456", &retry) != SAR_OK)
        goto out;
    if (l->EnumContainer(app, NULL, &clen) != SAR_OK || clen == 0)
        goto out;
    ctns = calloc(1, clen + 1);
    if (!ctns || l->EnumContainer(app, (LPSTR)ctns, &clen) != SAR_OK)
        goto out;
    for (char *p = ctns; p < ctns + clen && *p; p += strlen(p) + 1) {
        if (strncmp(p, "K01231-", 7) == 0) { ctn = p; break; }
        if (!ctn) ctn = p;
    }
    if (!ctn || l->OpenContainer(app, (LPSTR)ctn, &c) != SAR_OK)
        goto out;

    ULONG r_export = l->ECCExportSessionKey(c, SGD_SM4_ECB, &pub, cipher, &h1);
    ULONG slen = sizeof(session);
    ULONG r_dec = r_export == SAR_OK
                      ? l->ExtECCDecrypt(d, &pri, cipher, session, &slen)
                      : 0xffffffff;
    int e1 = (r_dec == SAR_OK) ? encrypt_block(l, h1, plain, c1out) : -1;
    int e2 = (r_dec == SAR_OK) ? sm4_ecb_encrypt(session, plain, c2out) : -1;
    printf("[DBG] %s export=%lx clen=%lu dec=%lx slen=%lu enc=%d/%d\n",
           name, (unsigned long)r_export, (unsigned long)cipher->CipherLen,
           (unsigned long)r_dec, (unsigned long)slen, e1, e2);
    if (r_export != SAR_OK || r_dec != SAR_OK || e1 != 0 || e2 != 0)
        goto out;
    ok = memcmp(c1out, c2out, 16) == 0;

out:
    if (h1) l->CloseHandle(h1);
    if (c) l->CloseContainer(c);
    if (app) l->CloseApplication(app);
    if (d) l->DisConnectDev(d);
    free(names);
    free(ctns);
    free(cipher);
    printf("[%s] %s: session key matches wrapped ECCCipherBlob\n",
           ok ? "PASS" : "FAIL", name);
    return ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    LIB vendor, native;
    int failures = 0;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <vendor-lib> <native-lib>\n", argv[0]);
        return 2;
    }
    if (load_lib(&vendor, argv[1]) || load_lib(&native, argv[2]))
        return 2;
    failures += run_lib(&vendor, "vendor");
    failures += run_lib(&native, "native");
    if (failures == 0) {
        printf("[PASS] session-key differential test: vendor == native\n");
        return 0;
    }
    printf("[FAIL] session-key differential test: %d failure(s)\n", failures);
    return 1;
}
