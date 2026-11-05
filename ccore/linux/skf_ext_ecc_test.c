/*
 * Differential ECC external-key test.
 *
 * Verifies that the native implementation and the vendor library agree on
 * the SKF ECC blob layout (coordinates/keys are right-aligned in their
 * 64-byte fields) and on SM2 encryption/signature interoperability:
 *
 *   vendor encrypt -> native decrypt
 *   native encrypt -> vendor decrypt
 *   vendor sign    -> native verify
 *   native sign    -> vendor verify
 *
 * Requires a connected device (no device authentication is needed).
 *
 * Usage: ./skf_ext_ecc_test ./lib/libskf.so ./reimpl/libskf_native.so
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
#include "skf.h"

typedef struct lib {
    void *h;
    typeof(&SKF_EnumDev) EnumDev;
    typeof(&SKF_ConnectDev) ConnectDev;
    typeof(&SKF_DisConnectDev) DisConnectDev;
    typeof(&SKF_ExtECCEncrypt) ExtECCEncrypt;
    typeof(&SKF_ExtECCDecrypt) ExtECCDecrypt;
    typeof(&SKF_ExtECCSign) ExtECCSign;
    typeof(&SKF_ExtECCVerify) ExtECCVerify;
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
    SYM(ExtECCEncrypt);
    SYM(ExtECCDecrypt);
    SYM(ExtECCSign);
    SYM(ExtECCVerify);
#undef SYM
    return 0;
}

static DEVHANDLE connect_dev(LIB *l)
{
    ULONG n = 0;
    char *names;
    DEVHANDLE d = NULL;

    if (l->EnumDev(TRUE, NULL, &n) != SAR_OK || n == 0)
        return NULL;
    names = calloc(1, n + 1);
    if (!names)
        return NULL;
    if (l->EnumDev(TRUE, (LPSTR)names, &n) != SAR_OK ||
        l->ConnectDev((LPSTR)names, &d) != SAR_OK)
        d = NULL;
    free(names);
    return d;
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

static int check(const char *name, int ok)
{
    printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    return ok ? 0 : 1;
}

int main(int argc, char **argv)
{
    LIB vendor, native;
    DEVHANDLE dv = NULL, dn = NULL;
    ECCPUBLICKEYBLOB pub;
    ECCPRIVATEKEYBLOB pri;
    unsigned char plain[16], out[64], digest[32];
    ECCCIPHERBLOB *cv = NULL, *cn = NULL;
    ECCSIGNATUREBLOB sv, sn;
    int failures = 0;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <vendor-lib> <native-lib>\n", argv[0]);
        return 2;
    }
    if (load_lib(&vendor, argv[1]) || load_lib(&native, argv[2]))
        return 2;
    if (make_key(&pub, &pri) != 0) {
        fprintf(stderr, "cannot generate SM2 key\n");
        return 2;
    }
    dv = connect_dev(&vendor);
    dn = connect_dev(&native);
    if (!dv || !dn) {
        printf("[FAIL] device connect vendor=%p native=%p\n",
               (void *)dv, (void *)dn);
        return 1;
    }
    for (int i = 0; i < 16; i++)
        plain[i] = (unsigned char)(0x40 + i);
    for (int i = 0; i < 32; i++)
        digest[i] = (unsigned char)i;

    cv = calloc(1, sizeof(ECCCIPHERBLOB) + 256);
    cn = calloc(1, sizeof(ECCCIPHERBLOB) + 256);
    if (!cv || !cn) {
        printf("[FAIL] out of memory\n");
        return 1;
    }

    /* Encryption: vendor -> native. */
    ULONG rc = vendor.ExtECCEncrypt(dv, &pub, plain, sizeof(plain), cv);
    ULONG olen = sizeof(out);
    memset(out, 0, sizeof(out));
    ULONG rc2 = native.ExtECCDecrypt(dn, &pri, cv, out, &olen);
    failures += check("vendor encrypt -> native decrypt",
                      rc == SAR_OK && rc2 == SAR_OK &&
                      olen == sizeof(plain) &&
                      memcmp(out, plain, sizeof(plain)) == 0);

    /* Encryption: native -> vendor. */
    rc = native.ExtECCEncrypt(dn, &pub, plain, sizeof(plain), cn);
    olen = sizeof(out);
    memset(out, 0, sizeof(out));
    rc2 = vendor.ExtECCDecrypt(dv, &pri, cn, out, &olen);
    failures += check("native encrypt -> vendor decrypt",
                      rc == SAR_OK && rc2 == SAR_OK &&
                      olen == sizeof(plain) &&
                      memcmp(out, plain, sizeof(plain)) == 0);

    /* Signature: vendor -> native. */
    memset(&sv, 0, sizeof(sv));
    memset(&sn, 0, sizeof(sn));
    rc = vendor.ExtECCSign(dv, &pri, digest, sizeof(digest), &sv);
    rc2 = native.ExtECCVerify(dn, &pub, digest, sizeof(digest), &sv);
    failures += check("vendor sign -> native verify",
                      rc == SAR_OK && rc2 == SAR_OK);

    /* Signature: native -> vendor. */
    rc = native.ExtECCSign(dn, &pri, digest, sizeof(digest), &sn);
    rc2 = vendor.ExtECCVerify(dv, &pub, digest, sizeof(digest), &sn);
    failures += check("native sign -> vendor verify",
                      rc == SAR_OK && rc2 == SAR_OK);

    if (failures == 0) {
        printf("[PASS] external ECC differential test: vendor == native\n");
    } else {
        printf("[FAIL] external ECC differential test: %d failure(s)\n",
               failures);
    }

    vendor.DisConnectDev(dv);
    native.DisConnectDev(dn);
    free(cv);
    free(cn);
    return failures ? 1 : 0;
}
