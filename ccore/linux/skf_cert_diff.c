/*
 * Vendor vs native certificate differential test.
 *
 * Reads every container in the KEDA application with both libraries and
 * compares:
 *   - container type
 *   - signing/encryption certificate rc, length and bytes
 *   - signing public key rc, length and bytes
 *
 * It also parses the signing certificate and checks that its public key
 * matches the container's signing public key.
 *
 * Read-only: does not create, delete or import anything.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
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
    typeof(&SKF_GetContainerType) GetContainerType;
    typeof(&SKF_ExportCertificate) ExportCertificate;
    typeof(&SKF_ExportPublicKey) ExportPublicKey;
} LIB;

typedef struct res {
    char name[80];
    ULONG type;
    ULONG type_rc;
    ULONG cert_rc[2], cert_len[2];
    unsigned char cert[2][8192];
    ULONG pub_rc, pub_len;
    unsigned char pub[sizeof(RSAPUBLICKEYBLOB)];
} RES;

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
    SYM(EnumDev); SYM(ConnectDev); SYM(DisConnectDev);
    SYM(OpenApplication); SYM(CloseApplication); SYM(VerifyPIN);
    SYM(EnumContainer); SYM(OpenContainer); SYM(CloseContainer);
    SYM(GetContainerType); SYM(ExportCertificate); SYM(ExportPublicKey);
#undef SYM
    return 0;
}

static int collect(LIB *l, const char *path, RES **out, int *count)
{
    *out = NULL;
    *count = 0;
    if (load_lib(l, path) != 0)
        return -1;

    ULONG n = 0;
    if (l->EnumDev(TRUE, NULL, &n) != SAR_OK || n == 0) {
        fprintf(stderr, "%s: no device\n", path);
        return -1;
    }
    char *names = calloc(1, n + 1);
    l->EnumDev(TRUE, (LPSTR)names, &n);
    DEVHANDLE dev = NULL;
    ULONG rc = l->ConnectDev((LPSTR)names, &dev);
    free(names);
    if (rc != SAR_OK) {
        fprintf(stderr, "%s: ConnectDev rc=0x%lx\n", path, (unsigned long)rc);
        return -1;
    }
    HAPPLICATION app = NULL;
    rc = l->OpenApplication(dev, (LPSTR)"KEDA", &app);
    if (rc != SAR_OK) {
        fprintf(stderr, "%s: OpenApplication rc=0x%lx\n", path, (unsigned long)rc);
        l->DisConnectDev(dev);
        return -1;
    }
    ULONG retry = 0;
    rc = l->VerifyPIN(app, USER_TYPE, (LPSTR)"123456", &retry);
    if (rc != SAR_OK) {
        fprintf(stderr, "%s: VerifyPIN rc=0x%lx\n", path, (unsigned long)rc);
        l->CloseApplication(app);
        l->DisConnectDev(dev);
        return -1;
    }

    ULONG clen = 0;
    l->EnumContainer(app, NULL, &clen);
    char *ctns = calloc(1, clen + 1);
    if (clen)
        l->EnumContainer(app, (LPSTR)ctns, &clen);
    int cap = 0;
    for (char *p = ctns; p < ctns + clen && *p; p += strlen(p) + 1)
        cap++;
    RES *r = calloc((size_t)cap, sizeof(*r));
    int k = 0;
    for (char *p = ctns; p < ctns + clen && *p; p += strlen(p) + 1) {
        snprintf(r[k].name, sizeof(r[k].name), "%s", p);
        HCONTAINER c = NULL;
        rc = l->OpenContainer(app, (LPSTR)p, &c);
        if (rc != SAR_OK) {
            r[k].type_rc = r[k].cert_rc[0] = r[k].cert_rc[1] = r[k].pub_rc = rc;
            k++;
            continue;
        }
        r[k].type_rc = l->GetContainerType(c, &r[k].type);
        for (int s = 0; s < 2; s++) {
            r[k].cert_len[s] = sizeof(r[k].cert[s]);
            r[k].cert_rc[s] = l->ExportCertificate(c, s ? FALSE : TRUE,
                                                   r[k].cert[s],
                                                   &r[k].cert_len[s]);
        }
        r[k].pub_len = sizeof(r[k].pub);
        r[k].pub_rc = l->ExportPublicKey(c, TRUE, r[k].pub, &r[k].pub_len);
        l->CloseContainer(c);
        k++;
    }
    free(ctns);
    l->CloseApplication(app);
    l->DisConnectDev(dev);
    *out = r;
    *count = k;
    return 0;
}

static void hexdiff(const char *tag, const unsigned char *a, ULONG alen,
                    const unsigned char *b, ULONG blen, int *bad)
{
    if (alen != blen || memcmp(a, b, alen) != 0) {
        printf("  [DIFF] %s: vendor len=%lu native len=%lu\n", tag,
               (unsigned long)alen, (unsigned long)blen);
        *bad = 1;
    }
}

/* SKF blobs may store integers in either byte order depending on the
 * vendor path that produced them; accept either representation. */
static int bn_matches_field(const BIGNUM *v, const unsigned char *field, int n)
{
    unsigned char buf[MAX_RSA_MODULUS_LEN];
    int eq = 0;
    if (n <= 0 || n > (int)sizeof(buf))
        return 0;
    memcpy(buf, field, (size_t)n);
    BIGNUM *b = BN_bin2bn(buf, n, NULL);
    if (b && BN_cmp(v, b) == 0)
        eq = 1;
    BN_free(b);
    if (eq)
        return 1;
    for (int i = 0; i < n / 2; i++) {
        unsigned char t = buf[i];
        buf[i] = buf[n - 1 - i];
        buf[n - 1 - i] = t;
    }
    b = BN_bin2bn(buf, n, NULL);
    if (b && BN_cmp(v, b) == 0)
        eq = 1;
    BN_free(b);
    return eq;
}

static int cert_pub_matches(const unsigned char *der, ULONG derlen,
                            const unsigned char *pub, ULONG publen)
{
    const unsigned char *p = der;
    X509 *x = d2i_X509(NULL, &p, (long)derlen);
    if (!x)
        return -1;
    EVP_PKEY *pk = X509_get_pubkey(x);
    int ret = -1;
    if (pk && publen == sizeof(ECCPUBLICKEYBLOB)) {
        const ECCPUBLICKEYBLOB *ep = (const ECCPUBLICKEYBLOB *)pub;
        BIGNUM *bx = NULL, *by = NULL;
        int gx = EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_PUB_X, &bx);
        int gy = EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_PUB_Y, &by);
        if (gx != 1 || gy != 1) {
            EC_KEY *k = EVP_PKEY_get1_EC_KEY(pk);
            if (k) {
                const EC_GROUP *g = EC_KEY_get0_group(k);
                const EC_POINT *pt = EC_KEY_get0_public_key(k);
                BN_free(bx);
                BN_free(by);
                bx = BN_new(); by = BN_new();
                if (!(bx && by && g && pt &&
                      EC_POINT_get_affine_coordinates(g, pt, bx, by,
                                                      NULL) == 1))
                    BN_free(bx), BN_free(by), bx = by = NULL;
                EC_KEY_free(k);
            }
        }
        if (bx && by) {
            unsigned char cx[32], cy[32];
            BN_bn2binpad(bx, cx, 32);
            BN_bn2binpad(by, cy, 32);
            ret = memcmp(cx, ep->XCoordinate + 32, 32) == 0 &&
                  memcmp(cy, ep->YCoordinate + 32, 32) == 0 ? 0 : -1;
        }
        BN_free(bx); BN_free(by);
    } else if (pk && publen == sizeof(RSAPUBLICKEYBLOB)) {
        const RSAPUBLICKEYBLOB *rp = (const RSAPUBLICKEYBLOB *)pub;
        RSA *r = EVP_PKEY_get1_RSA(pk);
        if (r) {
            const BIGNUM *n = NULL, *e = NULL;
            RSA_get0_key(r, &n, &e, NULL);
            if (n && e &&
                bn_matches_field(n, rp->Modulus, MAX_RSA_MODULUS_LEN) &&
                bn_matches_field(e, rp->PublicExponent,
                                 MAX_RSA_EXPONENT_LEN))
                ret = 0;
            RSA_free(r);
        }
    }
    EVP_PKEY_free(pk);
    X509_free(x);
    return ret;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <vendor-libskf.so> <native-libskf.so>\n",
                argv[0]);
        return 2;
    }
    LIB v, n;
    RES *vr = NULL, *nr = NULL;
    int vc = 0, nc = 0;
    if (collect(&v, argv[1], &vr, &vc) != 0)
        return 2;
    if (collect(&n, argv[2], &nr, &nc) != 0)
        return 2;

    int bad = 0;
    if (vc != nc) {
        printf("[FAIL] container count: vendor=%d native=%d\n", vc, nc);
        bad = 1;
    }
    for (int i = 0; i < vc && i < nc; i++) {
        if (strcmp(vr[i].name, nr[i].name) != 0) {
            printf("[FAIL] container name[%d]: vendor=%s native=%s\n", i,
                   vr[i].name, nr[i].name);
            bad = 1;
            continue;
        }
        int row_bad = 0;
        if (vr[i].type_rc != nr[i].type_rc || vr[i].type != nr[i].type)
            row_bad = 1;
        for (int s = 0; s < 2; s++) {
            if (vr[i].cert_rc[s] != nr[i].cert_rc[s] ||
                (vr[i].cert_rc[s] == SAR_OK &&
                 vr[i].cert_len[s] != nr[i].cert_len[s]))
                row_bad = 1;
            if (vr[i].cert_rc[s] == SAR_OK && nr[i].cert_rc[s] == SAR_OK)
                hexdiff(s ? "enc cert" : "sign cert",
                        vr[i].cert[s], vr[i].cert_len[s],
                        nr[i].cert[s], nr[i].cert_len[s], &row_bad);
        }
        if (vr[i].pub_rc != nr[i].pub_rc ||
            (vr[i].pub_rc == SAR_OK && vr[i].pub_len != nr[i].pub_len))
            row_bad = 1;
        if (vr[i].pub_rc == SAR_OK && nr[i].pub_rc == SAR_OK)
            hexdiff("sign pub", vr[i].pub, vr[i].pub_len,
                    nr[i].pub, nr[i].pub_len, &row_bad);

        printf("[%s] %-40s type=%lu/%lu sign=%lx/%lx enc=%lx/%lx pub=%lx/%lx\n",
               row_bad ? "FAIL" : "PASS", vr[i].name,
               (unsigned long)vr[i].type, (unsigned long)nr[i].type,
               (unsigned long)vr[i].cert_rc[0], (unsigned long)nr[i].cert_rc[0],
               (unsigned long)vr[i].cert_rc[1], (unsigned long)nr[i].cert_rc[1],
               (unsigned long)vr[i].pub_rc, (unsigned long)nr[i].pub_rc);
        if (row_bad) {
            printf("        vendor vs native output differs\n");
            bad = 1;
        }

        /* Semantic check: the exported certificate must match the
         * container's signing public key. */
        if (vr[i].cert_rc[0] == SAR_OK && vr[i].pub_rc == SAR_OK) {
            int m = cert_pub_matches(vr[i].cert[0], vr[i].cert_len[0],
                                     vr[i].pub, vr[i].pub_len);
            if (m == 0) {
                printf("        cert <-> signing key: MATCH\n");
            } else {
                printf("        [FAIL] cert <-> signing key: MISMATCH"
                       " (container key len=%lu, cert key does not match)\n",
                       (unsigned long)vr[i].pub_len);
                bad = 1;
            }
        }
    }

    free(vr);
    free(nr);
    printf("\n%s\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
