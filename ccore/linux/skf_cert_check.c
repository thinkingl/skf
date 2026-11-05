/*
 * Read-only container certificate / public-key / signature consistency check.
 *
 * Usage: ./skf_cert_check <libskf.so> [container]
 *
 * Opens the KEDA application, verifies the development PIN 123456, then for
 * each container (or the named one) exports the signing certificate, exports
 * the signing public key, signs a 32-byte digest and verifies it with the
 * exported public key.  It prints whether the certificate public key matches
 * the exported public key and whether the signature verifies with it.
 *
 * Nothing is created or deleted.
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
    typeof(&SKF_ECCSignData) ECCSignData;
    typeof(&SKF_ECCVerify) ECCVerify;
    typeof(&SKF_RSASignData) RSASignData;
    typeof(&SKF_RSAVerify) RSAVerify;
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
    SYM(EnumDev); SYM(ConnectDev); SYM(DisConnectDev);
    SYM(OpenApplication); SYM(CloseApplication); SYM(VerifyPIN);
    SYM(EnumContainer); SYM(OpenContainer); SYM(CloseContainer);
    SYM(GetContainerType); SYM(ExportCertificate); SYM(ExportPublicKey);
    SYM(ECCSignData); SYM(ECCVerify); SYM(RSASignData); SYM(RSAVerify);
#undef SYM
    return 0;
}

static void hex(const char *tag, const unsigned char *p, int n)
{
    printf("%s=", tag);
    for (int i = 0; i < n; i++) printf("%02x", p[i]);
}

static int ec_pub_from_cert(X509 *x, unsigned char xbuf[32], unsigned char ybuf[32])
{
    EVP_PKEY *pk = X509_get_pubkey(x);
    if (!pk)
        return -1;

    /* OpenSSL 3 may expose SM2 keys only through the provider interface;
     * EVP_PKEY_get1_EC_KEY() then fails even though the key is EC/SM2. */
    BIGNUM *bx = NULL, *by = NULL;
    int gx = EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_PUB_X, &bx);
    int gy = EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_PUB_Y, &by);
    int ok = 0;
    if (gx == 1 && gy == 1) {
        BN_bn2binpad(bx, xbuf, 32);
        BN_bn2binpad(by, ybuf, 32);
        ok = 1;
    } else {
        EC_KEY *k = EVP_PKEY_get1_EC_KEY(pk);
        if (k) {
            const EC_GROUP *g = EC_KEY_get0_group(k);
            const EC_POINT *pt = EC_KEY_get0_public_key(k);
            BN_free(bx);
            BN_free(by);
            bx = BN_new();
            by = BN_new();
            if (bx && by && g && pt &&
                EC_POINT_get_affine_coordinates(g, pt, bx, by, NULL) == 1) {
                BN_bn2binpad(bx, xbuf, 32);
                BN_bn2binpad(by, ybuf, 32);
                ok = 1;
            }
            EC_KEY_free(k);
        }
    }
    BN_free(bx);
    BN_free(by);
    EVP_PKEY_free(pk);
    return ok ? 0 : -1;
}

/* Coordinates in SKF blobs are right-aligned in a 64-byte field. */
static void coord32(const unsigned char *field, unsigned char out[32])
{
    int nz = 0;
    for (int i = 0; i < 32; i++)
        if (field[i]) nz = 1;
    memcpy(out, field + (nz ? 0 : 32), 32);
}

static int rsa_pub_from_cert(X509 *x, unsigned char mod[256], unsigned char exp[256])
{
    EVP_PKEY *pk = X509_get_pubkey(x);
    if (!pk || EVP_PKEY_base_id(pk) != EVP_PKEY_RSA) {
        EVP_PKEY_free(pk);
        return -1;
    }
    RSA *r = EVP_PKEY_get1_RSA(pk);
    EVP_PKEY_free(pk);
    if (!r)
        return -1;
    const BIGNUM *n = NULL, *e = NULL;
    RSA_get0_key(r, &n, &e, NULL);
    memset(mod, 0, 256);
    memset(exp, 0, 256);
    int nlen = BN_num_bytes(n), elen = BN_num_bytes(e);
    int ok = nlen > 0 && nlen <= 256 && elen > 0 && elen <= 256;
    if (ok) {
        BN_bn2bin(n, mod + 256 - nlen);
        BN_bn2bin(e, exp + 256 - elen);
    }
    RSA_free(r);
    return ok ? 0 : -1;
}

static void check_container(LIB *l, DEVHANDLE dev, HAPPLICATION app, const char *name)
{
    HCONTAINER ctn = NULL;
    ULONG rc = l->OpenContainer(app, (LPSTR)name, &ctn);
    printf("\n=== container %s: OpenContainer rc=0x%08lx\n", name,
           (unsigned long)rc);
    if (rc != SAR_OK)
        return;

    ULONG ctype = 0;
    rc = l->GetContainerType(ctn, &ctype);
    printf("GetContainerType rc=0x%08lx type=%lu\n", (unsigned long)rc,
           (unsigned long)ctype);

    unsigned char signcert[8192], enccert[8192];
    ULONG signlen = sizeof(signcert), enclen = sizeof(enccert);
    rc = l->ExportCertificate(ctn, TRUE, signcert, &signlen);
    printf("ExportCertificate(sign) rc=0x%08lx len=%lu\n", (unsigned long)rc,
           (unsigned long)signlen);
    ULONG rc2 = l->ExportCertificate(ctn, FALSE, enccert, &enclen);
    printf("ExportCertificate(enc)  rc=0x%08lx len=%lu\n", (unsigned long)rc2,
           (unsigned long)enclen);

    X509 *signx = NULL, *encx = NULL;
    if (rc == SAR_OK && signlen > 0) {
        const unsigned char *p = signcert;
        signx = d2i_X509(NULL, &p, (long)signlen);
        printf("sign cert parse: %s\n", signx ? "OK" : "FAILED");
        if (signx) {
            EVP_PKEY *pk = X509_get_pubkey(signx);
            const char *tn = pk ? EVP_PKEY_get0_type_name(pk) : NULL;
            char *subj = X509_NAME_oneline(X509_get_subject_name(signx), NULL, 0);
            char *iss = X509_NAME_oneline(X509_get_issuer_name(signx), NULL, 0);
            printf("sign cert pubkey: %s, cert len=%lu\n",
                   tn ? tn : "unknown", (unsigned long)signlen);
            printf("sign cert subject: %s\n", subj ? subj : "?");
            printf("sign cert issuer : %s\n", iss ? iss : "?");
            FILE *cf = fopen("/tmp/opencode/signcert.der", "wb");
            if (cf) { fwrite(signcert, 1, signlen, cf); fclose(cf); }
            OPENSSL_free(subj); OPENSSL_free(iss);
            EVP_PKEY_free(pk);
        }
    }
    if (rc2 == SAR_OK && enclen > 0) {
        const unsigned char *p = enccert;
        encx = d2i_X509(NULL, &p, (long)enclen);
        printf("enc  cert parse: %s\n", encx ? "OK" : "FAILED");
    }

    /* Determine the actual key type from the signing certificate. */
    int cert_is_ec = 0;
    unsigned char cx[32], cy[32], cmod[256], cexp[256];
    if (signx) {
        if (ec_pub_from_cert(signx, cx, cy) == 0)
            cert_is_ec = 1;
        else if (rsa_pub_from_cert(signx, cmod, cexp) == 0)
            cert_is_ec = 0;
    }

    if (cert_is_ec) {
        ECCPUBLICKEYBLOB pub;
        ULONG publen = sizeof(pub);
        memset(&pub, 0, sizeof(pub));
        rc = l->ExportPublicKey(ctn, TRUE, (BYTE *)&pub, &publen);
        printf("ExportPublicKey(sign) rc=0x%08lx len=%lu bitlen=%lu\n",
               (unsigned long)rc, (unsigned long)publen,
               (unsigned long)pub.BitLen);
        unsigned char px[32], py[32];
        if (rc == SAR_OK) {
            coord32(pub.XCoordinate, px);
            coord32(pub.YCoordinate, py);
            hex("cert pub x", cx, 32); printf("\n");
            hex("skf  pub x", px, 32); printf("\n");
            hex("cert pub y", cy, 32); printf("\n");
            hex("skf  pub y", py, 32); printf("\n");
            printf("cert/skf public key: %s\n",
                   signx && memcmp(cx, px, 32) == 0 && memcmp(cy, py, 32) == 0
                       ? "MATCH" : "MISMATCH");
        }

        unsigned char digest[32];
        for (int i = 0; i < 32; i++) digest[i] = (unsigned char)(i + 1);
        ECCSIGNATUREBLOB sig;
        memset(&sig, 0, sizeof(sig));
        rc = l->ECCSignData(ctn, digest, 32, &sig);
        printf("ECCSignData rc=0x%08lx\n", (unsigned long)rc);
        if (rc == SAR_OK) {
            ULONG v = l->ECCVerify(dev, &pub, digest, 32, &sig);
            printf("ECCVerify(exported pub) rc=0x%08lx\n", (unsigned long)v);
            if (signx) {
                ECCPUBLICKEYBLOB cp;
                memset(&cp, 0, sizeof(cp));
                cp.BitLen = 256;
                memcpy(cp.XCoordinate + 32, cx, 32);
                memcpy(cp.YCoordinate + 32, cy, 32);
                v = l->ECCVerify(dev, &cp, digest, 32, &sig);
                printf("ECCVerify(cert pub)     rc=0x%08lx %s\n",
                       (unsigned long)v, v == SAR_OK ? "MATCH" : "MISMATCH");
            }
        }
    } else if (signx) {
        RSAPUBLICKEYBLOB pub;
        ULONG publen = sizeof(pub);
        memset(&pub, 0, sizeof(pub));
        rc = l->ExportPublicKey(ctn, TRUE, (BYTE *)&pub, &publen);
        printf("ExportPublicKey(sign) rc=0x%08lx len=%lu bitlen=%lu\n",
               (unsigned long)rc, (unsigned long)publen,
               (unsigned long)pub.BitLen);
        if (rc == SAR_OK) {
            printf("cert/skf RSA modulus: %s\n",
                   memcmp(pub.Modulus, cmod, 256) == 0 ? "MATCH" : "MISMATCH");
            printf("cert/skf RSA exponent: %s\n",
                   memcmp(pub.PublicExponent, cexp, 256) == 0 ? "MATCH" : "MISMATCH");
        }
        unsigned char digest[32], sig[256];
        ULONG siglen = sizeof(sig);
        for (int i = 0; i < 32; i++) digest[i] = (unsigned char)(i + 1);
        rc = l->RSASignData(ctn, digest, 32, sig, &siglen);
        printf("RSASignData rc=0x%08lx len=%lu\n", (unsigned long)rc,
               (unsigned long)siglen);
        if (rc == SAR_OK) {
            ULONG v = l->RSAVerify(dev, &pub, digest, 32, sig, siglen);
            printf("RSAVerify(exported pub) rc=0x%08lx\n", (unsigned long)v);
        }
    }

    if (signx) X509_free(signx);
    if (encx) X509_free(encx);
    l->CloseContainer(ctn);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <libskf.so> [container]\n", argv[0]);
        return 2;
    }
    LIB l;
    if (load_lib(&l, argv[1]) != 0)
        return 1;

    ULONG n = 0;
    if (l.EnumDev(TRUE, NULL, &n) != SAR_OK || n == 0) {
        fprintf(stderr, "no device\n");
        return 1;
    }
    char *names = calloc(1, n + 1);
    l.EnumDev(TRUE, (LPSTR)names, &n);
    DEVHANDLE dev = NULL;
    ULONG rc = l.ConnectDev((LPSTR)names, &dev);
    printf("ConnectDev rc=0x%08lx name=%s\n", (unsigned long)rc, names);
    free(names);
    if (rc != SAR_OK)
        return 1;

    HAPPLICATION app = NULL;
    rc = l.OpenApplication(dev, (LPSTR)"KEDA", &app);
    printf("OpenApplication(KEDA) rc=0x%08lx\n", (unsigned long)rc);
    if (rc == SAR_OK) {
        ULONG retry = 0;
        rc = l.VerifyPIN(app, USER_TYPE, (LPSTR)"123456", &retry);
        printf("VerifyPIN rc=0x%08lx retry=%lu\n", (unsigned long)rc,
               (unsigned long)retry);
        if (rc == SAR_OK) {
            if (argc >= 3) {
                check_container(&l, dev, app, argv[2]);
            } else {
                ULONG clen = 0;
                rc = l.EnumContainer(app, NULL, &clen);
                char *ctns = calloc(1, clen + 1);
                rc = l.EnumContainer(app, (LPSTR)ctns, &clen);
                printf("EnumContainer rc=0x%08lx len=%lu\n", (unsigned long)rc,
                       (unsigned long)clen);
                for (char *p = ctns; p < ctns + clen && *p; p += strlen(p) + 1)
                    check_container(&l, dev, app, p);
                free(ctns);
            }
        }
        l.CloseApplication(app);
    }
    l.DisConnectDev(dev);
    dlclose(l.h);
    return 0;
}
