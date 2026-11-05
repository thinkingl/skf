/*
 * Regression test for per-container certificate EFs and ECC key/cert
 * consistency.
 *
 * Scenario 1: device-generated ECC key, import a CA-issued certificate for
 *             the device public key, export it, sign and verify with the
 *             certificate public key.
 * Scenario 2: imported software ECC key, self-signed certificate, export it,
 *             sign and verify with the certificate public key.
 *
 * The test also checks that importing certificates into temporary containers
 * does not change the certificate of the existing K01231 container.
 *
 * Destructive only to the temporary containers SKFCRT1/SKFCRT2.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include "skf_ossl_compat.h"
#include "skf.h"

static int failures;

static void check(const char *what, ULONG rc, int ok)
{
    printf("[%s] %-48s rc=0x%08lx\n", ok ? "PASS" : "FAIL", what,
           (unsigned long)rc);
    if (!ok)
        failures++;
}

static void fill_ecc_envelope(ENVELOPEDKEYBLOB *b, EC_KEY *k)
{
    memset(b, 0, sizeof(*b));
    b->Version = 1;
    b->ulSymmAlgID = SGD_SM4_ECB;
    b->ulBits = 256;
    BN_bn2binpad(EC_KEY_get0_private_key(k), b->cbEncryptedPriKey, 32);
    const EC_GROUP *g = EC_KEY_get0_group(k);
    const EC_POINT *p = EC_KEY_get0_public_key(k);
    BIGNUM *x = BN_new(), *y = BN_new();
    EC_POINT_get_affine_coordinates(g, p, x, y, NULL);
    b->PubKey.BitLen = 256;
    BN_bn2binpad(x, b->PubKey.XCoordinate + 32, 32);
    BN_bn2binpad(y, b->PubKey.YCoordinate + 32, 32);
    BN_free(x); BN_free(y);
}

static EVP_PKEY *ecc_pkey_from_blob(const ECCPUBLICKEYBLOB *pub)
{
    EC_KEY *k = EC_KEY_new_by_curve_name(NID_sm2);
    if (!k)
        return NULL;
    const EC_GROUP *g = EC_KEY_get0_group(k);
    EC_POINT *pt = EC_POINT_new(g);
    BIGNUM *x = BN_bin2bn(pub->XCoordinate + 32, 32, NULL);
    BIGNUM *y = BN_bin2bn(pub->YCoordinate + 32, 32, NULL);
    int ok = pt && x && y &&
             EC_POINT_set_affine_coordinates(g, pt, x, y, NULL) == 1 &&
             EC_KEY_set_public_key(k, pt) == 1;
    EVP_PKEY *pkey = ok ? EVP_PKEY_new() : NULL;
    if (pkey) {
        if (EVP_PKEY_set1_EC_KEY(pkey, k) != 1) {
            EVP_PKEY_free(pkey);
            pkey = NULL;
        }
    }
    BN_free(x); BN_free(y); EC_POINT_free(pt);
    EC_KEY_free(k);
    return pkey;
}

static X509 *make_cert(EVP_PKEY *subject, EVP_PKEY *issuer, int serial)
{
    X509 *x = X509_new();
    if (!x)
        return NULL;
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
    X509_gmtime_adj(X509_get_notBefore(x), 0);
    X509_gmtime_adj(X509_get_notAfter(x), 31536000L);
    if (X509_set_pubkey(x, subject) != 1 ||
        X509_sign(x, issuer, EVP_sha256()) <= 0) {
        X509_free(x);
        return NULL;
    }
    return x;
}

static int x509_to_der(X509 *x, unsigned char **der)
{
    int len = i2d_X509(x, NULL);
    if (len <= 0)
        return -1;
    *der = malloc((size_t)len);
    if (!*der)
        return -1;
    unsigned char *p = *der;
    if (i2d_X509(x, &p) != len) {
        free(*der);
        *der = NULL;
        return -1;
    }
    return len;
}

static EVP_PKEY *make_rsa_issuer(void)
{
    RSA *r = RSA_new();
    BIGNUM *e = BN_new();
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!r || !e || !pkey) {
        RSA_free(r); BN_free(e); EVP_PKEY_free(pkey);
        return NULL;
    }
    BN_set_word(e, RSA_F4);
    if (RSA_generate_key_ex(r, 2048, e, NULL) != 1 ||
        EVP_PKEY_set1_RSA(pkey, r) != 1) {
        RSA_free(r); BN_free(e); EVP_PKEY_free(pkey);
        return NULL;
    }
    RSA_free(r);
    BN_free(e);
    return pkey;
}

static ECCPUBLICKEYBLOB pub_from_cert(X509 *x)
{
    ECCPUBLICKEYBLOB out;
    memset(&out, 0, sizeof(out));
    out.BitLen = 256;
    EVP_PKEY *pk = X509_get_pubkey(x);
    BIGNUM *bx = NULL, *by = NULL;
    int gx = pk ? EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_PUB_X, &bx) : -1;
    int gy = pk ? EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_PUB_Y, &by) : -1;
    if (gx == 1 && gy == 1) {
        BN_bn2binpad(bx, out.XCoordinate + 32, 32);
        BN_bn2binpad(by, out.YCoordinate + 32, 32);
    } else {
        EC_KEY *k = pk ? EVP_PKEY_get1_EC_KEY(pk) : NULL;
        if (k) {
            const EC_GROUP *g = EC_KEY_get0_group(k);
            const EC_POINT *pt = EC_KEY_get0_public_key(k);
            BIGNUM *ex = BN_new(), *ey = BN_new();
            if (ex && ey && g && pt &&
                EC_POINT_get_affine_coordinates(g, pt, ex, ey, NULL) == 1) {
                BN_bn2binpad(ex, out.XCoordinate + 32, 32);
                BN_bn2binpad(ey, out.YCoordinate + 32, 32);
            }
            BN_free(ex); BN_free(ey);
            EC_KEY_free(k);
        }
    }
    BN_free(bx); BN_free(by);
    EVP_PKEY_free(pk);
    return out;
}

static void test_device_ecc(DEVHANDLE dev, HAPPLICATION app, EVP_PKEY *issuer,
                            const char *name)
{
    printf("\n=== device-generated ECC key: %s\n", name);
    HCONTAINER c = NULL;
    SKF_DeleteContainer(app, (LPSTR)name);
    ULONG rc = SKF_CreateContainer(app, (LPSTR)name, &c);
    check("SKF_CreateContainer", rc, rc == SAR_OK);
    if (rc != SAR_OK)
        return;

    ECCPUBLICKEYBLOB pub;
    memset(&pub, 0, sizeof(pub));
    rc = SKF_GenECCKeyPair(c, SGD_SM2, &pub);
    check("SKF_GenECCKeyPair", rc, rc == SAR_OK);
    if (rc != SAR_OK)
        goto out;

    EVP_PKEY *subj = ecc_pkey_from_blob(&pub);
    X509 *x = subj ? make_cert(subj, issuer, 10) : NULL;
    unsigned char *der = NULL;
    int derlen = x ? x509_to_der(x, &der) : -1;
    check("make certificate", derlen > 0 ? SAR_OK : SAR_FAIL, derlen > 0);
    if (derlen <= 0)
        goto out_cert;

    rc = SKF_ImportCertificate(c, TRUE, der, (ULONG)derlen);
    check("SKF_ImportCertificate(device ECC pub)", rc, rc == SAR_OK);

    unsigned char out[8192];
    ULONG outlen = sizeof(out);
    rc = SKF_ExportCertificate(c, TRUE, out, &outlen);
    check("SKF_ExportCertificate(sign)", rc,
          rc == SAR_OK && outlen == (ULONG)derlen &&
          memcmp(out, der, outlen) == 0);

    ECCPUBLICKEYBLOB exppub;
    ULONG publen = sizeof(exppub);
    rc = SKF_ExportPublicKey(c, TRUE, (BYTE *)&exppub, &publen);
    check("SKF_ExportPublicKey(sign)", rc,
          rc == SAR_OK && publen == sizeof(exppub) &&
          memcmp(exppub.XCoordinate, pub.XCoordinate, 64) == 0 &&
          memcmp(exppub.YCoordinate, pub.YCoordinate, 64) == 0);

    unsigned char digest[32];
    for (int i = 0; i < 32; i++) digest[i] = (unsigned char)(0x20 + i);
    ECCSIGNATUREBLOB sig;
    memset(&sig, 0, sizeof(sig));
    rc = SKF_ECCSignData(c, digest, sizeof(digest), &sig);
    check("SKF_ECCSignData", rc, rc == SAR_OK);

    ECCPUBLICKEYBLOB certpub = pub_from_cert(x);
    ULONG v = SKF_ExtECCVerify(dev, &certpub, digest, sizeof(digest), &sig);
    check("SKF_ExtECCVerify(cert pub)", v, v == SAR_OK);
    v = SKF_ECCVerify(dev, &pub, digest, sizeof(digest), &sig);
    check("SKF_ECCVerify(device pub)", v, v == SAR_OK);

    free(der);
    X509_free(x);
    EVP_PKEY_free(subj);
out:
    SKF_CloseContainer(c);
    SKF_DeleteContainer(app, (LPSTR)name);
    return;
out_cert:
    SKF_CloseContainer(c);
    SKF_DeleteContainer(app, (LPSTR)name);
}

static void test_software_ecc(DEVHANDLE dev, HAPPLICATION app,
                              EVP_PKEY *issuer, const char *name)
{
    printf("\n=== imported software ECC key: %s\n", name);
    HCONTAINER c = NULL;
    SKF_DeleteContainer(app, (LPSTR)name);
    ULONG rc = SKF_CreateContainer(app, (LPSTR)name, &c);
    check("SKF_CreateContainer", rc, rc == SAR_OK);
    if (rc != SAR_OK)
        return;

    EC_KEY *k = EC_KEY_new_by_curve_name(NID_sm2);
    if (!k || EC_KEY_generate_key(k) != 1) {
        check("EC_KEY_generate_key", SAR_FAIL, 0);
        EC_KEY_free(k);
        SKF_CloseContainer(c);
        SKF_DeleteContainer(app, (LPSTR)name);
        return;
    }
    ENVELOPEDKEYBLOB env;
    fill_ecc_envelope(&env, k);
    rc = SKF_ImportECCKeyPair(c, &env);
    check("SKF_ImportECCKeyPair(native)", rc, rc == SAR_OK);

    EVP_PKEY *subj = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(subj, k);
    X509 *x = subj ? make_cert(subj, issuer, 11) : NULL;
    unsigned char *der = NULL;
    int derlen = x ? x509_to_der(x, &der) : -1;
    check("make certificate", derlen > 0 ? SAR_OK : SAR_FAIL, derlen > 0);
    if (derlen > 0) {
        rc = SKF_ImportCertificate(c, TRUE, der, (ULONG)derlen);
        check("SKF_ImportCertificate(software ECC pub)", rc, rc == SAR_OK);

        unsigned char out[8192];
        ULONG outlen = sizeof(out);
        rc = SKF_ExportCertificate(c, TRUE, out, &outlen);
        check("SKF_ExportCertificate(sign)", rc,
              rc == SAR_OK && outlen == (ULONG)derlen &&
              memcmp(out, der, outlen) == 0);

        ECCPUBLICKEYBLOB exppub;
        ULONG publen = sizeof(exppub);
        rc = SKF_ExportPublicKey(c, TRUE, (BYTE *)&exppub, &publen);
        check("SKF_ExportPublicKey(sign)", rc,
              rc == SAR_OK && publen == sizeof(exppub) &&
              memcmp(exppub.XCoordinate, env.PubKey.XCoordinate, 64) == 0 &&
              memcmp(exppub.YCoordinate, env.PubKey.YCoordinate, 64) == 0);

        unsigned char digest[32];
        for (int i = 0; i < 32; i++) digest[i] = (unsigned char)(0x40 + i);
        ECCSIGNATUREBLOB sig;
        memset(&sig, 0, sizeof(sig));
        rc = SKF_ECCSignData(c, digest, sizeof(digest), &sig);
        check("SKF_ECCSignData(software key)", rc, rc == SAR_OK);

        ECCPUBLICKEYBLOB certpub = pub_from_cert(x);
        ULONG v = SKF_ExtECCVerify(dev, &certpub, digest, sizeof(digest), &sig);
        check("SKF_ExtECCVerify(cert pub)", v, v == SAR_OK);
        v = SKF_ExtECCVerify(dev, &env.PubKey, digest, sizeof(digest), &sig);
        check("SKF_ExtECCVerify(imported pub)", v, v == SAR_OK);

        free(der);
    }
    X509_free(x);
    EVP_PKEY_free(subj);
    EC_KEY_free(k);
    SKF_CloseContainer(c);
    SKF_DeleteContainer(app, (LPSTR)name);
}

int main(void)
{
    ULONG len = 0;
    SKF_EnumDev(TRUE, NULL, &len);
    char *names = calloc(1, len + 1);
    SKF_EnumDev(TRUE, (LPSTR)names, &len);
    DEVHANDLE dev = NULL;
    ULONG rc = SKF_ConnectDev((LPSTR)names, &dev);
    check("SKF_ConnectDev", rc, rc == SAR_OK);
    free(names);
    if (rc != SAR_OK)
        return 1;

    HAPPLICATION app = NULL;
    rc = SKF_OpenApplication(dev, (LPSTR)"KEDA", &app);
    check("SKF_OpenApplication(KEDA)", rc, rc == SAR_OK);
    if (rc != SAR_OK)
        return 1;
    ULONG retry = 0;
    rc = SKF_VerifyPIN(app, USER_TYPE, (LPSTR)"123456", &retry);
    check("SKF_VerifyPIN(KEDA)", rc, rc == SAR_OK);
    if (rc != SAR_OK)
        return 1;

    /* Snapshot the K01231 certificate so we can prove EF isolation. */
    unsigned char snap[8192];
    ULONG snaplen = 0;
    HCONTAINER kc = NULL;
    rc = SKF_OpenContainer(app, (LPSTR)"K01231-85422873-3457921", &kc);
    if (rc == SAR_OK) {
        snaplen = sizeof(snap);
        rc = SKF_ExportCertificate(kc, TRUE, snap, &snaplen);
        printf("K01231 cert snapshot: rc=0x%08lx len=%lu\n",
               (unsigned long)rc, (unsigned long)snaplen);
        SKF_CloseContainer(kc);
    }

    EVP_PKEY *issuer = make_rsa_issuer();
    if (!issuer) {
        fprintf(stderr, "cannot make issuer key\n");
        return 1;
    }

    test_device_ecc(dev, app, issuer, "SKFCRT1");
    test_software_ecc(dev, app, issuer, "SKFCRT2");

    /* The K01231 certificate must be unchanged. */
    kc = NULL;
    rc = SKF_OpenContainer(app, (LPSTR)"K01231-85422873-3457921", &kc);
    if (rc == SAR_OK) {
        unsigned char after[8192];
        ULONG afterlen = sizeof(after);
        rc = SKF_ExportCertificate(kc, TRUE, after, &afterlen);
        check("K01231 certificate unchanged", rc,
              rc == SAR_OK && afterlen == snaplen &&
              memcmp(after, snap, snaplen) == 0);
        SKF_CloseContainer(kc);
    }

    EVP_PKEY_free(issuer);
    SKF_CloseApplication(app);
    SKF_DisConnectDev(dev);
    printf("\nFailures: %d\n", failures);
    return failures ? 1 : 0;
}
