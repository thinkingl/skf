/*
 * Regression test for native SKF import and ECC agreement interfaces.
 *
 * Uses the existing KEDA application and temporary containers; it does not
 * touch DEFAULT or KEDA's existing containers.  The KEDA user PIN is expected
 * to be 123456 on the development key.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include "skf.h"

static int failures;

static void check(const char *what, ULONG rc, int ok)
{
    printf("[%s] %-34s rc=0x%08lx\n", ok ? "PASS" : "FAIL", what,
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

static void fill_rsa_blob(RSAPRIVATEKEYBLOB *b, RSA *r)
{
    memset(b, 0, sizeof(*b));
    b->AlgID = SGD_RSA;
    b->BitLen = 1024;
    const BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
    RSA_get0_key(r, &n, &e, &d);
    RSA_get0_factors(r, &p, &q);
    RSA_get0_crt_params(r, &dmp1, &dmq1, &iqmp);
    BN_bn2binpad(e, b->PublicExponent, MAX_RSA_EXPONENT_LEN);
    BN_bn2binpad(n, b->Modulus + MAX_RSA_MODULUS_LEN - 128, 128);
    BN_bn2binpad(d, b->PrivateExponent, MAX_RSA_MODULUS_LEN);
    BN_bn2binpad(p, b->Prime1, MAX_RSA_MODULUS_LEN / 2);
    BN_bn2binpad(q, b->Prime2, MAX_RSA_MODULUS_LEN / 2);
    BN_bn2binpad(dmp1, b->Prime1Exponent, MAX_RSA_MODULUS_LEN / 2);
    BN_bn2binpad(dmq1, b->Prime2Exponent, MAX_RSA_MODULUS_LEN / 2);
    BN_bn2binpad(iqmp, b->Coefficient, MAX_RSA_MODULUS_LEN / 2);
}

int main(void)
{
    ULONG len = 0;
    SKF_EnumDev(TRUE, NULL, &len);
    char *names = calloc(1, len + 1);
    SKF_EnumDev(TRUE, names, &len);
    DEVHANDLE dev = NULL;
    ULONG rc = SKF_ConnectDev(names, &dev);
    check("SKF_ConnectDev", rc, rc == SAR_OK);
    if (rc != SAR_OK)
        return 1;

    HAPPLICATION app = NULL;
    rc = SKF_OpenApplication(dev, "KEDA", &app);
    check("SKF_OpenApplication(KEDA)", rc, rc == SAR_OK);
    if (rc != SAR_OK)
        return 1;
    ULONG retry = 0;
    rc = SKF_VerifyPIN(app, USER_TYPE, "123456", &retry);
    check("SKF_VerifyPIN(KEDA)", rc, rc == SAR_OK);
    if (rc != SAR_OK)
        return 1;

    SKF_DeleteContainer(app, "SKFIMP1");
    SKF_DeleteContainer(app, "SKFIMP2");
    HCONTAINER c1 = NULL, c2 = NULL;
    rc = SKF_CreateContainer(app, "SKFIMP1", &c1);
    check("SKF_CreateContainer(SKFIMP1)", rc, rc == SAR_OK);
    rc = SKF_CreateContainer(app, "SKFIMP2", &c2);
    check("SKF_CreateContainer(SKFIMP2)", rc, rc == SAR_OK);
    if (!c1 || !c2)
        return 1;

    unsigned char sess[16];
    for (int i = 0; i < 16; i++) sess[i] = (unsigned char)(0x10 + i);
    HANDLE hSess = NULL;
    rc = SKF_ImportSessionKey(c1, SGD_SM4_ECB, sess, 16, &hSess);
    check("SKF_ImportSessionKey", rc, rc == SAR_OK);
    if (hSess) {
        unsigned char in[16], out[32], back[32];
        ULONG olen = sizeof(out), blen = sizeof(back);
        memset(in, 0x5a, sizeof(in));
        rc = SKF_Encrypt(hSess, in, 16, out, &olen);
        check("imported session encrypt", rc, rc == SAR_OK && olen == 16);
        rc = SKF_Decrypt(hSess, out, olen, back, &blen);
        check("imported session decrypt", rc,
              rc == SAR_OK && blen == 16 && memcmp(in, back, 16) == 0);
        SKF_CloseHandle(hSess);
    }

    unsigned char fakecert[64];
    for (int i = 0; i < 64; i++) fakecert[i] = (unsigned char)(0x80 + i);
    rc = SKF_ImportCertificate(c1, TRUE, fakecert, sizeof(fakecert));
    check("SKF_ImportCertificate(fake)", rc, rc == SAR_OBJERR);

    ENVELOPEDKEYBLOB e1, e2;
    EC_KEY *k1 = EC_KEY_new_by_curve_name(NID_sm2);
    EC_KEY *k2 = EC_KEY_new_by_curve_name(NID_sm2);
    EC_KEY_generate_key(k1);
    EC_KEY_generate_key(k2);
    fill_ecc_envelope(&e1, k1);
    fill_ecc_envelope(&e2, k2);
    rc = SKF_ImportECCKeyPair(c1, &e1);
    check("SKF_ImportECCKeyPair(1)", rc, rc == SAR_OK);
    rc = SKF_ImportECCKeyPair(c2, &e2);
    check("SKF_ImportECCKeyPair(2)", rc, rc == SAR_OK);
    if (rc != SAR_OK) {
        SKF_CloseContainer(c1);
        SKF_CloseContainer(c2);
        SKF_DeleteContainer(app, "SKFIMP1");
        SKF_DeleteContainer(app, "SKFIMP2");
        SKF_CloseApplication(app);
        SKF_DisConnectDev(dev);
        free(names);
        return 1;
    }

    ECCPUBLICKEYBLOB sponsorTemp, respTemp;
    HANDLE hAgree = NULL, key1 = NULL, key2 = NULL;
    unsigned char id1[] = "sponsor";
    unsigned char id2[] = "responder";
    rc = SKF_GenerateAgreementDataWithECC(c1, SGD_SM4_ECB, &sponsorTemp,
                                          id1, sizeof(id1) - 1, &hAgree);
    check("SKF_GenerateAgreementDataWithECC", rc, rc == SAR_OK);
    rc = SKF_GenerateAgreementDataAndKeyWithECC(c2, SGD_SM4_ECB,
                                                &e1.PubKey, &sponsorTemp,
                                                &respTemp, id2, sizeof(id2) - 1,
                                                id1, sizeof(id1) - 1, &key2);
    check("SKF_GenerateAgreementDataAndKeyWithECC", rc, rc == SAR_OK);
    if (hAgree)
        rc = SKF_GenerateKeyWithECC(hAgree, &e2.PubKey, &respTemp,
                                    id2, sizeof(id2) - 1, &key1);
    else
        rc = SAR_INVALIDHANDLEERR;
    check("SKF_GenerateKeyWithECC", rc, rc == SAR_OK);
    if (key1 && key2) {
        unsigned char in[16], out[32], back[32];
        ULONG olen = sizeof(out), blen = sizeof(back);
        memset(in, 0xa5, sizeof(in));
        rc = SKF_Encrypt(key1, in, 16, out, &olen);
        ULONG r2 = SKF_Decrypt(key2, out, olen, back, &blen);
        check("agreement key agreement", rc,
              rc == SAR_OK && r2 == SAR_OK && blen == 16 &&
              memcmp(in, back, 16) == 0);
        SKF_CloseHandle(key1);
        SKF_CloseHandle(key2);
    }
    if (hAgree)
        SKF_CloseHandle(hAgree);

    RSAPRIVATEKEYBLOB rblob;
    RSA *r = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(r, 1024, e, NULL);
    fill_rsa_blob(&rblob, r);
    rc = SKF_ImportRSAKeyPair(c1, SGD_SM4_ECB, (BYTE *)&rblob, sizeof(rblob),
                              (BYTE *)"", 0);
    check("SKF_ImportRSAKeyPair", rc, rc == SAR_OK);

    /* Make a self-signed certificate for the imported RSA key and import it. */
    {
        EVP_PKEY *pkey = EVP_PKEY_new();
        EVP_PKEY_set1_RSA(pkey, r);
        X509 *x509 = X509_new();
        X509_set_version(x509, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
        X509_set_pubkey(x509, pkey);
        X509_sign(x509, pkey, EVP_sha256());
        int derlen = i2d_X509(x509, NULL);
        unsigned char *der = malloc((size_t)derlen);
        unsigned char *dp = der;
        i2d_X509(x509, &dp);
        rc = SKF_ImportCertificate(c1, TRUE, der, (ULONG)derlen);
        check("SKF_ImportCertificate(valid)", rc, rc == SAR_OK);
        unsigned char certout[2048];
        ULONG clen = sizeof(certout);
        rc = SKF_ExportCertificate(c1, TRUE, certout, &clen);
        check("SKF_ExportCertificate(valid)", rc,
              rc == SAR_OK && clen == (ULONG)derlen &&
              memcmp(der, certout, clen) == 0);
        free(der);
        X509_free(x509);
        EVP_PKEY_free(pkey);
    }

    unsigned char digest[32], sig[256];
    for (int i = 0; i < 32; i++) digest[i] = (unsigned char)i;
    ULONG siglen = sizeof(sig);
    rc = SKF_RSASignData(c1, digest, 32, sig, &siglen);
    check("SKF_RSASignData(imported)", rc, rc == SAR_OK);
    if (rc == SAR_OK) {
        RSAPUBLICKEYBLOB pub;
        memset(&pub, 0, sizeof(pub));
        pub.AlgID = SGD_RSA;
        pub.BitLen = 1024;
        memcpy(pub.Modulus, rblob.Modulus, sizeof(pub.Modulus));
        memcpy(pub.PublicExponent, rblob.PublicExponent,
               sizeof(pub.PublicExponent));
        rc = SKF_RSAVerify(dev, &pub, digest, 32, sig, siglen);
        check("SKF_RSAVerify(imported)", rc, rc == SAR_OK);
    }
    RSA_free(r);
    BN_free(e);

    SKF_CloseContainer(c1);
    SKF_CloseContainer(c2);
    rc = SKF_DeleteContainer(app, "SKFIMP1");
    check("SKF_DeleteContainer(SKFIMP1)", rc, rc == SAR_OK);
    rc = SKF_DeleteContainer(app, "SKFIMP2");
    check("SKF_DeleteContainer(SKFIMP2)", rc, rc == SAR_OK);
    SKF_CloseApplication(app);
    SKF_DisConnectDev(dev);
    EC_KEY_free(k1);
    EC_KEY_free(k2);
    free(names);
    printf("\nFailures: %d\n", failures);
    return failures ? 1 : 0;
}
