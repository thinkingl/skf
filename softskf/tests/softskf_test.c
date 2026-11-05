#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "skf.h"

static int failures;

static void check(const char *what, ULONG rc, int ok)
{
    printf("[%s] %-42s rc=0x%08lx\n", ok ? "PASS" : "FAIL", what,
           (unsigned long)rc);
    if (!ok)
        failures++;
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

static void fill_ecc_private_blob(EC_KEY *k, ECCPRIVATEKEYBLOB *pri)
{
    memset(pri, 0, sizeof(*pri));
    pri->BitLen = 256;
    BN_bn2binpad(EC_KEY_get0_private_key(k), pri->PrivateKey + 32, 32);
}

static void fill_rsa_public_blob(RSA *r, RSAPUBLICKEYBLOB *b)
{
    memset(b, 0, sizeof(*b));
    b->AlgID = SGD_RSA;
    const BIGNUM *n, *e;
    RSA_get0_key(r, &n, &e, NULL);
    b->BitLen = (ULONG)BN_num_bits(n);
    BN_bn2binpad(n, b->Modulus + MAX_RSA_MODULUS_LEN - BN_num_bytes(n),
                 BN_num_bytes(n));
    BN_bn2binpad(e, b->PublicExponent, MAX_RSA_EXPONENT_LEN);
}

static void fill_rsa_private_blob(RSA *r, RSAPRIVATEKEYBLOB *b)
{
    memset(b, 0, sizeof(*b));
    b->AlgID = SGD_RSA;
    const BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
    RSA_get0_key(r, &n, &e, &d);
    RSA_get0_factors(r, &p, &q);
    RSA_get0_crt_params(r, &dmp1, &dmq1, &iqmp);
    b->BitLen = (ULONG)BN_num_bits(n);
    BN_bn2binpad(e, b->PublicExponent, MAX_RSA_EXPONENT_LEN);
    BN_bn2binpad(n, b->Modulus + MAX_RSA_MODULUS_LEN - BN_num_bytes(n),
                 BN_num_bytes(n));
    BN_bn2binpad(d, b->PrivateExponent, MAX_RSA_MODULUS_LEN);
    BN_bn2binpad(p, b->Prime1, MAX_RSA_MODULUS_LEN / 2);
    BN_bn2binpad(q, b->Prime2, MAX_RSA_MODULUS_LEN / 2);
    BN_bn2binpad(dmp1, b->Prime1Exponent, MAX_RSA_MODULUS_LEN / 2);
    BN_bn2binpad(dmq1, b->Prime2Exponent, MAX_RSA_MODULUS_LEN / 2);
    BN_bn2binpad(iqmp, b->Coefficient, MAX_RSA_MODULUS_LEN / 2);
}

static void wrap_auth(DEVHANDLE dev, const unsigned char key[16], ULONG alg,
                      ULONG *out_rc)
{
    BYTE challenge[16] = {0};
    ULONG rc = SKF_GenRandom(dev, challenge, 8);
    HANDLE h = NULL;
    if (rc == SAR_OK)
        rc = SKF_SetSymmKey(dev, (BYTE *)key, alg, &h);
    BLOCKCIPHERPARAM p;
    memset(&p, 0, sizeof(p));
    if (rc == SAR_OK)
        rc = SKF_EncryptInit(h, p);
    BYTE out[32];
    ULONG outlen = sizeof(out);
    if (rc == SAR_OK)
        rc = SKF_Encrypt(h, challenge, sizeof(challenge), out, &outlen);
    if (h)
        SKF_CloseHandle(h);
    if (rc == SAR_OK)
        rc = SKF_DevAuth(dev, out, outlen);
    *out_rc = rc;
}

static int do_sm4_roundtrip(DEVHANDLE dev, ULONG alg)
{
    unsigned char key[16], iv[16];
    for (int i = 0; i < 16; i++) {
        key[i] = (unsigned char)(0x10 + i);
        iv[i] = (unsigned char)(0x30 + i);
    }
    HANDLE h = NULL;
    ULONG rc = SKF_SetSymmKey(dev, key, alg, &h);
    if (rc != SAR_OK)
        return 0;
    BLOCKCIPHERPARAM p;
    memset(&p, 0, sizeof(p));
    p.PaddingType = 1;
    if (alg != SGD_SM4_ECB) {
        memcpy(p.IV, iv, 16);
        p.IVLen = 16;
    }
    unsigned char in[37], enc[80], dec[80];
    for (int i = 0; i < (int)sizeof(in); i++)
        in[i] = (unsigned char)i;
    ULONG enclen = sizeof(enc), declen = sizeof(dec);
    rc = SKF_EncryptInit(h, p);
    if (rc == SAR_OK)
        rc = SKF_Encrypt(h, in, sizeof(in), enc, &enclen);
    if (rc == SAR_OK)
        rc = SKF_DecryptInit(h, p);
    if (rc == SAR_OK)
        rc = SKF_Decrypt(h, enc, enclen, dec, &declen);
    int ok = rc == SAR_OK && declen == sizeof(in) &&
             memcmp(in, dec, sizeof(in)) == 0;
    SKF_CloseHandle(h);
    return ok;
}

int main(void)
{
    const unsigned char authkey[16] = {
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x61,0x62,0x63,0x64,0x65,0x66
    };

    ULONG len = 0;
    ULONG rc = SKF_EnumDev(TRUE, NULL, &len);
    check("SKF_EnumDev(NULL)", rc, rc == SAR_OK && len > 0);
    char *names = calloc(1, len + 1);
    rc = SKF_EnumDev(TRUE, (LPSTR)names, &len);
    check("SKF_EnumDev(list)", rc, rc == SAR_OK && names[0]);

    DEVHANDLE dev = NULL;
    rc = SKF_ConnectDev((LPSTR)names, &dev);
    check("SKF_ConnectDev", rc, rc == SAR_OK && dev);
    if (!dev)
        return 1;

    DEVINFO info;
    memset(&info, 0, sizeof(info));
    rc = SKF_GetDevInfo(dev, &info);
    check("SKF_GetDevInfo", rc, rc == SAR_OK && info.SerialNumber[0]);
    check("SM1 not in AlgSymCap", 0, (info.AlgSymCap & SGD_SM1) == 0);

    ULONG ar = SAR_FAIL;
    wrap_auth(dev, authkey, info.DevAuthAlgId, &ar);
    check("SKF_DevAuth", ar, ar == SAR_OK);

    HAPPLICATION app = NULL;
    rc = SKF_OpenApplication(dev, (LPSTR)"KEDA", &app);
    check("SKF_OpenApplication", rc, rc == SAR_OK && app);
    if (!app)
        return 1;
    ULONG retry = 0;
    rc = SKF_VerifyPIN(app, USER_TYPE, (LPSTR)"123456", &retry);
    check("SKF_VerifyPIN", rc, rc == SAR_OK);

    SKF_DeleteContainer(app, (LPSTR)"SOFTECC");
    SKF_DeleteContainer(app, (LPSTR)"SOFTECC2");
    SKF_DeleteContainer(app, (LPSTR)"SOFTRSA");
    SKF_DeleteContainer(app, (LPSTR)"SOFTIMPECC");
    SKF_DeleteContainer(app, (LPSTR)"SOFTIMPRSA");

    /* ECC */
    HCONTAINER ecc1 = NULL, ecc2 = NULL;
    rc = SKF_CreateContainer(app, (LPSTR)"SOFTECC", &ecc1);
    check("SKF_CreateContainer(ECC)", rc, rc == SAR_OK && ecc1);
    ECCPUBLICKEYBLOB eccpub1;
    rc = SKF_GenECCKeyPair(ecc1, SGD_SM2, &eccpub1);
    check("SKF_GenECCKeyPair", rc, rc == SAR_OK && eccpub1.BitLen == 256);

    BYTE pubbuf[256];
    ULONG publen = sizeof(pubbuf);
    rc = SKF_ExportPublicKey(ecc1, TRUE, pubbuf, &publen);
    check("SKF_ExportPublicKey(ECC)", rc,
          rc == SAR_OK && publen == sizeof(ECCPUBLICKEYBLOB));

    BYTE digest[32];
    for (int i = 0; i < 32; i++) digest[i] = (BYTE)i;
    ECCSIGNATUREBLOB sig;
    rc = SKF_ECCSignData(ecc1, digest, sizeof(digest), &sig);
    check("SKF_ECCSignData", rc, rc == SAR_OK);
    rc = SKF_ECCVerify(dev, (ECCPUBLICKEYBLOB *)pubbuf, digest,
                       sizeof(digest), &sig);
    check("SKF_ECCVerify", rc, rc == SAR_OK);
    rc = SKF_ExtECCVerify(dev, (ECCPUBLICKEYBLOB *)pubbuf, digest,
                          sizeof(digest), &sig);
    check("SKF_ExtECCVerify", rc, rc == SAR_OK);

    BYTE plain[16], cplain[16];
    for (int i = 0; i < 16; i++) plain[i] = (BYTE)(0x40 + i);
    ECCCIPHERBLOB *cipher = calloc(1, sizeof(ECCCIPHERBLOB) + 256);
    rc = SKF_ExtECCEncrypt(dev, (ECCPUBLICKEYBLOB *)pubbuf, plain,
                           sizeof(plain), cipher);
    check("SKF_ExtECCEncrypt", rc, rc == SAR_OK);
    ULONG cplainlen = sizeof(cplain);
    rc = SKF_ECCDecrypt(ecc1, cipher, cplain, &cplainlen);
    check("SKF_ECCDecrypt", rc,
          rc == SAR_OK && cplainlen == sizeof(plain) &&
          memcmp(plain, cplain, sizeof(plain)) == 0);
    free(cipher);

    HANDLE sess = NULL;
    ECCCIPHERBLOB *sesscipher = calloc(1, sizeof(ECCCIPHERBLOB) + 16);
    rc = SKF_ECCExportSessionKey(ecc1, SGD_SM4_ECB,
                                 (ECCPUBLICKEYBLOB *)pubbuf, sesscipher,
                                 &sess);
    check("SKF_ECCExportSessionKey", rc, rc == SAR_OK && sess);
    if (sess)
        SKF_CloseHandle(sess);
    free(sesscipher);

    rc = SKF_CreateContainer(app, (LPSTR)"SOFTECC2", &ecc2);
    check("SKF_CreateContainer(ECC2)", rc, rc == SAR_OK && ecc2);
    ECCPUBLICKEYBLOB eccpub2;
    rc = SKF_GenECCKeyPair(ecc2, SGD_SM2, &eccpub2);
    check("SKF_GenECCKeyPair(2)", rc, rc == SAR_OK);

    ECCPUBLICKEYBLOB temp1, temp2;
    HANDLE agree = NULL;
    BYTE id1[] = "SPONSOR", id2[] = "RESPONDER";
    rc = SKF_GenerateAgreementDataWithECC(ecc1, SGD_SM4_ECB, &temp1,
                                          id1, sizeof(id1) - 1, &agree);
    check("SKF_GenerateAgreementDataWithECC", rc, rc == SAR_OK && agree);
    HANDLE agreekey = NULL;
    if (rc == SAR_OK) {
        rc = SKF_GenerateAgreementDataAndKeyWithECC(
            ecc2, SGD_SM4_ECB, &eccpub1, &temp1, &temp2,
            id2, sizeof(id2) - 1, id1, sizeof(id1) - 1, &agreekey);
        check("SKF_GenerateAgreementDataAndKeyWithECC", rc,
              rc == SAR_OK && agreekey);
    }
    HANDLE agreekey2 = NULL;
    if (rc == SAR_OK) {
        rc = SKF_GenerateKeyWithECC(agree, &eccpub2, &temp2,
                                    id2, sizeof(id2) - 1, &agreekey2);
        check("SKF_GenerateKeyWithECC", rc, rc == SAR_OK && agreekey2);
    }
    if (agreekey) SKF_CloseHandle(agreekey);
    if (agreekey2) SKF_CloseHandle(agreekey2);
    if (agree) SKF_CloseHandle(agree);

    /* ECC native-envelope import */
    EC_KEY *ik = EC_KEY_new_by_curve_name(NID_sm2);
    EC_KEY_generate_key(ik);
    ENVELOPEDKEYBLOB env;
    memset(&env, 0, sizeof(env));
    env.Version = 1;
    env.ulSymmAlgID = SGD_SM4_ECB;
    env.ulBits = 256;
    BN_bn2binpad(EC_KEY_get0_private_key(ik), env.cbEncryptedPriKey, 32);
    fill_ecc_pub(ik, &env.PubKey);
    HCONTAINER impecc = NULL;
    rc = SKF_CreateContainer(app, (LPSTR)"SOFTIMPECC", &impecc);
    check("SKF_CreateContainer(IMPECC)", rc, rc == SAR_OK && impecc);
    rc = SKF_ImportECCKeyPair(impecc, &env);
    check("SKF_ImportECCKeyPair", rc, rc == SAR_OK);
    BYTE impubbuf[256];
    ULONG impublen = sizeof(impubbuf);
    rc = SKF_ExportPublicKey(impecc, TRUE, impubbuf, &impublen);
    check("SKF_ExportPublicKey(IMPECC)", rc,
          rc == SAR_OK && impublen == sizeof(ECCPUBLICKEYBLOB));

    /* External ECC private-key operations */
    ECCPRIVATEKEYBLOB ipri;
    fill_ecc_private_blob(ik, &ipri);
    ECCSIGNATUREBLOB esig;
    rc = SKF_ExtECCSign(dev, &ipri, digest, sizeof(digest), &esig);
    check("SKF_ExtECCSign", rc, rc == SAR_OK);
    rc = SKF_ExtECCVerify(dev, &env.PubKey, digest, sizeof(digest), &esig);
    check("SKF_ExtECCVerify(private)", rc, rc == SAR_OK);

    ECCCIPHERBLOB *ecipher = calloc(1, sizeof(ECCCIPHERBLOB) + 256);
    rc = SKF_ExtECCEncrypt(dev, &env.PubKey, plain, sizeof(plain), ecipher);
    check("SKF_ExtECCEncrypt(private)", rc, rc == SAR_OK);
    BYTE extplain[32];
    ULONG extplainlen = sizeof(extplain);
    rc = SKF_ExtECCDecrypt(dev, &ipri, ecipher, extplain, &extplainlen);
    check("SKF_ExtECCDecrypt", rc,
          rc == SAR_OK && extplainlen == sizeof(plain) &&
          memcmp(plain, extplain, sizeof(plain)) == 0);
    free(ecipher);

    /* ECC certificate */
    EVP_PKEY *epkey = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(epkey, ik);
    X509 *ex = X509_new();
    X509_set_version(ex, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(ex), 2);
    X509_gmtime_adj(X509_get_notBefore(ex), 0);
    X509_gmtime_adj(X509_get_notAfter(ex), 31536000L);
    X509_set_pubkey(ex, epkey);
    int esignok = X509_sign(ex, epkey, EVP_sm3());
    int ederlen = i2d_X509(ex, NULL);
    printf("ECC cert sign=%d derlen=%d\n", esignok, ederlen);
    unsigned char *eder = malloc((size_t)ederlen);
    unsigned char *edp = eder;
    i2d_X509(ex, &edp);
    rc = SKF_ImportCertificate(impecc, TRUE, eder, (ULONG)ederlen);
    check("SKF_ImportCertificate(ECC)", rc, rc == SAR_OK);
    unsigned char ecertout[2048];
    ULONG ecertoutlen = sizeof(ecertout);
    rc = SKF_ExportCertificate(impecc, TRUE, ecertout, &ecertoutlen);
    check("SKF_ExportCertificate(ECC)", rc,
          rc == SAR_OK && ecertoutlen == (ULONG)ederlen &&
          memcmp(eder, ecertout, ecertoutlen) == 0);
    free(eder);
    X509_free(ex);
    EVP_PKEY_free(epkey);

    /* RSA */
    HCONTAINER rsa = NULL;
    rc = SKF_CreateContainer(app, (LPSTR)"SOFTRSA", &rsa);
    check("SKF_CreateContainer(RSA)", rc, rc == SAR_OK && rsa);
    RSAPUBLICKEYBLOB rsapub;
    rc = SKF_GenRSAKeyPair(rsa, 1024, &rsapub);
    check("SKF_GenRSAKeyPair", rc, rc == SAR_OK && rsapub.BitLen == 1024);
    BYTE rsapubbuf[512];
    ULONG rsapublen = sizeof(rsapubbuf);
    rc = SKF_ExportPublicKey(rsa, TRUE, rsapubbuf, &rsapublen);
    check("SKF_ExportPublicKey(RSA)", rc,
          rc == SAR_OK && rsapublen == sizeof(RSAPUBLICKEYBLOB));

    BYTE rsasig[512];
    ULONG rsasiglen = sizeof(rsasig);
    rc = SKF_RSASignData(rsa, digest, sizeof(digest), rsasig, &rsasiglen);
    check("SKF_RSASignData", rc, rc == SAR_OK && rsasiglen == 128);
    rc = SKF_RSAVerify(dev, (RSAPUBLICKEYBLOB *)rsapubbuf, digest,
                       sizeof(digest), rsasig, rsasiglen);
    check("SKF_RSAVerify", rc, rc == SAR_OK);

    BYTE rsa_sess[256];
    ULONG rsa_sess_len = sizeof(rsa_sess);
    HANDLE rsa_sess_key = NULL;
    rc = SKF_RSAExportSessionKey(rsa, SGD_SM4_ECB,
                                 (RSAPUBLICKEYBLOB *)rsapubbuf,
                                 rsa_sess, &rsa_sess_len, &rsa_sess_key);
    check("SKF_RSAExportSessionKey", rc,
          rc == SAR_OK && rsa_sess_len == 128 && rsa_sess_key);
    if (rsa_sess_key) SKF_CloseHandle(rsa_sess_key);

    /* External RSA key operations */
    RSAPRIVATEKEYBLOB extpri;
    rc = SKF_GenExtRSAKey(dev, 1024, &extpri);
    check("SKF_GenExtRSAKey", rc, rc == SAR_OK && extpri.BitLen == 1024);
    RSA *extrsa = RSA_new();
    BIGNUM *en = BN_bin2bn(extpri.Modulus, MAX_RSA_MODULUS_LEN, NULL);
    BIGNUM *ee = BN_bin2bn(extpri.PublicExponent, MAX_RSA_EXPONENT_LEN, NULL);
    BIGNUM *ed = BN_bin2bn(extpri.PrivateExponent, MAX_RSA_MODULUS_LEN, NULL);
    RSA_set0_key(extrsa, en, ee, ed);
    RSAPUBLICKEYBLOB extpub;
    fill_rsa_public_blob(extrsa, &extpub);
    RSA_free(extrsa);
    BYTE raw_in[128], raw_out[256], raw_back[256];
    memset(raw_in, 0, sizeof(raw_in));
    raw_in[127] = 0x42;
    ULONG raw_outlen = sizeof(raw_out), raw_backlen = sizeof(raw_back);
    rc = SKF_ExtRSAPriKeyOperation(dev, &extpri, raw_in, sizeof(raw_in),
                                   raw_out, &raw_outlen);
    check("SKF_ExtRSAPriKeyOperation", rc, rc == SAR_OK);
    rc = SKF_ExtRSAPubKeyOperation(dev, &extpub, raw_out, raw_outlen,
                                   raw_back, &raw_backlen);
    check("SKF_ExtRSAPubKeyOperation", rc,
          rc == SAR_OK && raw_backlen == sizeof(raw_in) &&
          memcmp(raw_in, raw_back, sizeof(raw_in)) == 0);

    /* RSA import */
    RSA *ir = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(ir, 1024, e, NULL);
    RSAPRIVATEKEYBLOB rblob;
    fill_rsa_private_blob(ir, &rblob);
    HCONTAINER imprsa = NULL;
    rc = SKF_CreateContainer(app, (LPSTR)"SOFTIMPRSA", &imprsa);
    check("SKF_CreateContainer(IMPRSA)", rc, rc == SAR_OK && imprsa);
    rc = SKF_ImportRSAKeyPair(imprsa, SGD_SM4_ECB, (BYTE *)&rblob,
                              sizeof(rblob), NULL, 0);
    check("SKF_ImportRSAKeyPair", rc, rc == SAR_OK);

    /* Certificate import/export on the container that holds ir's key. */
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, ir);
    X509 *x = X509_new();
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_get_notBefore(x), 0);
    X509_gmtime_adj(X509_get_notAfter(x), 31536000L);
    X509_set_pubkey(x, pkey);
    X509_sign(x, pkey, EVP_sha256());
    int derlen = i2d_X509(x, NULL);
    unsigned char *der = malloc((size_t)derlen);
    unsigned char *dp = der;
    i2d_X509(x, &dp);
    rc = SKF_ImportCertificate(imprsa, TRUE, der, (ULONG)derlen);
    check("SKF_ImportCertificate", rc, rc == SAR_OK);
    unsigned char certout[2048];
    ULONG certoutlen = sizeof(certout);
    rc = SKF_ExportCertificate(imprsa, TRUE, certout, &certoutlen);
    check("SKF_ExportCertificate", rc,
          rc == SAR_OK && certoutlen == (ULONG)derlen &&
          memcmp(der, certout, certoutlen) == 0);
    free(der);
    X509_free(x);
    EVP_PKEY_free(pkey);
    RSA_free(ir);
    BN_free(e);
    EC_KEY_free(ik);

    /* Files */
    SKF_DeleteFile(app, (LPSTR)"SOFT.TMP");
    rc = SKF_CreateFile(app, (LPSTR)"SOFT.TMP", 64,
                        SECURE_ANYONE_ACCOUNT, SECURE_ANYONE_ACCOUNT);
    check("SKF_CreateFile", rc, rc == SAR_OK);
    BYTE fdata[] = "softskf-file-data";
    rc = SKF_WriteFile(app, (LPSTR)"SOFT.TMP", 3, fdata, sizeof(fdata));
    check("SKF_WriteFile", rc, rc == SAR_OK);
    BYTE fread[64];
    ULONG freadlen = sizeof(fread);
    rc = SKF_ReadFile(app, (LPSTR)"SOFT.TMP", 3, sizeof(fdata), fread,
                      &freadlen);
    check("SKF_ReadFile", rc,
          rc == SAR_OK && freadlen == sizeof(fdata) &&
          memcmp(fread, fdata, sizeof(fdata)) == 0);
    FILEATTRIBUTE fa;
    rc = SKF_GetFileInfo(app, (LPSTR)"SOFT.TMP", &fa);
    check("SKF_GetFileInfo", rc, rc == SAR_OK && fa.FileSize == 64);
    rc = SKF_DeleteFile(app, (LPSTR)"SOFT.TMP");
    check("SKF_DeleteFile", rc, rc == SAR_OK);

    /* Symmetric / hash / MAC */
    check("SM4-ECB roundtrip", 0, do_sm4_roundtrip(dev, SGD_SM4_ECB));
    check("SM4-CBC roundtrip", 0, do_sm4_roundtrip(dev, SGD_SM4_CBC));
    check("SM4-CFB roundtrip", 0, do_sm4_roundtrip(dev, SGD_SM4_CFB));
    check("SM4-OFB roundtrip", 0, do_sm4_roundtrip(dev, SGD_SM4_OFB));

    HANDLE sm1 = NULL;
    rc = SKF_SetSymmKey(dev, (BYTE *)authkey, SGD_SM1_ECB, &sm1);
    check("SM1 returns NOTSUPPORT", rc, rc == SAR_NOTSUPPORTYETERR);
    rc = SKF_SetSymmKey(dev, (BYTE *)authkey, SGD_SSF33_ECB, &sm1);
    check("SSF33 returns NOTSUPPORT", rc, rc == SAR_NOTSUPPORTYETERR);

    HANDLE hmac = NULL;
    rc = SKF_SetSymmKey(dev, (BYTE *)authkey, SGD_SM4_MAC, &hmac);
    check("SKF_SetSymmKey(MAC)", rc, rc == SAR_OK);
    HANDLE mac = NULL;
    BLOCKCIPHERPARAM mp;
    memset(&mp, 0, sizeof(mp));
    if (rc == SAR_OK)
        rc = SKF_MacInit(hmac, &mp, &mac);
    check("SKF_MacInit", rc, rc == SAR_OK && mac);
    BYTE macout[16];
    ULONG maclen = sizeof(macout);
    rc = SKF_Mac(mac, (BYTE *)"hello", 5, macout, &maclen);
    check("SKF_Mac", rc, rc == SAR_OK && maclen == 16);
    if (mac) SKF_CloseHandle(mac);
    if (hmac) SKF_CloseHandle(hmac);

    HANDLE hhash = NULL;
    rc = SKF_DigestInit(dev, SGD_SM3, NULL, NULL, 0, &hhash);
    check("SKF_DigestInit", rc, rc == SAR_OK && hhash);
    BYTE hashout[32];
    ULONG hashlen = sizeof(hashout);
    rc = SKF_Digest(hhash, (BYTE *)"abc", 3, hashout, &hashlen);
    check("SKF_Digest", rc, rc == SAR_OK && hashlen == 32);
    if (hhash) SKF_CloseHandle(hhash);

    BYTE rnd[16];
    rc = SKF_GenRandom(dev, rnd, sizeof(rnd));
    check("SKF_GenRandom", rc, rc == SAR_OK);

    /* cleanup */
    if (ecc1) SKF_CloseContainer(ecc1);
    if (ecc2) SKF_CloseContainer(ecc2);
    if (rsa) SKF_CloseContainer(rsa);
    if (impecc) SKF_CloseContainer(impecc);
    if (imprsa) SKF_CloseContainer(imprsa);
    SKF_DeleteContainer(app, (LPSTR)"SOFTECC");
    SKF_DeleteContainer(app, (LPSTR)"SOFTECC2");
    SKF_DeleteContainer(app, (LPSTR)"SOFTRSA");
    SKF_DeleteContainer(app, (LPSTR)"SOFTIMPECC");
    SKF_DeleteContainer(app, (LPSTR)"SOFTIMPRSA");
    SKF_CloseApplication(app);
    SKF_DisConnectDev(dev);
    free(names);

    printf("\nFailures: %d\n", failures);
    return failures ? 1 : 0;
}
