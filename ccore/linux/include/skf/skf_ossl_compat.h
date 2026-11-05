#pragma once
/*
 * skf_ossl_compat.h - OpenSSL 1.x / 3.x portability layer for the C*Core tools.
 *
 * The certificate tests and the native reimplementation use a few OpenSSL 3
 * APIs. OpenSSL 3.x is always preferred: when it is available the real
 * <openssl/core_names.h> and the native EVP_PKEY_get_bn_param() are used and
 * nothing here is emulated. Only with an OpenSSL 1.x toolchain (for example
 * 1.1.1 on Kylin / 麒麟 V10) the missing symbols are provided so the same
 * sources compile and behave identically:
 *
 *   - OSSL_PKEY_PARAM_EC_PUB_X / _Y  -> dummy names
 *   - EVP_PKEY_get_bn_param()        -> returns 0, so callers take their
 *                                       EVP_PKEY_get1_EC_KEY() +
 *                                       EC_POINT_get_affine_coordinates()
 *                                       fallback path
 *   - EVP_PKEY_get0_type_name()      -> OBJ_nid2sn(EVP_PKEY_id())
 *
 * Detection is done from <openssl/opensslv.h>, so no build-system probing is
 * needed and cross builds (make native-arm64) behave the same way.
 */

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/objects.h>

#if defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L

/* OpenSSL 3.x: use the native core names and APIs. */
#include <openssl/core_names.h>

#else

#ifndef OSSL_PKEY_PARAM_EC_PUB_X
#define OSSL_PKEY_PARAM_EC_PUB_X "qx"
#endif
#ifndef OSSL_PKEY_PARAM_EC_PUB_Y
#define OSSL_PKEY_PARAM_EC_PUB_Y "qy"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Not available before 3.0. Failing here is deliberate: the call sites in
 * skf_native.c already fall back to the classic EC_KEY accessors. */
static inline int EVP_PKEY_get_bn_param(const EVP_PKEY *pkey, const char *name,
                    BIGNUM **val)
{
    (void)pkey;
    (void)name;
    if (val != NULL)
        *val = NULL;
    return 0;
}

/* Not available before 3.0. */
static inline const char *EVP_PKEY_get0_type_name(const EVP_PKEY *pkey)
{
    if (pkey == NULL)
        return NULL;
    return OBJ_nid2sn(EVP_PKEY_id(pkey));
}

#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_VERSION_NUMBER < 0x30000000L */
