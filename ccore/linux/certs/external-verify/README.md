# External SM2 verification of K01231 signatures

This directory contains a reproducible external verification of signatures
produced by the C*Core device. Only public data is stored here.

## Files

- `pub.pem` — public key extracted from
  `../K01231-85422873-3457921-sign.der` (the certificate exported from the
  device)
- `message.bin` — `ccore K01231 external SM2 verification\n`
- `e-sm3.bin` — standard SM2 digest
  `e = SM3(ZA || message)`, with the default SM2 user ID
  `1234567812345678`
- `sig-vendor.der` — signature produced through the vendor `libskf.so`
- `sig-native.der` — signature produced through `libskf_native.so`

The two signatures are different because SM2 signing is randomized, but both
verify against the same certificate public key.

## Verification

```sh
openssl pkeyutl -verify \
  -pubin -inkey pub.pem \
  -in e-sm3.bin \
  -sigfile sig-vendor.der

openssl pkeyutl -verify \
  -pubin -inkey pub.pem \
  -in e-sm3.bin \
  -sigfile sig-native.der
```

Expected:

```text
Signature Verified Successfully
Signature Verified Successfully
```

## Negative checks

```sh
python3 - <<'PY'
b=bytearray(open('e-sm3.bin','rb').read())
b[0] ^= 1
open('/tmp/bad-e.bin','wb').write(b)
s=bytearray(open('sig-vendor.der','rb').read())
s[-1] ^= 1
open('/tmp/bad-sig.der','wb').write(s)
PY

openssl pkeyutl -verify -pubin -inkey pub.pem \
  -in /tmp/bad-e.bin -sigfile sig-vendor.der        # fails
openssl pkeyutl -verify -pubin -inkey pub.pem \
  -in e-sm3.bin -sigfile /tmp/bad-sig.der           # fails
```

## Important digest convention

`SKF_ECCSignData` signs a caller-supplied 32-byte digest. In this test the
digest is the standard SM2 value `e = SM3(ZA || message)`, using the default
user ID.

The verification command passes `e` directly to `openssl pkeyutl` (digest
mode). Do not add `-rawin -digest sm3` here: that asks OpenSSL to perform its
own SM2 hashing/ZA step, which is not the same as verifying a signature over a
precomputed `e` and therefore does not verify this signature. The direct
`EVP_PKEY_verify`/`pkeyutl` digest input matches what `SKF_ECCSignData`
actually signs.

## SHA-256

```text
5f1b31e845a65122abf129933370e286ca6c7dfd3df2368a6f757f1a97cdc9d5  e-sm3.bin
87f9338602dbc8dad31c06fc235814b2d13a7deab931f46f009a6a93212afc7c  message.bin
19772ba054f373d313a6102f76f48acc6600672c43d1c6409476a79af1a777a9  pub.pem
a08dd402ecb653e2e124d2279ed025bc73ad7f1d640715e82c2d8b8fc63c1b8e  sig-native.der
c04ca289493aba1037041e61fdc7b15883d5707221d074b8d086693e38e4359d  sig-vendor.der
```
