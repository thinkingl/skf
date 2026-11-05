# Container certificate / signature mismatch — investigation report

- Date: 2026-11-05
- Device: C*Core USB Key `02e3:0702`
- Test host: x86-64 Linux (the same native code path used by the arm64 build)
- Application: `KEDA`, user PIN `123456`
- Existing container: `K01231-85422873-3457921`

## Symptom

The certificate exported from a container does not match the container's
signing key/signature. On the arm64 build this appears as a certificate whose
public key does not verify `SKF_ECCSignData()` output.

## Confirmed result before recovery

Using both the vendor `libskf.so` and the native implementation on the same
device (before the original certificate was recovered and restored):

| Item | Result |
| --- | --- |
| `SKF_ExportCertificate(K01231, sign=TRUE)` | 375-byte **RSA-1024** certificate |
| `SKF_ExportPublicKey(K01231, sign=TRUE)` | 132-byte **ECC** public key |
| `SKF_ECCSignData(K01231)` | succeeds; verifies with the exported ECC key |
| `SKF_RSASignData(K01231)` | `SAR_UNKNOWNERR` / not an RSA container |

The certificate is a self-signed RSA test certificate:

- serial number 1
- empty subject/issuer
- notBefore 2026-11-02 (the date `skf_imports_test` was run)
- `sha256WithRSAEncryption`

It is the test certificate created by `linux/skf_imports_test.c` for its
temporary RSA container, not the ECC certificate belonging to K01231.

## Root cause

The certificate EFs are **per container slot**:

```text
encryption certificate: 0x1401 + (slot - 0x1101)
signing certificate:    0x1501 + (slot - 0x1101)
```

Vendor SG traces confirm this:

- K01231 (slot `0x1102`): sign cert `0x1502`, enc cert `0x1402`
- temporary container (slot `0x1103`): sign cert `0x1503`, enc cert `0x1403`

The native `SKF_ExportCertificate()` / `SKF_ImportCertificate()` used fixed
EFs `0x1502` / `0x1501`:

```c
file = sign ? 0x1502 : 0x1501;   /* wrong for every slot except 0x1101/0x1102 */
```

Consequences:

1. Importing a certificate into any container (for example the temporary
   `SKFIMP1` at slot `0x1103`) wrote EF `0x1502`, overwriting K01231's
   certificate.
2. Exporting from `DEFAULT` (slot `0x1101`) read EF `0x1502` instead of
   `0x1501`, returning K01231's certificate.
3. Exporting from any slot other than `0x1102` read the wrong certificate, so
   the exported certificate did not match that container's key/signature.

This exactly reproduces the reported mismatch. It is not ARM-specific; the
same code is used on x86-64. The ARM build only made the difference visible
because that is where the native implementation is used.

## Why the earlier comparison test missed it

There was a real gap in the test coverage, not just a hard-to-hit bug:

1. `linux/skf_diff_test.c` **loads** `SKF_ImportCertificate` and
   `SKF_ExportCertificate` but never calls either function. They appear only in
   the `LIB` structure and the `LOAD()` list, so the vendor/native comparison
   never covered certificate behavior.
2. `linux/skf_all.c` does call `SKF_ExportCertificate`, but only records the
   return code. It never parses the certificate and never compares the
   certificate public key with `SKF_ExportPublicKey`. Its signature checks use
   the exported key file, so a completely unrelated certificate still passes.
3. `linux/skf_imports_test.c` imports and exports a certificate with the same
   library and compares the bytes round-trip. With the old fixed EF it both
   wrote and read EF `0x1502`, so the round-trip matched even though the
   certificate was stored in the wrong container. It also never checked the
   certificate public key against the container key.
4. The old hard-coded signing EF `0x1502` happens to be K01231's EF (slot
   `0x1102`). Exporting K01231 therefore looked correct, while importing a
   certificate for any other slot overwrote K01231. Tests that only exercised
   K01231 could not see the bug.
5. The earlier "comparison" checks were mostly single-library return-code
   checks. They did not compare the **content** returned by the vendor library
   and the native library for the same device state.

The old native library demonstrably fails the new differential test:

```text
[FAIL] DEFAULT                 type=0/1 sign=a00001c/0 enc=a00001c/a000031 ...
[FAIL] K01231-...             ...
```

## Fixes applied

`linux/reimpl/skf_native.c`:

- `cert_ef()` computes `0x1401/0x1501 + (slot - 0x1101)` for the current
  container slot.
- `SKF_ExportCertificate()` selects the application and container key file
  first (matching the vendor `SKF_CTN_active`), reads the FCI, uses the
  `0x80 0x02` size as the read length, and reads the EF.
- `SKF_ImportCertificate()` creates the per-slot EF with the certificate
  length in attribute bytes `[6..7]`, matching the vendor-created FCI.
- `read_file()` / `write_selected()` now transfer files in chunks of at most
  `0x1c1` (449) bytes and handle end-of-file correctly, so certificates larger
  than one chunk are not truncated.
- `cert_key_matches()` also validates certificates against **device-generated**
  ECC public keys (using the container key file and the device word order).
- `SKF_ECCSignData()` / `SKF_ExportPublicKey()` use an imported software ECC
  key when `ecc_priv_valid` is set instead of always using the device key.
- Key/certificate state is cleared when switching between ECC and RSA key
  types, avoiding stale software keys.
- `SKF_GetContainerType()` now follows the vendor convention: type 0 for an
  empty container, 1 for RSA, 2 for ECC, based on the container key file FCI
  size (`0x68` means ECC). It no longer reports a type just from the slot.
- `SKF_ExportPublicKey()` maps a missing container key file to
  `SAR_KEYNOTFOUNTERR`, matching the vendor library.

## Regression test

`linux/skf_cert_regress.c` (requires KEDA user PIN `123456`, creates and
deletes temporary containers `SKFCRT1`/`SKFCRT2`):

- device-generated ECC key: import a CA-issued certificate, export it, sign,
  verify with the certificate public key;
- imported software ECC key: self-signed certificate, export, sign, verify;
- checks that the K01231 certificate is unchanged after importing into the
  temporary containers.

Result on the test device:

```text
Failures: 0
```

Build/run:

```sh
cd linux
make native skf_cert_regress
sudo ./skf_cert_regress
```

Read-only diagnostic for the current device:

```sh
make skf_cert_check
sudo ./skf_cert_check ./reimpl/libskf_native.so K01231-85422873-3457921
```

## Vendor vs native differential test

`linux/skf_cert_diff.c` loads both libraries, enumerates every container in
`KEDA`, and compares the following for the same device state:

- container type;
- signing and encryption certificate return code, length and bytes;
- signing public key return code, length and bytes;
- certificate public key against the container signing public key.

It is read-only and is the test that was missing before. Run:

```sh
cd linux
make native skf_cert_diff
sudo ./skf_cert_diff ./lib/libskf.so ./reimpl/libskf_native.so
```

Output after restoring K01231's original certificate:

```text
[PASS] DEFAULT                 type=0/0 sign=a00001c/a00001c enc=a00001c/a00001c pub=a00001b/a00001b
[PASS] K01231-85422873-3457921 type=2/2 sign=0/0 enc=a00001c/a00001c pub=0/0
        cert <-> signing key: MATCH

PASS
```

All vendor/native output comparisons pass, and the certificate matches the
container signing key.

Before the certificate was restored, the same test reported the corruption:

```text
[PASS] K01231-85422873-3457921 type=2/2 sign=0/0 enc=a00001c/a00001c pub=0/0
        [FAIL] cert <-> signing key: MISMATCH (container key len=132, cert key does not match)
```

Against the old native library the test immediately reports the real bug:

```text
[FAIL] DEFAULT                 type=0/1 sign=a00001c/0 enc=a00001c/a000031 pub=a00001b/a000002
        vendor vs native output differs
[FAIL] K01231-...              sign=0/0 enc=a00001c/a000031 pub=0/0
        vendor vs native output differs
```

The C*Core device is a single USB target; run these tests sequentially, not in
parallel.

## Recovery of K01231's certificate

The original certificate was not lost. The 2026-10-30 SG trace
`linux/reimpl/ctn_trace.log` contains a complete read of EF `0x1502`:

- the FCI reports `0x01C1` (449) bytes;
- the read response contains a complete DER certificate
  (`30 82 01 BD`, also 449 bytes);
- its SM2 public key is exactly the current K01231 public key
  (`81D10678...E4`, `18286DB1...A4`).

The recovered certificate is stored as:

```text
linux/certs/K01231-85422873-3457921-sign.der
SHA-256 bdc2b2dbf761ba48ae8f0f336c2386165dc26399d38485a4d8ecfbbb5497b9af
```

Before writing, a fresh `SKF_ECCSignData` output was verified with the
recovered certificate's public key. It was then imported into K01231 with
`SKF_ImportCertificate(hCtn, TRUE, der, derlen)`; the exported bytes match the
recovered file exactly. The previous corrupted 375-byte RSA certificate was
backed up to `/tmp/opencode/k01231_cert_before_restore.der`.

Final state: `skf_cert_diff` is `PASS`, the certificate/public key check is
`MATCH`, and `SKF_ECCSignData` verifies with the certificate public key.

## External verification with OpenSSL

The exported certificate was also verified **outside SKF**, using OpenSSL:

1. Export sign certificate from K01231 (vendor library):
   449 bytes, SHA-256
   `bdc2b2db...b9af` (same as the recovered file).
2. Extract its SM2 public key.
3. Choose a message `M` and compute the standard SM2 digest
   `e = SM3(ZA || M)`, with default user ID `1234567812345678`.
4. Ask the device to sign `e` with `SKF_ECCSignData`.
5. Convert the raw 64-byte `r || s` signature to DER and verify:

```sh
openssl pkeyutl -verify -pubin -inkey pub.pem \
  -in e-sm3.bin -sigfile sig-vendor.der
openssl pkeyutl -verify -pubin -inkey pub.pem \
  -in e-sm3.bin -sigfile sig-native.der
```

Result:

```text
Signature Verified Successfully   # vendor library signature
Signature Verified Successfully   # native library signature
```

Both the vendor and native signing paths produce signatures that verify with
the device-exported certificate. A tampered digest or tampered signature
returns `Signature Verification Failure`.

An independent Python implementation of the SM2 verification equation also
returned `True` for both signatures, so the result is not specific to one
library.

The reproducible artifacts and commands are in
`linux/certs/external-verify/`.

Note: `SKF_ECCSignData` takes a precomputed 32-byte `e` value. The verification
above therefore passes `e` directly to `openssl pkeyutl`. Adding
`-rawin -digest sm3` makes OpenSSL perform its own SM2 hashing/ZA step, which
does not match a signature over a precomputed `e`.

## arm64 build note

The source changes are platform-independent. Cross-building here failed only
because this host lacks the arm64 OpenSSL development headers:

```text
openssl/opensslconf.h: No such file or directory
```

On the arm64 build host, install the target OpenSSL development package and run:

```sh
cd linux
make native-arm64
```
