# Recovered container certificates

These files are **public X.509 certificates**, not private keys.

## `K01231-85422873-3457921-sign.der`

Original signing certificate of the KEDA container
`K01231-85422873-3457921`, recovered from the SG trace
`linux/reimpl/ctn_trace.log` (captured 2026-10-30, before the container's
certificate EF `0x1502` was overwritten by the old fixed-EF native bug).

- DER size: 449 bytes
- SHA-256: `bdc2b2dbf761ba48ae8f0f336c2386165dc26399d38485a4d8ecfbbb5497b9af`
- Subject: `C=CN, ST=shanghai, O=keda, OU=cu, CN=130928198408305555`
- Issuer: `C=CN, ST=Shanghai, L=Xuhui, O=PKU, OU=CS, CN=CA`
- Serial: `0909977BC89749E4B72BFB5B`
- Validity: 2023-06-25 to 2033-06-22
- Public key: SM2, coordinates
  - X: `81d106785470fc77986f1ed052ef89cb6c54a9c9b4092e2c64b8c3af1e6691e4`
  - Y: `18286db1660fad7ffea1fb9ff0e6cc34c539a3c21321f27814d32645a3e16ba4`

The public key matches the current signing public key of the container, and
`SKF_ECCSignData` output verifies against this certificate's public key.

Restored into the device on 2026-11-05 with the native
`SKF_ImportCertificate(hCtn, TRUE, der, derlen)`. The previous corrupted
375-byte RSA test certificate is backed up in
`/tmp/opencode/k01231_cert_before_restore.der` for this session.

Recovery method: the raw SG trace contains the complete response to the
`00 B0` read of EF `0x1502`. The DER length (`30 82 01 BD` = 449 bytes)
matches the FCI size (`0x01C1` = 449), so the extraction is complete.

See `external-verify/` for an OpenSSL-only verification of device signatures
against this certificate.
