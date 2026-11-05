# SKF

This repository contains two related SKF implementations:

## `ccore/`

C*Core USB Key (`02e3:0702`) Linux SKF native implementation, wire-protocol
notes, differential tests and hardware audit notes.

See [`ccore/README.md`](ccore/README.md) and
[`ccore/PROTOCOL.md`](ccore/PROTOCOL.md).

## `softskf/`

Local-file backed software SKF library. It exports all 79 `SKF_*` interfaces,
stores each soft token in a per-token SQLite database, and uses OpenSSL 3 for
SM2/SM3/SM4/RSA/X.509.

SM1/SSF33 are intentionally unsupported and return `SAR_NOTSUPPORTYETERR`.

Build and test:

```bash
cd softskf
make
make test
make check
```

See [`softskf/README.md`](softskf/README.md) for initialization and
compatibility details, and [`softskf/HW_CROSS_REPORT.md`](softskf/HW_CROSS_REPORT.md)
for hardware cross-validation results.
