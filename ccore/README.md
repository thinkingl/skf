# C*Core USB Key (02e3:0702) — Linux SKF

New UKey: **C*Core USB Key**, USB ID `02e3:0702`, product string
`CCore USB CCID DEVICE`.

Despite the product string, the USB interface is **Mass Storage / SCSI
Bulk-Only** (class `08/06/50`), not USB CCID. The vendor SKF library talks to
it with vendor SCSI commands (`0xC0` write / `0xC1` read) through `/dev/sdX`.

Detailed wire protocol: [`PROTOCOL.md`](PROTOCOL.md). It documents the SCSI
transport, frame/APDU formats, status words, device authentication, application
list, PIN/key objects, directories, files and containers.

## Result

Linux SKF works with the generic C*Core `libskf.so` (438 KB, the one from
`/home/x/code/work/cu2.0/.../libskf.so`), **not** with
`libskf_szgx_3310uk.so` (that one enumerates the device but returns
`SAR_UNKNOWNERR` on connect).

Verified with the device plugged in and running as root:

```text
SKF_EnumDev        SAR_OK, names: sdd1, sdd
SKF_GetDevState    SAR_OK, state=0x1
SKF_ConnectDev     SAR_OK
SKF_GetDevInfo     SAR_OK
  Manufacturer     C*CORE
  Issuer           XXXX
  Label            UKEY
  SerialNumber     3430483532044F43
  HWVersion        1.0
  FirmwareVersion  1.24
  TotalSpace       115680
  FreeSpace        109440
  MaxECCBufferSize 256
  MaxBufferSize    59360
SKF_EnumApplication
  DEFAULT
  KEDA
SKF_EnumContainer
  DEFAULT (in both apps)
  K01231-85422873-3457921 (KEDA)
SKF_GenRandom      SAR_OK (16 bytes)
```

## PIN status

Verified with `linux/skf_pin`:

```text
KEDA/USER   GetPINInfo max=6 remain=6 default=0
KEDA/USER   VerifyPIN(123456) -> SAR_OK, retry=0
```

So the **KEDA application user PIN is `123456`**.

Warning: the `DEFAULT` application's user PIN has only **1 retry left**
(`remain=1`). Do not try guesses against `DEFAULT`; one wrong attempt can lock
it.

No PIN verification was attempted against `DEFAULT` or either ADMIN PIN.

## ARM64 / aarch64

The local vendor trees do **not** contain an arm64 `libskf.so`.  They do
contain an arm64 SDF stack (`libkdssl-ext.so` + `libsdf_crypto.so`), which is
the path the vendor's ARM K2MS client uses.  The SDF library talks through a
netlink kernel driver, so it is not a drop-in SKF replacement.

The SKF transport itself is portable: see `ARM64.md` and
`linux/arm64_sgprobe.c`.  The probe implements the vendor SCSI handshake with
plain `SG_IO` and can be cross-compiled:

```bash
aarch64-linux-gnu-gcc -static -O2 -o linux/arm64_sgprobe_aarch64 linux/arm64_sgprobe.c
```

It works on x86-64; qemu-user does not pass `SG_IO` through, so it must be
tested on real arm64 hardware or a full-system VM with USB passthrough.

## Native SKF reimplementation

`linux/reimpl/skf_native.c` implements SKF directly over the vendor SCSI
transport, without linking the vendor `libskf.so`.  It covers device
authentication, applications/containers, PIN verification/change/unblock,
file management, certificates, ECC key generation/signing/verification/
encryption, container RSA generation/signing/verification/session-key export,
symmetric/hash/MAC (software SM4/SM3), external RSA, native import paths and
ECC agreement.  See `SKF_NATIVE_REPORT.md` for details and
[`PROTOCOL.md`](PROTOCOL.md) for the wire protocol.

```bash
cd linux
make native
LD_LIBRARY_PATH="$PWD/reimpl" ./skf_test_generic
LD_LIBRARY_PATH="$PWD/reimpl" ./skf_all "$PWD/reimpl/libskf_native.so"
LD_LIBRARY_PATH="$PWD/reimpl" ./skf_destructive
LD_LIBRARY_PATH="$PWD/reimpl" ./skf_imports_test
```

For arm64, build with an aarch64 `libcrypto`:

```bash
make -C linux native-arm64
```

Standard RSA wrapped-key and ECC `ENVELOPEDKEYBLOB` import formats are
supported when the container already has a software-imported private key.
Known limitations: importing a standard envelope into a device-generated
(non-exportable) key, `SKF_ChangeDevAuthKey`, and external ECC private key
operations (`SKF_ExtECCSign` / `SKF_ExtECCDecrypt`).
The protocol frames and the reverse-engineering notes are in `ARM64.md` and
`SKF_NATIVE_REPORT.md`.

## Why root is needed

`libskf.so` uses Linux `SG_IO` vendor SCSI commands on `/dev/sdd`/`/dev/sg3`.
The kernel requires `CAP_SYS_RAWIO` for these vendor commands, so a normal user
gets no device even if the block device is group-readable. The simplest is to
run via `sudo`:

```bash
sudo ./linux/skf_test_generic
# or
./linux/run-skf.sh
```

`setcap cap_sys_rawio+ep` also works, but secure-execution mode ignores
`$ORIGIN` rpath; use an absolute rpath or install `libskf.so` in the system
library path if you choose that route.

## Build and run

```bash
cd linux
make
sudo ./skf_test_generic          # device info, apps, containers, random
sudo ./skf_pin 123456            # KEDA/USER PIN check
sudo env SKF_DEVAUTH_KEY='<16-byte-device-key>' ./skf_all ./lib/libskf.so
sudo ./skf_destructive           # temporary container create/delete test
sudo env LD_LIBRARY_PATH="$PWD/lib" ./skf_devauth '<16-byte-device-key>' SKFA5
```

`skf_all` uses `dlopen`/`dlsym` and does not link the SKF library at build
time. It writes `linux/report.md`; the curated report is
`../SKF_API_TEST_REPORT.md`.

`skf_destructive` creates a temporary container in KEDA, tests ECC/RSA key
generation, signing, verification, session-key export and external RSA
public/private operations, then deletes the container. It does not create an
application or file (application creation requires device authentication).

`skf_devauth` performs device authentication with the 16-byte device key and,
after success, creates a temporary application, tests PIN change/lock/unlock,
file and container operations, then reconnects and deletes the application.
The key is read from argv and is not stored in the repository.

Device authentication on this firmware is a challenge/response, not a direct
key check: `SKF_GenRandom(8)` -> zero-pad to 16 -> encrypt with the key using
`DevAuthAlgId` (SM1 ECB on this device) -> `SKF_DevAuth(ciphertext)`.  See
`SKF_API_TEST_REPORT.md` for the exact sequence and the failed direct-key
attempts.

`make` also builds `skf_test_vendor` against
`libskf_szgx_3310uk.so`; that variant is known to fail on this key.
`skf_pin` accepts the PIN as its first argument and does not try `DEFAULT`
or ADMIN PINs.

## Udev permissions (optional)

`linux/udev/99-ccore-ukey.rules` makes the block and SCSI-generic nodes
group `plugdev` and mode `0660`. It does not replace `CAP_SYS_RAWIO`; it is
useful for tools that use read/write instead of SG_IO, and for group access.

```bash
sudo install -m 0644 linux/udev/99-ccore-ukey.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

## Windows tools in `win/`

- `win/ukeytool-新key/SKF.dll` — C*Core SKF 2.0.20.617, 32-bit, USB mass
  storage transport (`SKF_usb_ms.pdb`). `SKF_szgx_3310uk(1).dll` is identical
  (same MD5).
- `SKF1.dll` (1.6.16.901), `SKF2.dll` (2.0.21.1214) and `SKF_tf.dll`
  (1.6.16.325) are alternate/newer builds.
- `hwinit.exe` — creates a CSR and writes a certificate into the key
  (`FactoryHwInit`, `SKFWriteConEncCert`, ...).
- `format_tool_usb_ms.exe` — reinitializes the key if it is locked or device
  authentication fails. Static analysis shows it calls `LC_DEV_TokenInit` and
  then `LC_APP_Create` for the `DEFAULT` application with PIN `111111`.
  **Do not run this unless you intend to erase/reinit the key.**
- `libkdssl-ext.dll` — vendor wrapper around SKF; its DevAuth path
  (`SKF_GenRandom`, `SKF_SetSymmKey`, `SKF_EncryptInit`, `SKF_Encrypt`,
  `SKF_DevAuth`, `DevAuthAlgId`) revealed the challenge/response scheme.
  No plaintext device-auth key is embedded in the EXE/DLL strings.
- `使用说明.txt` — key provisioning procedure (CSR -> CA sign -> write cert).

The key already has `DEFAULT` and `KEDA` applications and a `KEDA` container,
so it is initialized; do not format it just to test SKF.

## Notes

- The Linux library handshake was observed with `strace`: vendor SCSI
  `WRITE(16)` opcode `0xC0` and `READ(16)` opcode `0xC1`, 512-byte blocks.
  The first handshake returns the bitwise-NOT of a challenge
  (`checking aa bb cc dd 11 22 33 44` -> `checking 55 44 33 22 ee dd cc bb`),
  confirming the C*Core transport.
- `SKF_EnumDev` reports both the partition (`sdd1`) and the disk (`sdd`);
  either name connects to the same key.
- The key is a **C*Core CCM3310S-H** class device (firmware 1.24).
