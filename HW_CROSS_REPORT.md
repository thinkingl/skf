# 硬件 UKey × SoftSKF 交叉验证报告

- 日期：2026-11-05
- 硬件：C*Core CCM3302（序列号已隐藏），USB `02e3:0702`
- 硬件库：厂商 `libskf.so`（本机为 `../ccore/linux/lib/libskf.so`）
- 软库：`./libsoftskf.so`
- 硬件应用：`KEDA`，USER PIN `123456`
- 软令牌：`/tmp/softskf-xval/softskf0`，`KEDA`，USER PIN `123456`
- 交叉程序：`tests/hw_cross_test.c`

硬件库通过 `SG_IO` 访问 `/dev/sdd`，因此交叉程序以 root 运行。

## 结果

```text
hardware device: sdd1
software device: softskf0

[PASS] SKF_ConnectDev                             hw=0x00000000 soft=0x00000000
[PASS] SKF_GetDevState                            hw=0x00000000/1 soft=0x00000000/1
[PASS] SKF_GetDevInfo                             hw=C*CORE/<redacted> caps=0x80000713 soft=SoftSKF/3DCC0C06DA760CF8 caps=0x41f
[PASS] SKF_EnumApplication contains KEDA          hw=1 soft=1
[PASS] SKF_OpenApplication(KEDA)                  hw=0x00000000 soft=0x00000000
[PASS] SKF_GetPINInfo                             hw max=6 rem=6 def=0 soft max=6 rem=6 def=0
[PASS] SKF_VerifyPIN(KEDA/123456)                 hw=0x00000000 soft=0x00000000
[PASS] SKF_GenRandom                              hw=0x00000000 soft=0x00000000
[PASS] SKF_LockDev/UnlockDev                      lock=0x00000000/0x00000000 unlock=0x00000000/0x00000000
[PASS] SM4-ECB ciphertext                         ciphertext match (16 bytes)
[PASS] SM4 cross-decrypt                          hw<-soft=OK soft<-hw=OK
[PASS] SM4-CBC ciphertext                         ciphertext match (16 bytes)
[PASS] SM4 cross-decrypt                          hw<-soft=OK soft<-hw=OK
[NA  ] SM4-CFB128 ciphertext                      hw=0x0a000003 soft=0x00000000 (not comparable)
[PASS] SM4-OFB ciphertext                         ciphertext match (16 bytes)
[PASS] SM4 cross-decrypt                          hw<-soft=OK soft<-hw=OK
[PASS] SM4 CBC-MAC                                hw rc=0x00000000 len=16 soft rc=0x00000000 len=16
[PASS] SM3 digest                                 len hw=32 soft=32
[PASS] SHA1 digest                                len hw=20 soft=20
[PASS] SHA256 digest                              len hw=32 soft=32
[DIFF] SM1 expected difference                    hw=0x00000000 soft=0x0a000003
[PASS] HW SM2 sign -> soft verify                 hw sign=0x00000000 soft verify=0x00000000
[PASS] Soft SM2 sign -> HW verify                 soft sign=0x00000000 hw verify=0x00000000
[PASS] ExtECCSign HW -> soft verify               hw sign=0x00000000 soft verify=0x00000000
[PASS] ExtECCSign soft -> HW verify               soft sign=0x00000000 hw verify=0x00000000
[PASS] ExtECCEncrypt HW -> soft decrypt           hw enc=0x00000000 soft dec=0x00000000
[PASS] ExtECCEncrypt soft -> HW decrypt           soft enc=0x00000000 hw dec=0x00000000
[PASS] Soft RSA sign -> HW verify                 soft sign=0x00000000 hw verify=0x00000000

Summary: PASS=26 FAIL=0 DIFF=1 NA=1
```

## 差异说明

- `SM1`：硬件支持，软库按评审决定返回 `SAR_NOTSUPPORTYETERR`，属于**预期差异**。
- `SM4-CFB128`：厂商硬件库 `SKF_SetSymmKey` 返回 `SAR_NOTSUPPORTYETERR`，无法比较；
  软库支持 CFB128。
- `SKF_GetDevInfo` 的厂商/序列号/能力位必然不同，表格只比较调用是否成功。
- 硬件 KEDA 容器 `SKF_GetContainerType` 返回 2，但 `SKF_ExportPublicKey` 返回
  256 位 ECC 公钥；交叉程序按公钥 blob 实际类型判断，不依赖该字段的厂商私有语义。

## 复现

```bash
export SOFTSKF_HOME=/tmp/softskf-xval
./softskf-init --auth-key 0123456789abcdef \
  --app KEDA --admin-pin 123456 --user-pin 123456

make hw-cross
sudo env SOFTSKF_HOME=/tmp/softskf-xval ./tests/hw_cross_test \
  /path/to/vendor/libskf.so ./libsoftskf.so
```

硬件库需要 root 或 `CAP_SYS_RAWIO`；程序只做读取、验签、签名、加解密和锁测试，
不创建/删除硬件应用或容器，不修改硬件 PIN。
