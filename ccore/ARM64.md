# C*Core UKey 在 arm64 Linux 上的可行性

## 1. 是否能找到 arm64 驱动库？

### 结论

**当前材料里没有 arm64 的 `libskf.so`。**

本机找到的所有 SKF 库都是 x86-64：

```text
linux/lib/libskf.so                         ELF 64-bit x86-64
linux/lib/libskf_szgx_3310uk.so             ELF 64-bit x86-64
work/cu2.0/.../Linux/x86_64/libskf.so       ELF 64-bit x86-64
35114/.../linux-x86-64/libskf.so            ELF 64-bit x86-64
```

Windows 包也只有 32 位 DLL，没有 ARM64 DLL。

### 但找到了 arm64 的厂商 SDF 栈

这些目录里有 aarch64 库：

```text
work/cu2.0/14-sipauth/thirdparty/kmslib/lib/Linux/aarch64/
  libkdssl-ext.so       ARM aarch64
  libsdf_crypto.so      ARM aarch64
  libk2ms.so            ARM aarch64

35114/k2ms-client/src/main/resources/linux-aarch64/
  libkdssl-ext.so       ARM aarch64
  libsdf_crypto.so      ARM aarch64
  libk2ms.so            ARM aarch64
```

注意：**没有 `libskf.so`**。

`libkdssl-ext.so` 是一个动态加载器/封装层，字符串里会尝试加载：

```text
libskf.so
libskf_szgx_uk.so
libskf_szgx_3310uk.so
libskf_szgx_ccu3a.so
libsdf_crypto.so
```

在 arm64 上它找不到 `libskf.so`，但可以走 `libsdf_crypto.so` 的 SDF 后端。

`libsdf_crypto.so` 的版本和特征：

```text
C*CORE lib sdfcrypto version : 2.0.9 (2020-07-06)
LC_PLAT_LINUX_NETLINK
socket / bind / sendmsg / recvmsg
LC_CMD_OPEN_DEVICE / LC_CMD_GET_DEVINFO / ...
```

它不是直接走 USB SCSI，而是走 **netlink 内核驱动/服务**（`LC_PLAT_LINUX_NETLINK`）。因此：

- 它是厂商 ARM64 方案的一部分；
- 但它不是 SKF 的 drop-in 替代；
- 目标 arm64 系统必须安装/加载对应的 C*Core 内核驱动或 netlink 服务，否则 `SDF_OpenDevice` 无法工作。

`35114` 的 Java K2MS 客户端也明确区分了架构：

```java
if (Platform.isARM()) {
    // 飞腾
    copyFile("/linux-aarch64/", "liblibkdssl-ext.so", loadPath);
    copyFile("/linux-aarch64/", "libsdf_crypto.so", loadPath);
    // 不复制 libskf.so
} else {
    // x86
    copyFile("/linux-x86-64/", "libskf.so", userDir);
    ...
}
```

这说明厂商当前的 ARM64 路径是 **SDF**，不是 SKF。

### 设备本身需要什么驱动？

不需要专门的 USB 内核驱动。设备是标准 USB Mass Storage：

```text
USB ID        02e3:0702
接口          Mass Storage / SCSI Bulk-Only
内核驱动      usb-storage + sg
设备节点      /dev/sdX, /dev/sgN
vendor SCSI   WRITE(16) 0xC0 / READ(16) 0xC1
```

x86-64 上的 `libskf.so` 就是通过 `/dev/sgN` 发 vendor SCSI 命令，不需要额外内核模块。

所以缺的只是 **用户态 arm64 SKF 库**，不是内核驱动。

## 2. 能否从当前 SKF 库反向出设备协议？

### 结论

**可以，而且已经完成了第一层验证。**

x86-64 `libskf.so` 没有 strip，符号和源文件名都在：

```text
SendCmd
GetAPDUData
Linux_USB_OpenDevice / ReadDevice / WriteDevice
CCORE_DEV_author / ccore_devauth
CCORE_APP_* / CCORE_CTN_* / CCORE_FILE_* / CCORE_PIN_* / CCORE_SM2_* / CCORE_RSA_*
ccore_apdu.c / ccore_device.c / linux_driver_usb.c / ...
```

### 已确认的传输层

`strace -e ioctl` 抓到实际 `SG_IO`：

```text
READ:  cdb = c1 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00
WRITE: cdb = c0 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00
dxfer_len = 512
```

即：

- `0xC0` = vendor WRITE，`0xC1` = vendor READ；
- 每次 512 字节；
- CDB[3] = 512/256 = 2。

### 已确认的握手

打开设备后：

```text
写: "checking" + aa bb cc dd 11 22 33 44
读: "checking" + 55 44 33 22 ee dd cc bb
```

第二组是前一组 8 字节的按位取反。这个握手已经在
`linux/arm64_sgprobe.c` 中用原生 SG_IO 实现并验证通过。

### 已确认的命令帧

帧头：

```text
offset 0:  "DEMO"            44 45 4d 4f
offset 4:  length (big endian)
offset 8:  00 00 00 00
offset 12: 12 34 56 78
offset 16: APDU-like command
```

抓到的 `SKF_GetDevInfo` 相关帧：

```text
DEMO 00000008 00000000 12345678 80 aa 01 00 ...
DEMO 0000000a 00000000 12345678 00 a4 00 00 00 00 00 02 3f 00
DEMO 0000000a 00000000 12345678 00 a4 01 00 00 00 00 02 20 00
DEMO 00000010 00000000 12345678 80 b7 00 00 00 00 00 08
DEMO 00000028 00000000 12345678 00 b0 00 00 00 00 00 20
```

响应也是同样的 `DEMO` 帧，例如 `00 b0` 读回：

```text
DEMO 00000022 00000000 12345678 00 b0 00 00
55 4b 45 59 00 20 20 20 ...   ("UKEY" + 空格)
```

这说明 APDU 层可以逐条抓取、逐条实现。

### 已完成的 arm64 代码

`linux/arm64_sgprobe.c`：

- 打开 `/dev/sgN`；
- 发 `0xC1` 读 512 字节；
- 发 `0xC0` 写握手；
- 校验设备返回的取反 challenge；
- 交叉编译为 aarch64 静态 ELF：

```bash
aarch64-linux-gnu-gcc -static -O2 -o arm64_sgprobe_aarch64 linux/arm64_sgprobe.c
```

x86-64 上实测：

```text
handshake: OK (complement received)
```

### QEMU 用户态的限制

在 x86-64 上用 `qemu-aarch64-static` 运行该 arm64 程序时：

```text
SG_IO read: Inappropriate ioctl for device
```

`qemu-user` 不透传 `SG_IO`（`0x2285`），`qemu-x86_64-static` 也一样。
所以：

- **不能**用 qemu-user 在 x86 上验证 arm64 的 SG_IO 路径；
- **也不能**指望用 qemu-user 跑 x86-64 `libskf.so` 来绕过 arm64 移植；
- 必须在真实 arm64 机器、arm64 全系统虚拟机（带 USB 直通），或支持 SG_IO 的兼容层上测试。

## 3. 建议的落地方案

### 方案 A：应用改用 SDF（最省事，如果业务允许）

使用厂商已有的 arm64：

```text
libkdssl-ext.so + libsdf_crypto.so
```

前提：

- 目标 arm64 系统有对应的 C*Core 内核驱动/netlink 服务；
- 应用可以接受 SDF（GM/T 0018）而不是 SKF（GM/T 0016）。

这是厂商 K2MS ARM 客户端已经在用的路径。

### 方案 B：原生 arm64 SKF shim（保留 SKF API）

用 SG_IO 直接实现一个 arm64 `libskf.so`：

1. 枚举 `/dev/sgN`，用 SG_IO 发 `0xC0/0xC1`；
2. 实现 `DEMO` 帧的收发和握手；
3. 按 `SKF` 接口抓取/实现 APDU；
4. 先实现业务实际用到的子集，而不是一上来做全 79 个接口；
5. 在真实 arm64 上验证。

工作量取决于接口子集：

- 传输层 + 枚举/连接/设备信息：小；
- 应用/容器/PIN/证书/ECC 签名验签：中等；
- 全量 79 接口（含导入、协商、文件系统、RSA/ECC 扩展）：较大。

### 方案 C：box64 / 其他二进制兼容层

可以尝试，但 `SG_IO` 透传是风险点。qemu-user 已确认不行；box64 需要在目标 arm64 上实测。
不建议作为唯一方案。

## 4. 下一步需要的信息

如果要继续做原生 arm64 SKF：

1. 目标系统：发行版、内核版本、CPU（飞腾/鲲鹏/其他）；
2. 应用实际调用的 SKF 接口列表（可以先抓 `dlsym`/链接符号）；
3. 是否能提供一台 arm64 测试机，或带 USB 直通的 arm64 虚拟机；
4. 是否接受先用 SDF 路径，还是必须保持 SKF API。

有了 1-3，下一步可以把 `arm64_sgprobe.c` 扩展成：
`EnumDev -> ConnectDev -> GetDevInfo -> EnumApplication -> OpenApplication -> VerifyPIN -> ECCSignData` 的最小闭环。
