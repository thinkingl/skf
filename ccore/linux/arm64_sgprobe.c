/* Minimal vendor-SCSI probe for the C*Core USB key.
 *
 * This is transport-only: it opens /dev/sgN and reads one 512-byte block
 * with the vendor READ(16)-style CDB 0xC1.  It is intentionally portable so
 * it can be built natively on x86-64 and cross-built for arm64.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>

static void dump(const unsigned char *p, int n)
{
    for (int i = 0; i < n; i++) {
        if (i % 16 == 0)
            printf("%04x: ", i);
        printf("%02x ", p[i]);
        if (i % 16 == 15)
            putchar('\n');
    }
    if (n % 16)
        putchar('\n');
}

static int do_read(int fd, unsigned char *buf, int len)
{
    unsigned char cdb[16];
    unsigned char sb[32];
    sg_io_hdr_t io;

    memset(cdb, 0, sizeof(cdb));
    memset(sb, 0, sizeof(sb));
    memset(&io, 0, sizeof(io));
    cdb[0] = 0xc1;
    cdb[3] = (unsigned char)(((len + 511) & ~511) >> 8);

    io.interface_id = 'S';
    io.dxfer_direction = SG_DXFER_FROM_DEV;
    io.cmd_len = sizeof(cdb);
    io.cmdp = cdb;
    io.mx_sb_len = sizeof(sb);
    io.dxfer_len = (len + 511) & ~511;
    io.dxferp = buf;
    io.timeout = 1000;
    io.sbp = sb;

    if (ioctl(fd, SG_IO, &io) < 0)
        return -errno;
    printf("read: status=0x%x host=0x%x driver=0x%x resid=%d sb_len=%d\n",
           io.status, io.host_status, io.driver_status, io.resid, io.sb_len_wr);
    if (io.sb_len_wr)
        dump(sb, io.sb_len_wr);
    return 0;
}

static int do_write(int fd, const unsigned char *buf, int len)
{
    unsigned char cdb[16];
    unsigned char sb[32];
    sg_io_hdr_t io;

    memset(cdb, 0, sizeof(cdb));
    memset(sb, 0, sizeof(sb));
    memset(&io, 0, sizeof(io));
    cdb[0] = 0xc0;
    cdb[3] = (unsigned char)(((len + 511) & ~511) >> 8);

    io.interface_id = 'S';
    io.dxfer_direction = SG_DXFER_TO_DEV;
    io.cmd_len = sizeof(cdb);
    io.cmdp = cdb;
    io.mx_sb_len = sizeof(sb);
    io.dxfer_len = (len + 511) & ~511;
    io.dxferp = (void *)buf;
    io.timeout = 2000;
    io.sbp = sb;

    if (ioctl(fd, SG_IO, &io) < 0)
        return -errno;
    printf("write: status=0x%x host=0x%x driver=0x%x resid=%d sb_len=%d\n",
           io.status, io.host_status, io.driver_status, io.resid, io.sb_len_wr);
    if (io.sb_len_wr)
        dump(sb, io.sb_len_wr);
    return 0;
}

int main(int argc, char **argv)
{
    const char *dev = argc > 1 ? argv[1] : "/dev/sg3";
    unsigned char buf[512];
    int fd, rc;

    memset(buf, 0, sizeof(buf));
    fd = open(dev, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "open %s: %s\n", dev, strerror(errno));
        return 1;
    }
    printf("device: %s\n", dev);
    rc = do_read(fd, buf, sizeof(buf));
    if (rc < 0) {
        fprintf(stderr, "SG_IO read: %s\n", strerror(-rc));
        close(fd);
        return 1;
    }
    dump(buf, 32);

    /* The vendor library's open handshake: echo the first frame back with
     * "checking" + a challenge in the first 16 bytes.  The device replies
     * with the bitwise complement of the challenge. */
    unsigned char w[512];
    memcpy(w, buf, sizeof(w));
    memcpy(w, "checking", 8);
    const unsigned char chal[8] = {0xaa, 0xbb, 0xcc, 0xdd,
                                   0x11, 0x22, 0x33, 0x44};
    memcpy(w + 8, chal, 8);
    rc = do_write(fd, w, sizeof(w));
    if (rc < 0) {
        fprintf(stderr, "SG_IO write: %s\n", strerror(-rc));
        close(fd);
        return 1;
    }

    memset(buf, 0, sizeof(buf));
    rc = do_read(fd, buf, sizeof(buf));
    if (rc < 0) {
        fprintf(stderr, "SG_IO read: %s\n", strerror(-rc));
        close(fd);
        return 1;
    }
    dump(buf, 32);
    if (memcmp(buf, "checking", 8) == 0 &&
        buf[8] == 0x55 && buf[9] == 0x44 && buf[10] == 0x33 &&
        buf[11] == 0x22 && buf[12] == 0xee && buf[13] == 0xdd &&
        buf[14] == 0xcc && buf[15] == 0xbb) {
        printf("handshake: OK (complement received)\n");
    } else {
        printf("handshake: unexpected response\n");
    }

    close(fd);
    return 0;
}
