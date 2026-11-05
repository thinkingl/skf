/* Send one vendor APDU after the C*Core handshake. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>

static int xfer(int fd, int write, const unsigned char *buf, int len,
                unsigned char *out)
{
    unsigned char cdb[16], sb[32];
    sg_io_hdr_t io;
    memset(cdb, 0, sizeof(cdb));
    memset(sb, 0, sizeof(sb));
    memset(&io, 0, sizeof(io));
    cdb[0] = write ? 0xc0 : 0xc1;
    cdb[3] = (unsigned char)(((len + 511) & ~511) >> 8);
    io.interface_id = 'S';
    io.dxfer_direction = write ? SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV;
    io.cmd_len = sizeof(cdb);
    io.cmdp = cdb;
    io.mx_sb_len = sizeof(sb);
    io.dxfer_len = (len + 511) & ~511;
    io.dxferp = write ? (void *)buf : out;
    io.timeout = 2000;
    io.sbp = sb;
    if (ioctl(fd, SG_IO, &io) < 0)
        return -errno;
    return 0;
}

static int handshake(int fd)
{
    unsigned char r[512], w[512];
    if (xfer(fd, 0, NULL, 512, r) < 0)
        return -1;
    memcpy(w, r, 512);
    memcpy(w, "checking", 8);
    const unsigned char chal[8] = {0xaa,0xbb,0xcc,0xdd,0x11,0x22,0x33,0x44};
    memcpy(w + 8, chal, 8);
    if (xfer(fd, 1, w, 512, NULL) < 0)
        return -1;
    memset(r, 0, sizeof(r));
    if (xfer(fd, 0, NULL, 512, r) < 0)
        return -1;
    if (memcmp(r, "checking", 8) ||
        r[8] != 0x55 || r[9] != 0x44 || r[10] != 0x33 ||
        r[11] != 0x22 || r[12] != 0xee || r[13] != 0xdd ||
        r[14] != 0xcc || r[15] != 0xbb)
        return -2;
    return 0;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(int argc, char **argv)
{
    const char *dev = argc > 1 ? argv[1] : "/dev/sg3";
    const char *hex = argc > 2 ? argv[2] : "80b9000000000010";
    unsigned char apdu[512], req[512], resp[512];
    int alen = 0;

    for (const char *p = hex; p[0] && p[1]; p += 2) {
        int hi = hexval(p[0]), lo = hexval(p[1]);
        if (hi < 0 || lo < 0) { fprintf(stderr, "bad hex\n"); return 1; }
        apdu[alen++] = (unsigned char)((hi << 4) | lo);
    }

    int fd = open(dev, O_RDWR);
    if (fd < 0) { perror(dev); return 1; }
    int rc = handshake(fd);
    if (rc) { fprintf(stderr, "handshake failed: %d\n", rc); return 1; }

    memset(req, 0, sizeof(req));
    memcpy(req, "DEMO", 4);
    req[4] = (unsigned char)(alen >> 24);
    req[5] = (unsigned char)(alen >> 16);
    req[6] = (unsigned char)(alen >> 8);
    req[7] = (unsigned char)alen;
    req[12] = 0x12; req[13] = 0x34; req[14] = 0x56; req[15] = 0x78;
    memcpy(req + 16, apdu, alen);
    if (xfer(fd, 1, req, 512, NULL) < 0) { perror("write"); return 1; }
    memset(resp, 0, sizeof(resp));
    if (xfer(fd, 0, NULL, 512, resp) < 0) { perror("read"); return 1; }
    printf("response (%d bytes):\n", 512);
    for (int i = 0; i < 64; i++) {
        printf("%02x ", resp[i]);
        if (i % 16 == 15) putchar('\n');
    }
    close(fd);
    return 0;
}
