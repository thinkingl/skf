/*
 * Native SKF reimplementation for the C*Core USB key.
 *
 * Transport: vendor SCSI over Linux SG_IO (/dev/sgN), 512-byte frames.
 * Frame: "DEMO" + BE32(apdu_len) + 4 zero bytes + 12 34 56 78 + APDU.
 *
 * This file is intentionally self-contained and has no dependency on the
 * original libskf.so.
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <scsi/sg.h>
#include <openssl/des.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include "skf_ossl_compat.h"

#include "skf.h"

#ifndef SAR_APPLICATION_EXISTS
#define SAR_APPLICATION_EXISTS 0x0A00002C
#endif

#define MAX_APDU 512

typedef struct dev_ctx {
    int fd;
    pthread_mutex_t lock;
    char path[64];
    char name[64];
    unsigned char serial[8];
    unsigned short app_id;
    unsigned short ctn_id;
    int app_open;
    int ctn_open;
    int user_logged;
    int admin_logged;
    int dev_authed;
    char user_pin[17];
    DEVINFO info;
} DEV_CTX;

typedef struct app_ctx {
    DEV_CTX *dev;
    unsigned short id;
    char name[64];
} APP_CTX;

typedef struct ctn_ctx {
    APP_CTX *app;
    unsigned short file_id;
    unsigned short key_file;
    unsigned short type;
    unsigned char rsa_mod[256];
    unsigned long rsa_bits;
    unsigned char ecc_priv[32];
    int ecc_priv_valid;
    ECCPUBLICKEYBLOB ecc_pub_soft;
    RSAPRIVATEKEYBLOB *rsa_priv_soft;
    char name[64];
} CTN_CTX;

static void ctn_clear_ecc(CTN_CTX *c)
{
    c->ecc_priv_valid = 0;
    memset(c->ecc_priv, 0, sizeof(c->ecc_priv));
    memset(&c->ecc_pub_soft, 0, sizeof(c->ecc_pub_soft));
}

static void ctn_clear_rsa(CTN_CTX *c)
{
    free(c->rsa_priv_soft);
    c->rsa_priv_soft = NULL;
    c->rsa_bits = 0;
    memset(c->rsa_mod, 0, sizeof(c->rsa_mod));
}

typedef struct key_ctx {
    DEV_CTX *dev;
    unsigned long alg;
    unsigned char key[32];
    unsigned long keylen;
    int mac;
} KEY_CTX;

static unsigned long be32(const unsigned char *p)
{
    return ((unsigned long)p[0] << 24) | ((unsigned long)p[1] << 16) |
           ((unsigned long)p[2] << 8) | p[3];
}

static void put_be32(unsigned char *p, unsigned long v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

static ULONG raw_rsa(const BYTE *mod, const BYTE *exp, ULONG bits,
                     BYTE *in, ULONG len, BYTE *out, ULONG *outlen);
static ULONG write_selected(DEV_CTX *d, const BYTE *data, ULONG len);
static void rev_words32(const unsigned char in[32], unsigned char out[32]);
static ULONG fci_size(const unsigned char *buf, unsigned long len, ULONG *size);
static ULONG delete_ef(DEV_CTX *d, unsigned short file);
static ULONG pin_verify(DEV_CTX *d, unsigned short app_id, ULONG type,
                        const char *pin, ULONG *retry);
static void des_ecb_enc(const unsigned char *in, unsigned char *out,
                        long len, const unsigned char *key);
static void des_ecb_dec(const unsigned char *in, unsigned char *out,
                        long len, const unsigned char *key);
static int sm2_decrypt_std(const unsigned char priv[32],
                           const ECCCIPHERBLOB *c,
                           unsigned char *out, ULONG *outlen);
static int sym_decrypt_std(ULONG alg, const unsigned char key[16],
                           const unsigned char *in, ULONG inlen,
                           unsigned char *out, ULONG *outlen);
static int ecc_priv_matches(const unsigned char priv[32],
                            const ECCPUBLICKEYBLOB *pub);
static void ctrl_key(DEV_CTX *d, unsigned char out[16]);
static void tdes_ecb(const unsigned char *in, unsigned char *out, long len,
                     const unsigned char key[16], int enc);
static void des_cbc_mac(const unsigned char *data, unsigned long len,
                        const unsigned char key[8],
                        const unsigned char iv[8], unsigned char out[8]);
static int sm2_sign_digest(const unsigned char priv[32],
                           const unsigned char digest[32],
                           unsigned char r_out[32], unsigned char s_out[32]);
static void rev_words32(const unsigned char in[32], unsigned char out[32]);
static int sm2_verify_digest(const ECCPUBLICKEYBLOB *pub,
                             const unsigned char digest[32],
                             const unsigned char r_in[32],
                             const unsigned char s_in[32]);

static int sg_xfer(int fd, int write, const void *buf, int len, void *out)
{
    unsigned char cdb[16];
    unsigned char sb[32];
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
    io.timeout = 3000;
    io.sbp = sb;
    if (ioctl(fd, SG_IO, &io) < 0)
        return -errno;
    if (io.status || io.host_status || io.driver_status)
        return -EIO;
    return 0;
}

static int do_handshake(int fd)
{
    unsigned char r[512], w[512];
    static const unsigned char chal[8] =
        {0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44};

    memset(r, 0, sizeof(r));
    if (sg_xfer(fd, 0, NULL, 512, r) < 0)
        return -1;
    memcpy(w, r, sizeof(w));
    memcpy(w, "checking", 8);
    memcpy(w + 8, chal, 8);
    if (sg_xfer(fd, 1, w, 512, NULL) < 0)
        return -1;
    memset(r, 0, sizeof(r));
    if (sg_xfer(fd, 0, NULL, 512, r) < 0)
        return -1;
    if (memcmp(r, "checking", 8) != 0)
        return -1;
    for (int i = 0; i < 8; i++)
        if (r[8 + i] != (unsigned char)~chal[i])
            return -1;
    return 0;
}

/* Send one APDU.  On success returns SAR_OK and stores response data
 * (without the 2-byte SW) in out/outlen. */
static ULONG apdu_ext(DEV_CTX *d, const unsigned char *cmd, unsigned long clen,
                      unsigned long extra, unsigned char *out,
                      unsigned long *outlen)
{
    unsigned char req[512], resp[512];
    unsigned long total, dlen;
    unsigned short sw;

    if (clen + extra > 0x1f0)
        return SAR_INVALIDPARAMERR;
    memset(req, 0, sizeof(req));
    memcpy(req, "DEMO", 4);
    put_be32(req + 4, clen + extra);
    req[12] = 0x12; req[13] = 0x34; req[14] = 0x56; req[15] = 0x78;
    if (cmd[0] == 0x80 && (cmd[1] == 0x5b || cmd[1] == 0xae || cmd[1] == 0xb4)) {
        req[8] = 0xab; req[9] = 0xcd; req[10] = 0x56; req[11] = 0x78;
    }
    memcpy(req + 16, cmd, clen);

    if (sg_xfer(d->fd, 1, req, 512, NULL) < 0)
        return SAR_FAIL;
    memset(resp, 0, sizeof(resp));
    if (sg_xfer(d->fd, 0, NULL, 512, resp) < 0)
        return SAR_FAIL;
    if (memcmp(resp, "DEMO", 4) != 0)
        return SAR_FAIL;
    total = be32(resp + 4);
    if (total < 2 || total > 0x1f0)
        return SAR_FAIL;
    int status_first = (cmd[0] == 0x00 && cmd[1] == 0x82) ||
                       (cmd[0] == 0x80 &&
                        (cmd[1] == 0x5b || cmd[1] == 0xae || cmd[1] == 0xb4));
    if (status_first) {
        sw = (unsigned short)((resp[16] << 8) | resp[17]);
        dlen = be32(resp + 20);
        if (dlen > 0x1f0)
            dlen = 0;
    } else {
        sw = (unsigned short)((resp[16 + total - 2] << 8) | resp[16 + total - 1]);
        dlen = total - 2;
    }
    if (getenv("SKF_DEBUG"))
        fprintf(stderr, "apdu sw=%04x cmd=%02x%02x dlen=%lu\n",
                sw, cmd[0], cmd[1], dlen);
    if (sw != 0x9000) {
        if (sw == 0x6a82 || sw == 0x6a83)
            return SAR_FILE_NOT_EXIST;
        if (sw == 0x6a86 || sw == 0x6a84 || sw == 0x6a89 || sw == 0x6d00)
            return SAR_INVALIDPARAMERR;
        if (sw == 0x6982)
            return SAR_USER_NOT_LOGGED_IN;
        if (sw == 0x6983)
            return SAR_PIN_LOCKED;
        if ((sw & 0xfff0) == 0x63c0) {
            if (outlen)
                *outlen = sw & 0xf;
            return SAR_PIN_INCORRECT;
        }
        if (sw == 0x6f01)
            return SAR_INVALIDPARAMERR;
        return SAR_UNKNOWNERR;
    }
    if (out && outlen) {
        if (dlen > *outlen)
            dlen = *outlen;
        memcpy(out, resp + (status_first ? 24 : 16), dlen);
    }
    if (outlen)
        *outlen = dlen;
    return SAR_OK;
}

static ULONG apdu(DEV_CTX *d, const unsigned char *cmd, unsigned long clen,
                  unsigned char *out, unsigned long *outlen)
{
    return apdu_ext(d, cmd, clen, 0, out, outlen);
}

static ULONG select_file(DEV_CTX *d, unsigned short file, unsigned char p1)
{
    unsigned char cmd[10];
    cmd[0] = 0x00; cmd[1] = 0xa4; cmd[2] = p1; cmd[3] = 0x00;
    cmd[4] = 0x00; cmd[5] = 0x00; cmd[6] = 0x00; cmd[7] = 0x02;
    cmd[8] = (unsigned char)(file >> 8);
    cmd[9] = (unsigned char)file;
    ULONG r = apdu(d, cmd, sizeof(cmd), NULL, NULL);
    if (getenv("SKF_DEBUG"))
        fprintf(stderr, "select %04x p1=%u rc=%lx\n", file, p1, (unsigned long)r);
    return r;
}

static ULONG select_file_data(DEV_CTX *d, unsigned short file, unsigned char p1,
                              unsigned char *buf, unsigned long *len)
{
    unsigned char cmd[10];
    cmd[0] = 0x00; cmd[1] = 0xa4; cmd[2] = p1; cmd[3] = 0x00;
    cmd[4] = 0x00; cmd[5] = 0x00; cmd[6] = 0x00; cmd[7] = 0x02;
    cmd[8] = (unsigned char)(file >> 8);
    cmd[9] = (unsigned char)file;
    return apdu(d, cmd, sizeof(cmd), buf, len);
}

static ULONG select_app(DEV_CTX *d, unsigned short app_id)
{
    ULONG rc = select_file(d, 0x3f00, 0);
    if (rc != SAR_OK)
        return rc;
    return select_file(d, app_id, 1);
}

static ULONG read_file(DEV_CTX *d, unsigned short file, unsigned long off,
                       unsigned char *buf, unsigned long *len)
{
    unsigned char cmd[512];
    unsigned char tmp[512];
    unsigned long want = *len, total = 0;
    ULONG rc;

    rc = select_file(d, file, 2);
    if (rc != SAR_OK)
        return rc;
    while (total < want) {
        unsigned long chunk = want - total;
        unsigned long got;
        unsigned long pos = off + total;
        if (chunk > 0x1c1)
            chunk = 0x1c1;
        memset(cmd, 0, sizeof(cmd));
        cmd[0] = 0x00; cmd[1] = 0xb0;
        cmd[2] = (unsigned char)(pos >> 8);
        cmd[3] = (unsigned char)pos;
        put_be32(cmd + 4, chunk);
        got = chunk;
        /* The vendor frame carries a read buffer after the 8-byte APDU. */
        rc = apdu(d, cmd, 8 + chunk, tmp, &got);
        if (getenv("SKF_DEBUG"))
            fprintf(stderr, "read_file %04x off=%lu rc=%lx len=%lu\n",
                    file, pos, (unsigned long)rc, got);
        if (rc != SAR_OK) {
            /* Reading at/past EOF makes the device return an error.  If
             * data was already read, return it as a short file. */
            if (total > 0)
                rc = SAR_OK;
            break;
        }
        if (got > chunk)
            got = chunk;
        if (got == 0)
            break;
        memcpy(buf + total, tmp, got);
        total += got;
        if (got < chunk)
            break;
    }
    if (rc == SAR_OK)
        *len = total;
    return rc;
}

static int vendor_is_ccore(const char *sg)
{
    char path[256], buf[128];
    FILE *f;
    snprintf(path, sizeof(path),
             "/sys/class/scsi_generic/%s/device/vendor", sg);
    f = fopen(path, "r");
    if (!f)
        return 0;
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    return strstr(buf, "C*CORE") != NULL || strstr(buf, "CCore") != NULL ||
           strstr(buf, "C*Core") != NULL;
}

static int find_sg(char *out, size_t outlen, const char *hint)
{
    glob_t g;
    int found = 0;

    if (hint && strstr(hint, "/dev/sg"))
        snprintf(out, outlen, "%s", hint);
    else if (hint && strstr(hint, "sg")) {
        const char *p = strstr(hint, "sg");
        snprintf(out, outlen, "/dev/%.8s", p);
    } else {
        /* sdd1/sdd -> find the matching scsi_generic node */
        const char *base = hint ? hint : "";
        char sys[256];
        snprintf(sys, sizeof(sys), "/sys/block/%.16s/device/scsi_generic",
                 base);
        DIR *dir = opendir(sys);
        if (dir) {
            struct dirent *de;
            while ((de = readdir(dir))) {
                if (strncmp(de->d_name, "sg", 2) == 0) {
                    snprintf(out, outlen, "/dev/%s", de->d_name);
                    closedir(dir);
                    return 0;
                }
            }
            closedir(dir);
        }
    }

    if (out[0] && access(out, R_OK | W_OK) == 0)
        return 0;

    if (glob("/sys/class/scsi_generic/sg*", 0, NULL, &g) == 0) {
        for (size_t i = 0; i < g.gl_pathc; i++) {
            const char *sg = strrchr(g.gl_pathv[i], '/');
            if (!sg)
                continue;
            sg++;
            if (!vendor_is_ccore(sg))
                continue;
            snprintf(out, outlen, "/dev/%s", sg);
            found = 1;
            break;
        }
        globfree(&g);
    }
    if (!found) {
        for (int i = 0; i < 32; i++) {
            snprintf(out, outlen, "/dev/sg%d", i);
            if (access(out, R_OK | W_OK) == 0) {
                found = 1;
                break;
            }
        }
    }
    return found ? 0 : -1;
}

static void trim_label(char *s)
{
    size_t n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\0'))
        s[--n] = '\0';
}

static ULONG get_devinfo(DEV_CTX *d, DEVINFO *info)
{
    unsigned char cmd[8];
    unsigned char buf[512];
    unsigned long len;
    ULONG rc;
    unsigned long total = 0, free = 0;

    memset(info, 0, sizeof(*info));
    strcpy(info->Manufacturer, "C*CORE");
    strcpy(info->Issuer, "XXXX");
    strcpy(info->Label, "UKEY");
    info->Version.major = 1; info->Version.minor = 0;
    info->HWVersion.major = 1; info->HWVersion.minor = 0;
    info->FirmwareVersion.major = 1; info->FirmwareVersion.minor = 24;
    info->AlgSymCap = 0x80000713;
    info->AlgAsymCap = 0x00030700;
    info->AlgHashCap = 0x00000007;
    info->DevAuthAlgId = 0x101;
    info->MaxECCBufferSize = 256;
    info->MaxBufferSize = 59360;

    /* 80 aa 01 00: packed device information */
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0xaa; cmd[2] = 0x01;
    len = sizeof(buf);
    rc = apdu(d, cmd, sizeof(cmd), buf, &len);
    if (rc == SAR_OK && len >= 0x64) {
        for (unsigned long i = 0; i + 6 < len; i++) {
            if (memcmp(buf + i, "UKEY", 4) == 0) {
                strncpy(info->Label, (char *)(buf + i), 31);
                info->Label[31] = 0;
                trim_label(info->Label);
                break;
            }
        }
        for (unsigned long i = 0; i + 4 < len; i++) {
            if (buf[i] == '1' && buf[i+1] == '.' &&
                isdigit(buf[i+2]) && isdigit(buf[i+3])) {
                info->FirmwareVersion.major = 1;
                info->FirmwareVersion.minor =
                    (unsigned char)((buf[i+2]-'0')*10 + (buf[i+3]-'0'));
                break;
            }
        }
        if (len >= 0x64)
            memcpy(d->serial, buf + 0x5c, 8);
    }

    /* 80 b9: 16-byte serial (first 8 bytes are packed BCD) */
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0xb9;
    put_be32(cmd + 4, 0x10);
    len = sizeof(buf);
    rc = apdu(d, cmd, sizeof(cmd), buf, &len);
    if (rc == SAR_OK && len >= 8)
        memcpy(d->serial, buf, 8);
    snprintf(info->SerialNumber, sizeof(info->SerialNumber),
             "%02X%02X%02X%02X%02X%02X%02X%02X",
             d->serial[0], d->serial[1], d->serial[2], d->serial[3],
             d->serial[4], d->serial[5], d->serial[6], d->serial[7]);

    /* 80 b7: total / free space (two BE32 values) */
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0xb7;
    put_be32(cmd + 4, 0x08);
    len = sizeof(buf);
    rc = apdu(d, cmd, sizeof(cmd), buf, &len);
    if (rc == SAR_OK && len >= 8) {
        total = be32(buf);
        free = be32(buf + 4);
        info->TotalSpace = total;
        info->FreeSpace = free;
    }

    /* The writable label lives in EF 3F02; read it back if available. */
    {
        unsigned char label[32];
        unsigned long llen = sizeof(label);
        if (select_file(d, 0x3f00, 0) == SAR_OK &&
            read_file(d, 0x3f02, 0, label, &llen) == SAR_OK && llen > 0) {
            unsigned long n = llen > 31 ? 31 : llen;
            while (n && (label[n - 1] == 0x20 || label[n - 1] == 0))
                n--;
            memcpy(info->Label, label, n);
            info->Label[n] = 0;
        }
    }

    d->info = *info;
    return SAR_OK;
}

/* ---------- device API ---------- */

static int enum_add(char *list, size_t cap, size_t *off, const char *name)
{
    int n = snprintf(list + *off, cap - *off, "%s", name);
    if (n < 0 || (size_t)n >= cap - *off)
        return -1;
    *off += (size_t)n + 1;
    return 0;
}

static int enum_add_block(const char *sg, char *list, size_t cap, size_t *off)
{
    char path[256];
    int added = 0;
    snprintf(path, sizeof(path),
             "/sys/class/scsi_generic/%s/device/block", sg);
    DIR *d = opendir(path);
    if (!d)
        return 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.')
            continue;
        char base[64];
        snprintf(base, sizeof(base), "%s", de->d_name);
        glob_t g;
        char pat[256];
        snprintf(pat, sizeof(pat), "/sys/block/%s/%s*", base, base);
        if (glob(pat, 0, NULL, &g) == 0) {
            for (size_t i = 0; i < g.gl_pathc; i++) {
                const char *p = strrchr(g.gl_pathv[i], '/');
                if (!p)
                    continue;
                p++;
                if (strcmp(p, base) != 0) {
                    if (enum_add(list, cap, off, p) == 0)
                        added = 1;
                }
            }
            globfree(&g);
        }
        if (enum_add(list, cap, off, base) == 0)
            added = 1;
    }
    closedir(d);
    return added;
}

ULONG SKF_EnumDev(BOOL present, LPSTR names, ULONG *size)
{
    char list[256];
    glob_t g;
    size_t off = 0;

    (void)present;
    if (!size)
        return SAR_INVALIDPARAMERR;
    list[0] = 0;
    if (glob("/sys/class/scsi_generic/sg*", 0, NULL, &g) == 0) {
        for (size_t i = 0; i < g.gl_pathc; i++) {
            const char *sg = strrchr(g.gl_pathv[i], '/');
            if (!sg || !vendor_is_ccore(sg + 1))
                continue;
            if (!enum_add_block(sg + 1, list, sizeof(list), &off)) {
                char dev[32];
                snprintf(dev, sizeof(dev), "/dev/%s", sg + 1);
                enum_add(list, sizeof(list), &off, dev);
            }
        }
        globfree(&g);
    }
    if (off == 0) {
        for (int i = 0; i < 32; i++) {
            char p[32];
            snprintf(p, sizeof(p), "/dev/sg%d", i);
            if (access(p, R_OK | W_OK) == 0 && vendor_is_ccore(p + 5)) {
                enum_add(list, sizeof(list), &off, p);
                break;
            }
        }
    }
    if (off == 0)
        return SAR_FAIL;
    if (off < sizeof(list))
        list[off++] = 0;   /* match vendor list terminator */
    if (!names) {
        *size = (ULONG)off;
        return SAR_OK;
    }
    if (*size < off)
        return SAR_INVALIDPARAMERR;
    memcpy(names, list, off);
    *size = (ULONG)off;
    return SAR_OK;
}

ULONG SKF_ConnectDev(LPSTR name, DEVHANDLE *phDev)
{
    char path[64] = {0};
    DEV_CTX *d;
    if (!name || !phDev)
        return SAR_INVALIDPARAMERR;
    if (find_sg(path, sizeof(path), name) != 0)
        return SAR_FAIL;
    int fd = open(path, O_RDWR);
    if (fd < 0)
        return SAR_FAIL;
    if (do_handshake(fd) != 0) {
        close(fd);
        return SAR_FAIL;
    }
    d = calloc(1, sizeof(*d));
    if (!d) {
        close(fd);
        return SAR_FAIL;
    }
    d->fd = fd;
    pthread_mutex_init(&d->lock, NULL);
    snprintf(d->path, sizeof(d->path), "%s", path);
    snprintf(d->name, sizeof(d->name), "%s", name);
    d->app_id = 0x2000;
    d->ctn_id = 0x1101;
    get_devinfo(d, &d->info);
    *phDev = (DEVHANDLE)d;
    return SAR_OK;
}

ULONG SKF_DisConnectDev(DEVHANDLE hDev)
{
    DEV_CTX *d = (DEV_CTX *)hDev;
    if (!d)
        return SAR_INVALIDHANDLEERR;
    if (d->fd >= 0)
        close(d->fd);
    pthread_mutex_destroy(&d->lock);
    free(d);
    return SAR_OK;
}

ULONG SKF_GetDevState(LPSTR name, ULONG *state)
{
    char path[64];
    if (!name || !state)
        return SAR_INVALIDPARAMERR;
    if (find_sg(path, sizeof(path), name) != 0)
        return SAR_FAIL;
    *state = 1;
    return SAR_OK;
}

ULONG SKF_GetDevInfo(DEVHANDLE hDev, DEVINFO *info)
{
    DEV_CTX *d = (DEV_CTX *)hDev;
    if (!d || !info)
        return SAR_INVALIDHANDLEERR;
    return get_devinfo(d, info);
}

ULONG SKF_GenRandom(DEVHANDLE hDev, BYTE *buf, ULONG len)
{
    DEV_CTX *d = (DEV_CTX *)hDev;
    unsigned char cmd[8];
    unsigned long done = 0;

    if (!d || (!buf && len))
        return SAR_INVALIDPARAMERR;
    while (done < len) {
        unsigned long chunk = len - done;
        unsigned long outlen;
        if (chunk > 0x1c1)
            chunk = 0x1c1;
        unsigned char rcmd[512];
        memset(rcmd, 0, sizeof(rcmd));
        rcmd[0] = 0x00; rcmd[1] = 0x84;
        put_be32(rcmd + 4, chunk);
        outlen = chunk;
        ULONG rc = apdu(d, rcmd, 8 + chunk, buf + done, &outlen);
        if (rc != SAR_OK)
            return rc;
        if (outlen == 0)
            return SAR_FAIL;
        done += outlen;
    }
    return SAR_OK;
}

ULONG SKF_LockDev(DEVHANDLE hDev, ULONG timeout)
{
    DEV_CTX *d = (DEV_CTX *)hDev;
    (void)timeout;
    if (!d)
        return SAR_INVALIDHANDLEERR;
    return pthread_mutex_lock(&d->lock) == 0 ? SAR_OK : SAR_FAIL;
}

ULONG SKF_UnlockDev(DEVHANDLE hDev)
{
    DEV_CTX *d = (DEV_CTX *)hDev;
    if (!d)
        return SAR_INVALIDHANDLEERR;
    return pthread_mutex_unlock(&d->lock) == 0 ? SAR_OK : SAR_FAIL;
}

ULONG SKF_Transmit(DEVHANDLE hDev, BYTE *cmd, ULONG clen, BYTE *out, ULONG *olen)
{
    (void)hDev; (void)cmd; (void)clen; (void)out; (void)olen;
    return SAR_NOTSUPPORTYETERR;
}

ULONG SKF_SetLabel(DEVHANDLE hDev, LPSTR label)
{
    DEV_CTX *d = (DEV_CTX *)hDev;
    unsigned char buf[33];
    size_t n;
    ULONG rc;
    if (!d || !label)
        return SAR_INVALIDPARAMERR;
    n = strlen((const char *)label);
    if (n > 31)
        n = 31;
    memset(buf, 0x20, 32);
    memcpy(buf, label, n);
    buf[n] = 0;
    buf[32] = 0;
    rc = select_file(d, 0x3f00, 0);
    if (rc != SAR_OK)
        return rc;
    rc = select_file(d, 0x3f02, 2);
    if (rc != SAR_OK)
        return rc;
    return write_selected(d, buf, sizeof(buf));
}

ULONG SKF_DevAuth(DEVHANDLE hDev, BYTE *auth, ULONG len)
{
    DEV_CTX *d = (DEV_CTX *)hDev;
    unsigned char cmd[24];
    unsigned long n = 0;
    if (!d || !auth || len != 16)
        return SAR_INVALIDPARAMERR;
    ULONG sel = select_file(d, 0x3f00, 0);
    if (sel != SAR_OK)
        return sel;
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x00; cmd[1] = 0x82;
    put_be32(cmd + 4, 0x10);
    memcpy(cmd + 8, auth, 16);
    ULONG rc = apdu_ext(d, cmd, sizeof(cmd), 0, NULL, &n);
    if (rc == SAR_OK)
        d->dev_authed = 1;
    /* The vendor maps the device-auth lock SW 6983 to SAR_UNKNOWNERR. */
    if (rc == SAR_PIN_LOCKED)
        rc = SAR_UNKNOWNERR;
    return rc;
}

ULONG SKF_ChangeDevAuthKey(DEVHANDLE hDev, BYTE *key, ULONG keylen)
{
    DEV_CTX *d = (DEV_CTX *)hDev;
    unsigned char ctrl[16], obj[20], plain[32], cipher[32];
    unsigned char macin[40], mac[8], final[8], iv[8], cmd[44];
    ULONG rc;
    if (!d)
        return SAR_INVALIDHANDLEERR;
    if (!key)
        return SAR_INVALIDPARAMERR;
    /* An empty key would delete the device auth key; reject it. */
    if (keylen == 0 || keylen > 16)
        return SAR_INDATALENERR;
    memset(obj, 0, sizeof(obj));
    obj[0] = 0x02;
    obj[1] = 0x01;
    obj[2] = 0x10;
    memcpy(obj + 4, key, keylen);
    memset(plain, 0, sizeof(plain));
    put_be32(plain, 0x14);
    memcpy(plain + 4, obj, sizeof(obj));
    plain[24] = 0x80;
    ctrl_key(d, ctrl);
    tdes_ecb(plain, cipher, 32, ctrl, DES_ENCRYPT);
    memcpy(macin, cmd, 8);
    macin[0] = 0x84; macin[1] = 0xa5; macin[2] = 0x01; macin[3] = 0x00;
    put_be32(macin + 4, 0x20);
    memcpy(macin + 8, cipher, 32);
    rc = SKF_GenRandom(hDev, iv, sizeof(iv));
    if (rc != SAR_OK)
        return rc;
    des_cbc_mac(macin, sizeof(macin), ctrl, iv, mac);
    des_ecb_dec(mac, final, 8, ctrl + 8);
    des_ecb_enc(final, final, 8, ctrl);
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x84; cmd[1] = 0xa5; cmd[2] = 0x01; cmd[3] = 0x00;
    put_be32(cmd + 4, 0x24);
    memcpy(cmd + 8, cipher, 32);
    memcpy(cmd + 40, final, 4);
    rc = apdu(d, cmd, sizeof(cmd), NULL, NULL);
    /* The vendor maps SW 6988 (not authenticated) to SAR_UNKNOWNERR. */
    if (rc == SAR_USER_NOT_LOGGED_IN)
        rc = SAR_UNKNOWNERR;
    return rc;
}

static pthread_mutex_t g_event_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile sig_atomic_t g_event_cancel;

static int block_is_ccore(const char *name)
{
    char base[64], sys[256];
    struct dirent *de;
    DIR *dir;
    int ok = 0;
    size_t n;

    snprintf(base, sizeof(base), "%s", name);
    n = strlen(base);
    /* sdd1 -> sdd; the partition's sysfs "device" may not exist. */
    while (n && isdigit((unsigned char)base[n - 1]))
        base[--n] = 0;
    snprintf(sys, sizeof(sys),
             "/sys/class/block/%s/device/scsi_generic", base);
    dir = opendir(sys);
    if (!dir)
        return 0;
    while ((de = readdir(dir))) {
        if (strncmp(de->d_name, "sg", 2) == 0 &&
            vendor_is_ccore(de->d_name)) {
            ok = 1;
            break;
        }
    }
    closedir(dir);
    return ok;
}

static int dev_name_present(const char *name)
{
    char path[80];
    snprintf(path, sizeof(path), "/dev/%.64s", name);
    return access(path, F_OK) == 0;
}

static size_t event_snapshot(char *list, size_t cap)
{
    ULONG need = 0, got;
    char *tmp;

    list[0] = 0;
    if (SKF_EnumDev(TRUE, NULL, &need) != SAR_OK || need == 0)
        return 0;
    if (need > cap)
        need = (ULONG)cap;
    tmp = malloc(need);
    if (!tmp)
        return 0;
    got = need;
    if (SKF_EnumDev(TRUE, tmp, &got) != SAR_OK) {
        free(tmp);
        return 0;
    }
    if (got > cap)
        got = (ULONG)cap;
    memcpy(list, tmp, got);
    free(tmp);
    return got;
}

static int event_list_has(const char *list, size_t len, const char *name)
{
    size_t off = 0;
    while (off < len && list[off]) {
        if (strcmp(list + off, name) == 0)
            return 1;
        off += strlen(list + off) + 1;
    }
    return 0;
}

ULONG SKF_CancelWaitForDevEvent(void)
{
    g_event_cancel = 1;
    return SAR_OK;
}

ULONG SKF_WaitForDevEvent(LPSTR name, ULONG *namelen, ULONG *evt)
{
    char list[256];
    size_t listlen, off;
    ULONG cap;

    if (!name || !namelen || !evt)
        return SAR_INVALIDPARAMERR;
    cap = *namelen;
    if (cap == 0)
        return SAR_INVALIDPARAMERR;

    pthread_mutex_lock(&g_event_lock);
    g_event_cancel = 0;
    listlen = event_snapshot(list, sizeof(list));

    for (;;) {
        DIR *dir;
        struct dirent *de;

        if (g_event_cancel) {
            pthread_mutex_unlock(&g_event_lock);
            return SAR_NOT_EVENTERR;
        }

        dir = opendir("/dev");
        if (dir) {
            while ((de = readdir(dir))) {
                if (strncmp(de->d_name, "sd", 2) != 0)
                    continue;
                if (event_list_has(list, listlen, de->d_name))
                    continue;
                if (!block_is_ccore(de->d_name))
                    continue;
                if (strlen(de->d_name) + 1 > cap) {
                    closedir(dir);
                    pthread_mutex_unlock(&g_event_lock);
                    return SAR_INVALIDPARAMERR;
                }
                strcpy(name, de->d_name);
                *namelen = (ULONG)strlen(de->d_name) + 1;
                *evt = 1;
                closedir(dir);
                pthread_mutex_unlock(&g_event_lock);
                return SAR_OK;
            }
            closedir(dir);
        }

        for (off = 0; off < listlen && list[off];
             off += strlen(list + off) + 1) {
            if (!dev_name_present(list + off)) {
                if (strlen(list + off) + 1 > cap) {
                    pthread_mutex_unlock(&g_event_lock);
                    return SAR_INVALIDPARAMERR;
                }
                strcpy(name, list + off);
                *namelen = (ULONG)strlen(list + off) + 1;
                *evt = 2;
                pthread_mutex_unlock(&g_event_lock);
                return SAR_OK;
            }
        }

        usleep(50000);
    }
}

/* ---------- application ---------- */

static ULONG app_list(DEV_CTX *d, char *out, size_t *outlen)
{
    unsigned char buf[0x100];
    unsigned long len = sizeof(buf);
    ULONG rc;
    size_t off = 0;

    out[off++] = 'D'; out[off++] = 'E'; out[off++] = 'F'; out[off++] = 'A';
    out[off++] = 'U'; out[off++] = 'L'; out[off++] = 'T'; out[off++] = 0;
    rc = select_file(d, 0x3f00, 0);
    if (rc != SAR_OK) {
        *outlen = off;
        return SAR_OK;
    }
    len = sizeof(buf);
    rc = read_file(d, 0x3f03, 0, buf, &len);
    if (rc != SAR_OK || len < 0x14) {
        *outlen = off;
        return SAR_OK;
    }
    unsigned count = (unsigned)buf[0x12] | ((unsigned)buf[0x13] << 8);
    if (count > 32)
        count = 32;
    for (unsigned i = 0; i < count; i++) {
        unsigned char *rec = buf + ((i == 0) ? 0 : (0x14 + (i - 1) * 0x14));
        if (rec + 0x14 > buf + len)
            break;
        if (!rec[0])
            continue;
        size_t n = strnlen((char *)rec, 16);
        if (n == 0 || n > 16)
            continue;
        if (off + n + 1 >= 512)
            break;
        memcpy(out + off, rec, n);
        off += n;
        out[off++] = 0;
    }
    *outlen = off;
    return SAR_OK;
}

ULONG SKF_EnumApplication(DEVHANDLE hDev, LPSTR names, ULONG *size)
{
    DEV_CTX *d = (DEV_CTX *)hDev;
    char list[512];
    size_t len;
    if (!d || !size)
        return SAR_INVALIDHANDLEERR;
    ULONG rc = app_list(d, list, &len);
    if (rc != SAR_OK)
        return rc;
    if (!names) {
        *size = (ULONG)len;
        return SAR_OK;
    }
    if (*size < len)
        return SAR_INVALIDPARAMERR;
    memcpy(names, list, len);
    *size = (ULONG)len;
    return SAR_OK;
}

static ULONG find_app(DEV_CTX *d, const char *name, unsigned short *id)
{
    unsigned char buf[0x100];
    unsigned long len = sizeof(buf);
    ULONG rc;

    if (strcmp(name, "DEFAULT") == 0) {
        *id = 0x2000;
        return SAR_OK;
    }
    rc = select_file(d, 0x3f00, 0);
    if (rc != SAR_OK)
        return rc;
    len = sizeof(buf);
    rc = read_file(d, 0x3f03, 0, buf, &len);
    if (rc != SAR_OK || len < 0x14)
        return SAR_APPLICATION_NOT_EXISTS;
    unsigned count = (unsigned)buf[0x12] | ((unsigned)buf[0x13] << 8);
    if (count > 32)
        count = 32;
    for (unsigned i = 0; i < count; i++) {
        unsigned char *rec = buf + ((i == 0) ? 0 : (0x14 + (i - 1) * 0x14));
        if (rec + 0x14 > buf + len)
            break;
        if (strncmp((char *)rec, name, 16) == 0) {
            *id = (unsigned short)(rec[0x10] | (rec[0x11] << 8));
            return SAR_OK;
        }
    }
    return SAR_APPLICATION_NOT_EXISTS;
}

ULONG SKF_OpenApplication(DEVHANDLE hDev, LPSTR name, HAPPLICATION *phApp)
{
    DEV_CTX *d = (DEV_CTX *)hDev;
    unsigned short id;
    ULONG rc;
    if (!d || !name || !phApp)
        return SAR_INVALIDPARAMERR;
    rc = find_app(d, name, &id);
    if (rc != SAR_OK)
        return rc;
    rc = select_file(d, id, 0);
    if (rc != SAR_OK)
        return rc;
    APP_CTX *a = calloc(1, sizeof(*a));
    if (!a)
        return SAR_FAIL;
    a->dev = d;
    a->id = id;
    snprintf(a->name, sizeof(a->name), "%s", name);
    d->app_id = id;
    d->app_open = 1;
    *phApp = (HAPPLICATION)a;
    return SAR_OK;
}

ULONG SKF_CloseApplication(HAPPLICATION hApp)
{
    APP_CTX *a = (APP_CTX *)hApp;
    if (!a)
        return SAR_INVALIDHANDLEERR;
    if (a->dev) {
        a->dev->app_open = 0;
        a->dev->user_logged = 0;
        a->dev->admin_logged = 0;
    }
    free(a);
    return SAR_OK;
}

static void ctrl_key(DEV_CTX *d, unsigned char out[16])
{
    unsigned char in[12];
    memset(in, 0, sizeof(in));
    memcpy(in, d->serial, 8);
    EVP_Digest(in, sizeof(in), out, NULL, EVP_md5(), NULL);
}

static void des_ecb_dec(const unsigned char *in, unsigned char *out,
                        long len, const unsigned char *key)
{
    DES_key_schedule ks;
    DES_cblock k;
    memcpy(k, key, 8);
    DES_set_key_unchecked(&k, &ks);
    for (long off = 0; off + 8 <= len; off += 8) {
        DES_cblock inb, outb;
        memcpy(inb, in + off, 8);
        DES_ecb_encrypt(&inb, &outb, &ks, DES_DECRYPT);
        memcpy(out + off, outb, 8);
    }
}

static void tdes_ecb(const unsigned char *in, unsigned char *out, long len,
                     const unsigned char key[16], int enc)
{
    DES_key_schedule ks1, ks2, ks3;
    DES_cblock k1, k2, k3;
    memcpy(k1, key, 8);
    memcpy(k2, key + 8, 8);
    memcpy(k3, key, 8);
    DES_set_key_unchecked(&k1, &ks1);
    DES_set_key_unchecked(&k2, &ks2);
    DES_set_key_unchecked(&k3, &ks3);
    for (long off = 0; off + 8 <= len; off += 8)
        DES_ecb3_encrypt((const_DES_cblock *)(in + off),
                         (DES_cblock *)(out + off),
                         &ks1, &ks2, &ks3, enc);
}

static void des_cbc_mac(const unsigned char *data, unsigned long len,
                        const unsigned char key[8],
                        const unsigned char iv[8], unsigned char out[8])
{
    unsigned char buf[80];
    unsigned char enc[80];
    DES_key_schedule ks;
    DES_cblock k, v;
    unsigned long n = len;

    if (n + 8 > sizeof(buf))
        n = sizeof(buf) - 8;
    memcpy(buf, data, n);
    buf[n++] = 0x80;
    while (n & 7)
        buf[n++] = 0;
    memcpy(k, key, 8);
    memcpy(v, iv, 8);
    DES_set_key_unchecked(&k, &ks);
    DES_ncbc_encrypt(buf, enc, (long)n, &ks, &v, DES_ENCRYPT);
    memcpy(out, enc + n - 8, 8);
}

static ULONG write_key(DEV_CTX *d, unsigned int type,
                       const unsigned char obj[28], const unsigned char key[16])
{
    unsigned char plain[40], cipher[40], macin[48], macbuf[16];
    unsigned char mac[8], final[8], iv[8];
    unsigned char cmd[52];
    unsigned char k1[8];
    ULONG rc;

    memset(plain, 0, sizeof(plain));
    put_be32(plain, 0x1c);
    memcpy(plain + 4, obj, 28);
    plain[32] = 0x80;
    tdes_ecb(plain, cipher, 40, key, DES_ENCRYPT);

    memcpy(macin, cmd, 8); /* placeholder, filled below */
    macin[0] = 0x84; macin[1] = 0xa5; macin[2] = 0x02;
    macin[3] = (unsigned char)(type & 1);
    put_be32(macin + 4, 0x28);
    memcpy(macin + 8, cipher, 40);
    if (SKF_GenRandom((DEVHANDLE)d, iv, sizeof(iv)) != SAR_OK)
        memset(iv, 0, sizeof(iv));
    memcpy(k1, key, 8);
    des_cbc_mac(macin, sizeof(macin), k1, iv, mac);
    des_ecb_dec(mac, final, 8, key + 8);
    des_ecb_enc(final, final, 8, key);

    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x84; cmd[1] = 0xa5; cmd[2] = 0x02;
    cmd[3] = (unsigned char)(type & 1);
    put_be32(cmd + 4, 0x2c);
    memcpy(cmd + 8, cipher, 40);
    memcpy(cmd + 48, final, 4);
    rc = apdu(d, cmd, sizeof(cmd), NULL, NULL);
    return rc;
}

static ULONG read_app_list(DEV_CTX *d, unsigned char buf[256])
{
    unsigned long len = 256;
    ULONG rc = select_file(d, 0x3f00, 0);
    if (rc != SAR_OK)
        return rc;
    rc = read_file(d, 0x3f03, 0, buf, &len);
    if (rc != SAR_OK)
        return rc;
    if (len < 0x14)
        return SAR_FAIL;
    return SAR_OK;
}

static ULONG write_app_list(DEV_CTX *d, const unsigned char buf[256])
{
    ULONG rc = select_file(d, 0x3f00, 0);
    if (rc != SAR_OK)
        return rc;
    rc = select_file(d, 0x3f03, 2);
    if (rc != SAR_OK)
        return rc;
    return write_selected(d, buf, 256);
}

static unsigned app_count(const unsigned char *buf)
{
    unsigned n = (unsigned)buf[0x12] | ((unsigned)buf[0x13] << 8);
    if (n > 32)
        n = 32;
    return n;
}

static ULONG append_app_record(unsigned char *buf, const char *name,
                               unsigned short id)
{
    unsigned n = app_count(buf);
    if (n >= 32)
        return SAR_NO_ROOM;
    unsigned char *rec = buf + 0x14 * n;
    memset(rec, 0, 0x14);
    strncpy((char *)rec, name, 16);
    rec[0x10] = (unsigned char)id;
    rec[0x11] = (unsigned char)(id >> 8);
    buf[0x12] = (unsigned char)(n + 1);
    buf[0x13] = (unsigned char)((n + 1) >> 8);
    return SAR_OK;
}

static int app_id_used(const unsigned char *buf, unsigned short id)
{
    unsigned n = app_count(buf);
    for (unsigned i = 0; i < n; i++) {
        const unsigned char *rec = buf + 0x14 * i;
        unsigned short rid = (unsigned short)(rec[0x10] | ((unsigned)rec[0x11] << 8));
        if (rid == id)
            return 1;
    }
    return 0;
}

static ULONG create_ef_len(DEV_CTX *d, unsigned short file,
                           const unsigned char *attrs, unsigned long alen)
{
    unsigned char cmd[64];
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0xe0;
    cmd[2] = (unsigned char)(file >> 8);
    cmd[3] = (unsigned char)file;
    put_be32(cmd + 4, alen);
    memcpy(cmd + 8, attrs, alen);
    if (getenv("SKF_DEBUG")) {
        fprintf(stderr, "create_ef %04x alen=%lu attrs=", file, alen);
        for (unsigned long i = 0; i < alen; i++) fprintf(stderr, "%02x", attrs[i]);
        fprintf(stderr, "\n");
    }
    return apdu(d, cmd, 8 + alen, NULL, NULL);
}

static void rollback_app(DEV_CTX *d, unsigned short appid)
{
    unsigned char list[256];
    if (read_app_list(d, list) == SAR_OK) {
        unsigned n = app_count(list);
        for (unsigned i = 0; i < n; i++) {
            unsigned char *rec = list + 0x14 * i;
            unsigned short rid = (unsigned short)(rec[0x10] | ((unsigned)rec[0x11] << 8));
            if (rid == appid) {
                memmove(rec, rec + 0x14, (n - i - 1) * 0x14);
                memset(list + 0x14 * (n - 1), 0, sizeof(list) - 0x14 * (n - 1));
                n--;
                list[0x12] = (unsigned char)n;
                list[0x13] = (unsigned char)(n >> 8);
                break;
            }
        }
        write_app_list(d, list);
    }
    select_file(d, 0x3f00, 0);
    delete_ef(d, appid);
}

ULONG SKF_CreateApplication(DEVHANDLE hDev, LPSTR app, LPSTR adminpin,
                            ULONG adminlen, LPSTR userpin, ULONG userlen,
                            ULONG rights, HAPPLICATION *phApp)
{
    DEV_CTX *d = (DEV_CTX *)hDev;
    unsigned char list[256], ctrl[16], appkey[16];
    unsigned char obj[28];
    unsigned short appid = 0;
    static const unsigned char app_attr[24] =
        {0x38,0x0f,0x0f,0x0f,0x0f,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    static const unsigned char pin_attr[12] =
        {0xd8,0x0f,0x0f,0x0f,0x00,0x10,0x00,0x30,0x00,0x03,0x00,0x00};
    static const unsigned char ctn_attr[12] =
        {0x01,0x0f,0x0f,0x00,0x00,0x00,0x00,0x41,0x00,0x00,0x00,0x00};
    ULONG rc;

    (void)rights;
    if (!d || !app || !adminpin || !userpin || !phApp)
        return SAR_INVALIDPARAMERR;
    *phApp = NULL;
    if (!d->dev_authed)
        return SAR_USER_NOT_LOGGED_IN;
    if (strlen(app) > 15)
        return SAR_APPLICATION_NAME_INVALID;
    if (adminlen == 0)
        adminlen = (ULONG)strlen((const char *)adminpin);
    if (userlen == 0)
        userlen = (ULONG)strlen((const char *)userpin);
    if (adminlen > 16 || userlen > 16)
        return SAR_INVALIDPARAMERR;
    char apin[17], upin[17];
    memset(apin, 0, sizeof(apin));
    memset(upin, 0, sizeof(upin));
    memcpy(apin, adminpin, adminlen);
    memcpy(upin, userpin, userlen);

    rc = read_app_list(d, list);
    if (rc != SAR_OK)
        return rc;
    unsigned n = app_count(list);
    for (unsigned i = 0; i < n; i++) {
        if (strncmp((char *)(list + 0x14 * i), app, 16) == 0)
            return SAR_APPLICATION_EXISTS;
    }
    for (unsigned short cand = 0x3000; cand < 0xa000; cand += 0x1000) {
        if (!app_id_used(list, cand)) { appid = cand; break; }
    }
    if (!appid)
        return SAR_NO_ROOM;

    rc = append_app_record(list, app, appid);
    if (rc != SAR_OK)
        return rc;
    rc = write_app_list(d, list);
    if (rc != SAR_OK)
        return rc;

    rc = create_ef_len(d, appid, app_attr, sizeof(app_attr));
    if (rc != SAR_OK)
        goto fail;
    rc = select_app(d, appid);
    if (rc != SAR_OK)
        goto fail;
    rc = create_ef_len(d, 0x2001, pin_attr, sizeof(pin_attr));
    if (rc != SAR_OK)
        goto fail;
    rc = select_file(d, 0x2001, 2);
    if (rc != SAR_OK)
        goto fail;

    ctrl_key(d, ctrl);
    rc = SKF_GenRandom((DEVHANDLE)d, appkey, sizeof(appkey));
    if (rc != SAR_OK)
        goto fail;
    memset(obj, 0, sizeof(obj));
    obj[0] = 0x11; obj[1] = 0x01; obj[2] = 0x12;
    obj[4] = 0x0f; obj[5] = 0xf0; obj[7] = 0x06; obj[8] = 0x10;
    memcpy(obj + 0x0c, appkey, 16);
    rc = write_key(d, 0x21, obj, ctrl);
    if (rc != SAR_OK)
        goto fail;

    memset(obj, 0, sizeof(obj));
    obj[0] = 0x12; obj[1] = 0x01; obj[2] = 0x12; obj[3] = 0x04;
    obj[4] = 0x0f; obj[5] = 0x45; obj[6] = 0x04;
    obj[7] = (unsigned char)adminlen;
    obj[8] = 0x10;
    memcpy(obj + 0x0c, apin, adminlen);
    rc = write_key(d, 0x20, obj, appkey);
    if (rc != SAR_OK)
        goto fail;

    memset(obj, 0, sizeof(obj));
    obj[0] = 0x13; obj[1] = 0x01; obj[2] = 0x12; obj[3] = 0x01;
    obj[4] = 0x0f; obj[5] = 0x25; obj[6] = 0x03;
    obj[7] = (unsigned char)userlen;
    obj[8] = 0x10;
    memcpy(obj + 0x0c, upin, userlen);
    rc = write_key(d, 0x20, obj, appkey);
    if (rc != SAR_OK)
        goto fail;

    rc = select_app(d, appid);
    if (rc != SAR_OK)
        goto fail;
    rc = pin_verify(d, appid, USER_TYPE, upin, NULL);
    if (rc != SAR_OK)
        goto fail;

    unsigned short slot = 0;
    for (unsigned short s = 0x1101; s <= 0x1105; s++) {
        rc = select_file(d, s, 2);
        if (rc == SAR_FILE_NOT_EXIST) { slot = s; break; }
    }
    if (!slot) {
        rc = SAR_NO_ROOM;
        goto fail;
    }
    rc = create_ef_len(d, slot, ctn_attr, sizeof(ctn_attr));
    if (rc != SAR_OK)
        goto fail;
    rc = select_file(d, slot, 2);
    if (rc != SAR_OK)
        goto fail;
    rc = write_selected(d, (const BYTE *)"DEFAULT", 8);
    if (rc != SAR_OK)
        goto fail;

    APP_CTX *a = calloc(1, sizeof(*a));
    if (!a) {
        rc = SAR_FAIL;
        goto fail;
    }
    a->dev = d;
    a->id = appid;
    snprintf(a->name, sizeof(a->name), "%s", app);
    d->app_id = appid;
    d->app_open = 1;
    d->user_logged = 0;
    d->admin_logged = 0;
    *phApp = (HAPPLICATION)a;
    return SAR_OK;

fail:
    rollback_app(d, appid);
    return rc;
}

ULONG SKF_DeleteApplication(DEVHANDLE hDev, LPSTR name)
{
    DEV_CTX *d = (DEV_CTX *)hDev;
    unsigned char list[256];
    unsigned short appid = 0;
    ULONG rc;
    if (!d || !name)
        return SAR_INVALIDPARAMERR;
    rc = read_app_list(d, list);
    if (rc != SAR_OK)
        return SAR_FILE_NOT_EXIST;
    unsigned n = app_count(list);
    for (unsigned i = 0; i < n; i++) {
        unsigned char *rec = list + 0x14 * i;
        if (strncmp((char *)rec, name, 16) == 0) {
            appid = (unsigned short)(rec[0x10] | ((unsigned)rec[0x11] << 8));
            memmove(rec, rec + 0x14, (n - i - 1) * 0x14);
            memset(list + 0x14 * (n - 1), 0, sizeof(list) - 0x14 * (n - 1));
            n--;
            list[0x12] = (unsigned char)n;
            list[0x13] = (unsigned char)(n >> 8);
            break;
        }
    }
    if (!appid)
        return SAR_FILE_NOT_EXIST;
    if (!d->dev_authed)
        return SAR_USER_NOT_LOGGED_IN;
    rc = write_app_list(d, list);
    if (rc != SAR_OK)
        return rc;
    rc = select_file(d, 0x3f00, 0);
    if (rc != SAR_OK)
        return rc;
    return delete_ef(d, appid);
}

LONG SKF_GetPINInfo(HAPPLICATION hApp, ULONG type, ULONG *max,
                    ULONG *remain, BOOL *def)
{
    APP_CTX *a = (APP_CTX *)hApp;
    DEV_CTX *d;
    unsigned char cmd[20], buf[64];
    unsigned long len = sizeof(buf);
    ULONG rc;

    if (!a || !a->dev)
        return SAR_INVALIDHANDLEERR;
    d = a->dev;
    if (type != USER_TYPE && type != ADMIN_TYPE)
        return SAR_INVALIDPARAMERR;
    rc = select_app(d, a->id);
    if (rc != SAR_OK)
        return rc;
    select_file(d, 0x3f00, 0);
    select_app(d, a->id);
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0xbc;
    cmd[2] = (type == ADMIN_TYPE) ? 0x01 : 0x00;
    put_be32(cmd + 4, 0x0c);
    rc = apdu(d, cmd, 20, buf, &len);
    if (rc != SAR_OK)
        return rc;
    if (len < 12)
        return SAR_FAIL;
    if (max)
        *max = buf[7];
    if (remain)
        *remain = buf[11];
    if (def)
        *def = (buf[9] == 0xff) ? 0 : buf[9];
    return SAR_OK;
}

static void des_cbc_enc(const unsigned char *in, unsigned char *out,
                       long len, const unsigned char *key,
                       const unsigned char *iv)
{
    DES_key_schedule ks;
    DES_cblock k, v;
    memcpy(k, key, 8);
    memcpy(v, iv, 8);
    DES_set_key_unchecked(&k, &ks);
    DES_ncbc_encrypt(in, out, len, &ks, &v, DES_ENCRYPT);
}

static void des_ecb_enc(const unsigned char *in, unsigned char *out,
                        long len, const unsigned char *key)
{
    DES_key_schedule ks;
    DES_cblock k;
    memcpy(k, key, 8);
    DES_set_key_unchecked(&k, &ks);
    for (long off = 0; off + 8 <= len; off += 8) {
        DES_cblock inb, outb;
        memcpy(inb, in + off, 8);
        DES_ecb_encrypt(&inb, &outb, &ks, DES_ENCRYPT);
        memcpy(out + off, outb, 8);
    }
}

static ULONG sm1_init(DEV_CTX *d, const unsigned char key[16])
{
    unsigned char rnd[8], serial[16], plain[64], enc[64], blob[72], cmd[80];
    unsigned long n = 0;
    ULONG rc;
    if (!d || !key)
        return SAR_INVALIDPARAMERR;
    memset(serial, 0, sizeof(serial));
    memcpy(serial, d->serial, 8);
    if (getrandom(rnd, sizeof(rnd), 0) != (ssize_t)sizeof(rnd)) {
        for (size_t i = 0; i < sizeof(rnd); i++)
            rnd[i] = (unsigned char)rand();
    }
    memset(plain, 0, sizeof(plain));
    memcpy(plain, key, 16);
    des_cbc_enc(plain, enc, sizeof(plain), rnd, serial);
    memcpy(blob, rnd, 8);
    memcpy(blob + 8, enc, 64);
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x5b; cmd[2] = 0x00; cmd[3] = 0x01;
    put_be32(cmd + 4, 0x48);
    memcpy(cmd + 8, blob, 72);
    rc = apdu_ext(d, cmd, sizeof(cmd), 0, NULL, &n);
    return rc;
}

static ULONG sm1_encrypt(DEV_CTX *d, const unsigned char in[16],
                         unsigned char out[16])
{
    unsigned char cmd[32], buf[40];
    unsigned long n = sizeof(buf);
    ULONG rc;
    if (!d || !in || !out)
        return SAR_INVALIDPARAMERR;
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x5b; cmd[2] = 0x00; cmd[3] = 0x00;
    put_be32(cmd + 4, 0x18);
    memcpy(cmd + 8 + 8, in, 16);
    rc = apdu_ext(d, cmd, sizeof(cmd), 0, buf, &n);
    if (rc != SAR_OK || n < 16)
        return rc == SAR_OK ? SAR_FAIL : rc;
    memcpy(out, buf + n - 16, 16);
    return SAR_OK;
}

static ULONG pin_encrypt_buf(DEV_CTX *d, unsigned char *data, ULONG len)
{
    unsigned char serial[16], rnd[8], kout[8], iv[8];
    ULONG rc;
    if (!d || !data || (len % 8) != 0)
        return SAR_INVALIDPARAMERR;
    memset(serial, 0, sizeof(serial));
    memcpy(serial, d->serial, 8);
    rc = SKF_GenRandom((DEVHANDLE)d, rnd, sizeof(rnd));
    if (rc != SAR_OK)
        return rc;
    memcpy(iv, serial + 8, 4);
    memcpy(iv + 4, rnd, 4);
    des_cbc_enc(rnd, kout, 8, serial, iv);
    des_ecb_enc(data, data, (long)len, kout);
    return SAR_OK;
}

static ULONG pin_verify(DEV_CTX *d, unsigned short app_id, ULONG type,
                        const char *pin, ULONG *retry)
{
    unsigned char serial[16], rnd[8], pinbuf[16], kout[8], enc[16];
    unsigned char cmd[24];
    unsigned long len;
    ULONG rc;

    if (!d || !pin || (type != USER_TYPE && type != ADMIN_TYPE))
        return SAR_INVALIDPARAMERR;
    char pinstr[17];
    snprintf(pinstr, sizeof(pinstr), "%s", pin);
    if (strlen(pinstr) > 16)
        return SAR_INVALIDPARAMERR;

    memset(serial, 0, sizeof(serial));
    memcpy(serial, d->serial, 8);
    memset(pinbuf, 0, sizeof(pinbuf));
    memcpy(pinbuf, pinstr, strlen(pinstr));

    rc = SKF_GenRandom((DEVHANDLE)d, rnd, sizeof(rnd));
    if (rc != SAR_OK)
        return rc;

    unsigned char iv[8];
    memcpy(iv, serial + 8, 4);
    memcpy(iv + 4, rnd, 4);
    des_cbc_enc(rnd, kout, 8, serial, iv);
    des_ecb_enc(pinbuf, enc, 16, kout);

    rc = select_app(d, app_id);
    if (rc != SAR_OK)
        return rc;

    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x00; cmd[1] = 0x20;
    cmd[2] = (type == ADMIN_TYPE) ? 0x01 : 0x00;
    put_be32(cmd + 4, 16);
    memcpy(cmd + 8, enc, 16);

    len = 0;
    rc = apdu(d, cmd, sizeof(cmd), NULL, &len);
    if (rc == SAR_OK) {
        if (type == USER_TYPE) {
            d->user_logged = 1;
            snprintf(d->user_pin, sizeof(d->user_pin), "%s", pinstr);
            if (getenv("SKF_DEBUG"))
                fprintf(stderr, "pin_verify ok d=%p pin='%s' stored='%s'\n",
                        (void *)d, pin, d->user_pin);
        } else {
            d->admin_logged = 1;
        }
        if (retry)
            *retry = 0;
    } else if (rc == SAR_PIN_INCORRECT && retry) {
        *retry = len;
    }
    return rc;
}

ULONG SKF_VerifyPIN(HAPPLICATION hApp, ULONG type, LPSTR pin, ULONG *retry)
{
    APP_CTX *a = (APP_CTX *)hApp;
    if (!a || !a->dev)
        return SAR_INVALIDHANDLEERR;
    return pin_verify(a->dev, a->id, type, pin, retry);
}

ULONG SKF_ChangePIN(HAPPLICATION hApp, ULONG type, LPSTR oldpin,
                    LPSTR newpin, ULONG *retry)
{
    APP_CTX *a = (APP_CTX *)hApp;
    unsigned char buf[40], cmd[48];
    unsigned long len = 0;
    ULONG rc;
    if (!a || !a->dev || !oldpin || !newpin ||
        (type != USER_TYPE && type != ADMIN_TYPE))
        return SAR_INVALIDPARAMERR;
    if (strlen(oldpin) > 16 || strlen(newpin) > 16)
        return SAR_INVALIDPARAMERR;
    memset(buf, 0, sizeof(buf));
    memcpy(buf, oldpin, strlen(oldpin));
    buf[0x10] = 0xff;
    memcpy(buf + 0x11, newpin, strlen(newpin));
    rc = pin_encrypt_buf(a->dev, buf, 40);
    if (rc != SAR_OK)
        return rc;
    select_app(a->dev, a->id);
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x5e;
    cmd[2] = (type == ADMIN_TYPE) ? 0x00 : 0x01;
    put_be32(cmd + 4, 0x28);
    memcpy(cmd + 8, buf, 40);
    rc = apdu(a->dev, cmd, sizeof(cmd), NULL, &len);
    if (rc == SAR_OK && type == USER_TYPE)
        snprintf(a->dev->user_pin, sizeof(a->dev->user_pin), "%s", newpin);
    else if (rc == SAR_PIN_INCORRECT && retry)
        *retry = len;
    return rc;
}

ULONG SKF_UnblockPIN(HAPPLICATION hApp, LPSTR adminpin, LPSTR newpin,
                     ULONG *retry)
{
    APP_CTX *a = (APP_CTX *)hApp;
    unsigned char buf[32], cmd[40];
    unsigned long len = 0;
    ULONG rc;
    if (!a || !a->dev || !adminpin || !newpin)
        return SAR_INVALIDPARAMERR;
    if (strlen(adminpin) > 16 || strlen(newpin) > 16)
        return SAR_INVALIDPARAMERR;
    memset(buf, 0, sizeof(buf));
    memcpy(buf, adminpin, strlen(adminpin));
    memcpy(buf + 0x10, newpin, strlen(newpin));
    rc = pin_encrypt_buf(a->dev, buf, 32);
    if (rc != SAR_OK)
        return rc;
    select_app(a->dev, a->id);
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x2c;
    put_be32(cmd + 4, 0x20);
    memcpy(cmd + 8, buf, 32);
    rc = apdu(a->dev, cmd, sizeof(cmd), NULL, &len);
    if (rc == SAR_OK)
        snprintf(a->dev->user_pin, sizeof(a->dev->user_pin), "%s", newpin);
    else if (rc == SAR_PIN_INCORRECT && retry)
        *retry = len;
    return rc;
}

ULONG SKF_ClearSecureState(HAPPLICATION hApp)
{
    APP_CTX *a = (APP_CTX *)hApp;
    if (!a || !a->dev)
        return SAR_INVALIDHANDLEERR;
    a->dev->user_logged = 0;
    a->dev->admin_logged = 0;
    return SAR_OK;
}

/* ---------- containers ---------- */

static ULONG container_list(APP_CTX *a, char *out, size_t *outlen)
{
    size_t off = 0;
    for (unsigned short f = 0x1101; f <= 0x1105; f++) {
        unsigned char buf[0x41];
        unsigned long len = sizeof(buf);
        select_app(a->dev, a->id);
        ULONG rc = read_file(a->dev, f, 0, buf, &len);
        if (rc != SAR_OK || len < 2 || !buf[0])
            continue;
        size_t n = strnlen((char *)buf, 0x41);
        if (n == 0 || n >= 64)
            continue;
        if (off + n + 1 >= 512)
            break;
        memcpy(out + off, buf, n);
        off += n;
        out[off++] = 0;
    }
    *outlen = off;
    return SAR_OK;
}

ULONG SKF_EnumContainer(HAPPLICATION hApp, LPSTR names, ULONG *size)
{
    APP_CTX *a = (APP_CTX *)hApp;
    char list[512];
    size_t len;
    if (!a || !size)
        return SAR_INVALIDHANDLEERR;
    select_app(a->dev, a->id);
    container_list(a, list, &len);
    if (!names) {
        *size = (ULONG)len;
        return SAR_OK;
    }
    if (*size < len)
        return SAR_INVALIDPARAMERR;
    memcpy(names, list, len);
    *size = (ULONG)len;
    return SAR_OK;
}

ULONG SKF_OpenContainer(HAPPLICATION hApp, LPSTR name, HCONTAINER *phCtn)
{
    APP_CTX *a = (APP_CTX *)hApp;
    if (!a || !name || !phCtn)
        return SAR_INVALIDPARAMERR;
    select_app(a->dev, a->id);
    for (unsigned short f = 0x1101; f <= 0x1105; f++) {
        unsigned char buf[0x41];
        unsigned long len = sizeof(buf);
        if (read_file(a->dev, f, 0, buf, &len) != SAR_OK || len < 2)
            continue;
        if (strncmp((char *)buf, name, 0x41) == 0) {
            CTN_CTX *c = calloc(1, sizeof(*c));
            if (!c)
                return SAR_FAIL;
            c->app = a;
            c->file_id = f;
            c->key_file = (unsigned short)(0x1301 + (f - 0x1101));
            c->type = (f == 0x1101) ? 1 : 2;
            snprintf(c->name, sizeof(c->name), "%s", name);
            a->dev->ctn_id = f;
            a->dev->ctn_open = 1;
            *phCtn = (HCONTAINER)c;
            return SAR_OK;
        }
    }
    return SAR_FILE_NOT_EXIST;
}

ULONG SKF_CloseContainer(HCONTAINER hCtn)
{
    CTN_CTX *c = (CTN_CTX *)hCtn;
    if (!c)
        return SAR_INVALIDHANDLEERR;
    if (c->app && c->app->dev)
        c->app->dev->ctn_open = 0;
    free(c->rsa_priv_soft);
    free(c);
    return SAR_OK;
}

ULONG SKF_GetContainerType(HCONTAINER hCtn, ULONG *type)
{
    CTN_CTX *c = (CTN_CTX *)hCtn;
    unsigned char fci[128];
    unsigned long flen = sizeof(fci);
    ULONG size = 0;
    if (!c || !type)
        return SAR_INVALIDHANDLEERR;
    /* Vendor convention: 0 = empty container, 1 = RSA, 2 = ECC.
     * The type follows the key file, not the container slot. */
    *type = 0;
    select_app(c->app->dev, c->app->id);
    ULONG rc = select_file_data(c->app->dev, c->key_file, 2, fci, &flen);
    if (rc == SAR_FILE_NOT_EXIST)
        return SAR_OK;
    if (rc != SAR_OK)
        return rc;
    if (fci_size(fci, flen, &size) != SAR_OK)
        return SAR_FAIL;
    *type = (size == 0x68) ? 2 : 1;
    return SAR_OK;
}

static ULONG write_selected(DEV_CTX *d, const BYTE *data, ULONG len)
{
    unsigned char cmd[512];
    unsigned long total = 0;
    while (total < len) {
        unsigned long chunk = len - total;
        ULONG rc;
        if (chunk > 0x1c1)
            chunk = 0x1c1;
        memset(cmd, 0, sizeof(cmd));
        cmd[0] = 0x00; cmd[1] = 0xd6;
        cmd[2] = (unsigned char)(total >> 8);
        cmd[3] = (unsigned char)total;
        put_be32(cmd + 4, chunk);
        memcpy(cmd + 8, data + total, chunk);
        rc = apdu(d, cmd, 8 + chunk, NULL, NULL);
        if (rc != SAR_OK)
            return rc;
        total += chunk;
    }
    return SAR_OK;
}

static ULONG create_ef(DEV_CTX *d, unsigned short file,
                       const unsigned char attrs[12])
{
    unsigned char cmd[20];
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0xe0;
    cmd[2] = (unsigned char)(file >> 8);
    cmd[3] = (unsigned char)file;
    put_be32(cmd + 4, 0x0c);
    memcpy(cmd + 8, attrs, 12);
    return apdu(d, cmd, sizeof(cmd), NULL, NULL);
}

static ULONG delete_ef(DEV_CTX *d, unsigned short file)
{
    unsigned char cmd[10];
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0xe4;
    put_be32(cmd + 4, 0x02);
    cmd[8] = (unsigned char)(file >> 8);
    cmd[9] = (unsigned char)file;
    return apdu(d, cmd, sizeof(cmd), NULL, NULL);
}

ULONG SKF_CreateContainer(HAPPLICATION hApp, LPSTR name, HCONTAINER *phCtn)
{
    APP_CTX *a = (APP_CTX *)hApp;
    DEV_CTX *d;
    unsigned short slot = 0;
    static const unsigned char ctn_attr[12] =
        {0x01,0x0f,0x0f,0x00,0x00,0x00,0x00,0x41,0x00,0x00,0x00,0x00};
    static const unsigned char key_attr[12] =
        {0x1a,0x23,0x23,0x00,0x00,0x00,0x00,0x68,0x00,0x00,0x00,0x00};
    ULONG rc;

    if (!a || !name || !phCtn)
        return SAR_INVALIDPARAMERR;
    d = a->dev;
    if (!d->user_logged)
        return SAR_USER_NOT_LOGGED_IN;
    rc = select_app(d, a->id);
    if (rc != SAR_OK)
        return rc;
    for (unsigned short f = 0x1101; f <= 0x1105; f++) {
        unsigned char b[0x41];
        unsigned long n = sizeof(b);
        rc = read_file(d, f, 0, b, &n);
        if (rc == SAR_FILE_NOT_EXIST) { slot = f; break; }
    }
    if (!slot)
        return SAR_NO_ROOM;
    rc = create_ef(d, slot, ctn_attr);
    if (rc != SAR_OK)
        return rc;
    select_file(d, slot, 2);
    rc = write_selected(d, (const BYTE *)name, (ULONG)strlen(name) + 1);
    if (rc != SAR_OK) {
        delete_ef(d, slot);
        return rc;
    }

    select_app(d, a->id);
    unsigned short keyfile = (unsigned short)(0x1301 + (slot - 0x1101));
    rc = create_ef(d, keyfile, key_attr);
    if (rc != SAR_OK) {
        delete_ef(d, slot);
        return rc;
    }
    if (d->user_pin[0])
        pin_verify(d, a->id, USER_TYPE, d->user_pin, NULL);

    CTN_CTX *c = calloc(1, sizeof(*c));
    if (!c) {
        delete_ef(d, keyfile);
        delete_ef(d, slot);
        return SAR_FAIL;
    }
    c->app = a;
    c->file_id = slot;
    c->key_file = keyfile;
    c->type = 2;
    snprintf(c->name, sizeof(c->name), "%s", name);
    *phCtn = (HCONTAINER)c;
    return SAR_OK;
}

ULONG SKF_DeleteContainer(HAPPLICATION hApp, LPSTR name)
{
    APP_CTX *a = (APP_CTX *)hApp;
    DEV_CTX *d;
    unsigned short slot = 0, keyfile;
    if (!a || !name)
        return SAR_INVALIDPARAMERR;
    d = a->dev;
    select_app(d, a->id);
    for (unsigned short f = 0x1101; f <= 0x1105; f++) {
        unsigned char b[0x41];
        unsigned long n = sizeof(b);
        if (read_file(d, f, 0, b, &n) == SAR_OK &&
            strncmp((char *)b, name, 0x41) == 0) {
            slot = f;
            break;
        }
    }
    if (!slot)
        return SAR_FILE_NOT_EXIST;
    keyfile = (unsigned short)(0x1301 + (slot - 0x1101));
    ULONG rc = select_app(d, a->id);
    if (rc != SAR_OK)
        return rc;
    ULONG first = SAR_OK;
    unsigned short files[5] = {
        keyfile,
        (unsigned short)(0x1201 + (slot - 0x1101)),
        (unsigned short)(0x1401 + (slot - 0x1101)),
        (unsigned short)(0x1501 + (slot - 0x1101)),
        slot
    };
    for (int i = 0; i < 5; i++) {
        rc = delete_ef(d, files[i]);
        if (rc != SAR_OK && rc != SAR_FILE_NOT_EXIST && first == SAR_OK)
            first = rc;
    }
    return first;
}

/* ---------- files ---------- */

#define FILE_DIR_ID     0x2002
#define FILE_DIR_SIZE   477
#define FILE_ENTRY_SIZE 68
#define FILE_DATA_BASE  0x2f01

static void file_dir_init(unsigned char dir[FILE_DIR_SIZE])
{
    dir[0] = 0;
    memset(dir + 1, 0xff, FILE_DIR_SIZE - 1);
}

static ULONG file_dir_read(APP_CTX *a, unsigned char dir[FILE_DIR_SIZE])
{
    unsigned long len = FILE_DIR_SIZE;
    ULONG rc;
    if (!a || !a->dev)
        return SAR_INVALIDHANDLEERR;
    rc = select_app(a->dev, a->id);
    if (rc != SAR_OK)
        return rc;
    rc = read_file(a->dev, FILE_DIR_ID, 0, dir, &len);
    if (rc != SAR_OK)
        return rc;
    if (len < 1)
        return SAR_FAIL;
    if (dir[0] > 7)
        dir[0] = 7;
    return SAR_OK;
}

static ULONG file_dir_write(APP_CTX *a, const unsigned char dir[FILE_DIR_SIZE])
{
    ULONG rc;
    if (!a || !a->dev)
        return SAR_INVALIDHANDLEERR;
    rc = select_app(a->dev, a->id);
    if (rc != SAR_OK)
        return rc;
    rc = select_file(a->dev, FILE_DIR_ID, 2);
    if (rc != SAR_OK)
        return rc;
    return write_selected(a->dev, dir, FILE_DIR_SIZE);
}

static unsigned char *file_entry(unsigned char dir[FILE_DIR_SIZE], unsigned i)
{
    return dir + 1 + i * FILE_ENTRY_SIZE;
}

static ULONG file_find_id(APP_CTX *a, const char *name, unsigned short *id)
{
    unsigned char dir[FILE_DIR_SIZE];
    ULONG rc = file_dir_read(a, dir);
    if (rc != SAR_OK)
        return rc;
    unsigned n = dir[0];
    for (unsigned i = 0; i < n; i++) {
        unsigned char *e = file_entry(dir, i);
        size_t l = strnlen((char *)e, 64);
        if (l == strlen(name) && memcmp(e, name, l) == 0) {
            *id = (unsigned short)(e[0x41] | ((unsigned short)e[0x42] << 8));
            return SAR_OK;
        }
    }
    return SAR_FILE_NOT_EXIST;
}

static int file_id_used(const unsigned char dir[FILE_DIR_SIZE], unsigned short id)
{
    unsigned n = dir[0];
    for (unsigned i = 0; i < n; i++) {
        const unsigned char *e = dir + 1 + i * FILE_ENTRY_SIZE;
        unsigned short eid = (unsigned short)(e[0x41] | ((unsigned short)e[0x42] << 8));
        if (eid == id)
            return 1;
    }
    return 0;
}

static ULONG file_dir_add(unsigned char dir[FILE_DIR_SIZE], const char *name,
                          unsigned short id)
{
    unsigned n = dir[0];
    if (n >= 7)
        return SAR_NO_ROOM;
    unsigned char *e = file_entry(dir, n);
    memset(e, 0xff, FILE_ENTRY_SIZE);
    strncpy((char *)e, name, 64);
    e[0x40] = 0xff;
    e[0x41] = (unsigned char)id;
    e[0x42] = (unsigned char)(id >> 8);
    e[0x43] = 0;
    dir[0] = (unsigned char)(n + 1);
    return SAR_OK;
}

static void file_dir_remove(unsigned char dir[FILE_DIR_SIZE], unsigned idx)
{
    unsigned n = dir[0];
    if (idx >= n)
        return;
    if (idx + 1 < n)
        memmove(file_entry(dir, idx), file_entry(dir, idx + 1),
                (n - idx - 1) * FILE_ENTRY_SIZE);
    memset(file_entry(dir, n - 1), 0xff, FILE_ENTRY_SIZE);
    dir[0] = (unsigned char)(n - 1);
}

ULONG SKF_EnumFiles(HAPPLICATION hApp, LPSTR names, ULONG *size)
{
    APP_CTX *a = (APP_CTX *)hApp;
    unsigned char dir[FILE_DIR_SIZE];
    char list[512];
    size_t off = 0;
    ULONG rc;
    if (!a || !a->dev || !size)
        return SAR_INVALIDHANDLEERR;
    rc = file_dir_read(a, dir);
    if (rc == SAR_FILE_NOT_EXIST) {
        *size = 0;
        return SAR_OK;
    }
    if (rc != SAR_OK)
        return rc;
    unsigned n = dir[0];
    for (unsigned i = 0; i < n; i++) {
        unsigned char *e = file_entry(dir, i);
        size_t l = strnlen((char *)e, 64);
        if (l == 0 || l >= 64)
            continue;
        if (off + l + 1 >= sizeof(list))
            break;
        memcpy(list + off, e, l);
        off += l;
        list[off++] = 0;
    }
    if (!names) {
        *size = (ULONG)off;
        return SAR_OK;
    }
    if (*size < off)
        return SAR_INVALIDPARAMERR;
    memcpy(names, list, off);
    *size = (ULONG)off;
    return SAR_OK;
}

ULONG SKF_CreateFile(HAPPLICATION hApp, LPSTR name, ULONG size,
                     ULONG readright, ULONG writeright)
{
    APP_CTX *a = (APP_CTX *)hApp;
    DEV_CTX *d;
    unsigned char dir[FILE_DIR_SIZE];
    static const unsigned char dir_attr[12] =
        {0x01,0x0f,0x0f,0x0f,0x00,0x00,0x01,0xdd,0x00,0x00,0x00,0x00};
    unsigned char file_attr[12] =
        {0x01,0x0f,0x0f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    unsigned short id = 0;
    ULONG rc;

    if (!a || !a->dev || !name)
        return SAR_INVALIDPARAMERR;
    if (readright != SECURE_ANYONE_ACCOUNT || writeright != SECURE_ANYONE_ACCOUNT)
        return SAR_NOTSUPPORTYETERR;
    if (strlen(name) > 32 || strlen(name) == 0)
        return SAR_NAMELENERR;
    if (size > 0xffff)
        return SAR_INVALIDPARAMERR;

    d = a->dev;
    rc = file_dir_read(a, dir);
    if (rc == SAR_FILE_NOT_EXIST) {
        rc = select_app(d, a->id);
        if (rc != SAR_OK)
            return rc;
        rc = create_ef_len(d, FILE_DIR_ID, dir_attr, sizeof(dir_attr));
        if (rc != SAR_OK)
            return rc;
        file_dir_init(dir);
        rc = file_dir_write(a, dir);
        if (rc != SAR_OK)
            return rc;
    } else if (rc != SAR_OK) {
        return rc;
    }

    unsigned n = dir[0];
    for (unsigned i = 0; i < n; i++) {
        unsigned char *e = file_entry(dir, i);
        if (strncmp((char *)e, name, 64) == 0)
            return SAR_FILE_ALREADY_EXIST;
    }
    for (unsigned short cand = FILE_DATA_BASE; cand < FILE_DATA_BASE + 0x7f; cand++) {
        if (!file_id_used(dir, cand)) { id = cand; break; }
    }
    if (!id)
        return SAR_NO_ROOM;

    file_attr[6] = (unsigned char)(size >> 8);
    file_attr[7] = (unsigned char)size;
    rc = select_app(d, a->id);
    if (rc != SAR_OK)
        return rc;
    rc = create_ef_len(d, id, file_attr, sizeof(file_attr));
    if (rc != SAR_OK)
        return rc;
    rc = file_dir_add(dir, name, id);
    if (rc != SAR_OK)
        return rc;
    return file_dir_write(a, dir);
}

ULONG SKF_DeleteFile(HAPPLICATION hApp, LPSTR name)
{
    APP_CTX *a = (APP_CTX *)hApp;
    unsigned char dir[FILE_DIR_SIZE];
    unsigned short id = 0;
    ULONG rc;
    if (!a || !a->dev || !name)
        return SAR_INVALIDPARAMERR;
    rc = file_find_id(a, name, &id);
    if (rc != SAR_OK)
        return rc;
    rc = select_app(a->dev, a->id);
    if (rc != SAR_OK)
        return rc;
    rc = delete_ef(a->dev, id);
    if (rc != SAR_OK)
        return rc;
    rc = file_dir_read(a, dir);
    if (rc != SAR_OK)
        return rc;
    unsigned n = dir[0];
    for (unsigned i = 0; i < n; i++) {
        unsigned char *e = file_entry(dir, i);
        if (strncmp((char *)e, name, 64) == 0) {
            file_dir_remove(dir, i);
            return file_dir_write(a, dir);
        }
    }
    return SAR_FILE_NOT_EXIST;
}

ULONG SKF_ReadFile(HAPPLICATION hApp, LPSTR name, ULONG off, ULONG len,
                   BYTE *out, ULONG *outlen)
{
    APP_CTX *a = (APP_CTX *)hApp;
    unsigned short id = 0;
    ULONG rc, done = 0;
    if (!a || !a->dev || !name || !outlen || (!out && len))
        return SAR_INVALIDPARAMERR;
    if (off > 0xffff)
        return SAR_INVALIDPARAMERR;
    rc = file_find_id(a, name, &id);
    if (rc != SAR_OK)
        return rc;
    while (done < len) {
        unsigned long chunk = len - done;
        if (off + done > 0xffff)
            return SAR_INVALIDPARAMERR;
        if (chunk > 0x1c1)
            chunk = 0x1c1;
        if (chunk > *outlen - done)
            chunk = *outlen - done;
        if (chunk == 0)
            break;
        rc = read_file(a->dev, id, off + done, out + done, &chunk);
        if (rc != SAR_OK)
            return rc;
        if (chunk == 0)
            break;
        done += chunk;
    }
    *outlen = done;
    return SAR_OK;
}

ULONG SKF_WriteFile(HAPPLICATION hApp, LPSTR name, ULONG off,
                    BYTE *data, ULONG len)
{
    APP_CTX *a = (APP_CTX *)hApp;
    unsigned short id = 0;
    ULONG rc, done = 0;
    if (!a || !a->dev || !name || (!data && len))
        return SAR_INVALIDPARAMERR;
    if (off > 0xffff)
        return SAR_INVALIDPARAMERR;
    rc = file_find_id(a, name, &id);
    if (rc != SAR_OK)
        return rc;
    rc = select_app(a->dev, a->id);
    if (rc != SAR_OK)
        return rc;
    rc = select_file(a->dev, id, 2);
    if (rc != SAR_OK)
        return rc;
    while (done < len) {
        unsigned long chunk = len - done;
        if (off + done > 0xffff)
            return SAR_INVALIDPARAMERR;
        if (chunk > 0x1c1)
            chunk = 0x1c1;
        unsigned char cmd[512];
        memset(cmd, 0, sizeof(cmd));
        cmd[0] = 0x00; cmd[1] = 0xd6;
        cmd[2] = (unsigned char)((off + done) >> 8);
        cmd[3] = (unsigned char)(off + done);
        put_be32(cmd + 4, chunk);
        memcpy(cmd + 8, data + done, chunk);
        rc = apdu(a->dev, cmd, 8 + chunk, NULL, NULL);
        if (rc != SAR_OK)
            return rc;
        done += chunk;
    }
    return SAR_OK;
}

static ULONG fci_size(const unsigned char *buf, unsigned long len, ULONG *size)
{
    for (unsigned long i = 0; i + 4 <= len; i++) {
        if (buf[i] == 0x80 && buf[i + 1] == 0x02) {
            *size = ((ULONG)buf[i + 2] << 8) | buf[i + 3];
            return SAR_OK;
        }
    }
    return SAR_FAIL;
}

static ULONG fci_rights(const unsigned char *buf, unsigned long len,
                        ULONG *readright, ULONG *writeright)
{
    for (unsigned long i = 0; i + 6 <= len; i++) {
        if (buf[i] == 0x85 && buf[i + 1] == 0x04) {
            *readright = buf[i + 2];
            *writeright = buf[i + 3];
            return SAR_OK;
        }
    }
    return SAR_FAIL;
}

ULONG SKF_GetFileInfo(HAPPLICATION hApp, LPSTR name, FILEATTRIBUTE *info)
{
    APP_CTX *a = (APP_CTX *)hApp;
    unsigned short id = 0;
    unsigned char fci[256];
    unsigned long flen = sizeof(fci);
    ULONG size = 0, rr = 0, wr = 0;
    ULONG rc;
    if (!a || !a->dev || !name || !info)
        return SAR_INVALIDPARAMERR;
    rc = file_find_id(a, name, &id);
    if (rc != SAR_OK)
        return rc;
    rc = select_file_data(a->dev, id, 0, fci, &flen);
    if (rc != SAR_OK)
        return rc;
    if (fci_size(fci, flen, &size) != SAR_OK)
        return SAR_FAIL;
    fci_rights(fci, flen, &rr, &wr);
    memset(info, 0, sizeof(*info));
    snprintf(info->FileName, sizeof(info->FileName), "%s", name);
    info->FileSize = size;
    info->ReadRights = rr;
    info->WriteRights = wr;
    return SAR_OK;
}

/* ---------- crypto (to be filled in) ---------- */

typedef struct sym_ctx {
    int type;               /* 1 = symmetric, 2 = mac */
    DEV_CTX *dev;
    unsigned long alg;
    unsigned char key[32];
    unsigned long keylen;
    BLOCKCIPHERPARAM param;
    unsigned char *buf;
    unsigned long buflen;
    int initialized;
    int sm1;
} SYM_CTX;

typedef struct hash_ctx {
    int type;               /* 3 = hash */
    EVP_MD_CTX *ctx;
} HASH_CTX;

typedef struct agree_ctx {
    int type;               /* 4 = ECC agreement */
    DEV_CTX *dev;
    ULONG alg;
    EC_KEY *eph;
    unsigned char eph_priv[32];
    unsigned char static_priv[32];
    ECCPUBLICKEYBLOB static_pub;
    unsigned char id[32];
    ULONG idlen;
} AGREE_CTX;

static const EVP_CIPHER *cipher_for(unsigned long alg)
{
    switch (alg) {
    case SGD_SM4_ECB: return EVP_sm4_ecb();
    case SGD_SM4_CBC: return EVP_sm4_cbc();
    case SGD_SM4_CFB: return EVP_sm4_cfb128();
    case SGD_SM4_OFB: return EVP_sm4_ofb();
    default: return NULL;
    }
}

ULONG SKF_SetSymmKey(DEVHANDLE hDev, BYTE *key, ULONG alg, HANDLE *phKey)
{
    (void)hDev;
    if (!key || !phKey)
        return SAR_INVALIDPARAMERR;
    if (!cipher_for(alg) && alg != SGD_SM4_MAC && alg != SGD_SM1_ECB)
        return SAR_NOTSUPPORTYETERR;
    SYM_CTX *s = calloc(1, sizeof(*s));
    if (!s)
        return SAR_FAIL;
    s->type = 1;
    s->dev = (DEV_CTX *)hDev;
    s->alg = alg;
    s->keylen = 16;
    s->sm1 = (alg == SGD_SM1_ECB);
    memcpy(s->key, key, 16);
    *phKey = (HANDLE)s;
    return SAR_OK;
}

ULONG SKF_EncryptInit(HANDLE hKey, BLOCKCIPHERPARAM p)
{
    SYM_CTX *s = (SYM_CTX *)hKey;
    if (!s || s->type != 1)
        return SAR_INVALIDHANDLEERR;
    s->param = p;
    s->initialized = 1;
    if (s->buf) { free(s->buf); s->buf = NULL; }
    s->buflen = 0;
    if (s->sm1)
        return sm1_init(s->dev, s->key);
    return SAR_OK;
}

static ULONG sym_crypt(SYM_CTX *s, const BYTE *in, ULONG len, BYTE *out,
                       ULONG *outlen, int enc)
{
    const EVP_CIPHER *cipher = cipher_for(s->alg);
    EVP_CIPHER_CTX *ctx;
    int n1 = 0, n2 = 0;
    unsigned char iv[32];

    if (!cipher)
        return SAR_NOTSUPPORTYETERR;
    if (!out || !outlen)
        return SAR_INVALIDPARAMERR;
    if (s->param.IVLen > sizeof(iv))
        return SAR_INVALIDPARAMERR;
    memset(iv, 0, sizeof(iv));
    memcpy(iv, s->param.IV, s->param.IVLen);
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return SAR_FAIL;
    if (EVP_CipherInit_ex(ctx, cipher, NULL, s->key, iv, enc) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return SAR_FAIL;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    unsigned char padbuf[1024];
    if (enc && (len % 16) != 0 && len <= sizeof(padbuf)) {
        unsigned long plen = (len + 15) & ~15UL;
        memset(padbuf, 0, sizeof(padbuf));
        memcpy(padbuf, in, len);
        in = padbuf;
        len = plen;
    }
    if (EVP_CipherUpdate(ctx, out, &n1, in, (int)len) != 1 ||
        EVP_CipherFinal_ex(ctx, out + n1, &n2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return SAR_FAIL;
    }
    *outlen = (ULONG)(n1 + n2);
    EVP_CIPHER_CTX_free(ctx);
    return SAR_OK;
}

ULONG SKF_Encrypt(HANDLE hKey, BYTE *in, ULONG len, BYTE *out, ULONG *outlen)
{
    SYM_CTX *s = (SYM_CTX *)hKey;
    if (!s || s->type != 1 || !in)
        return SAR_INVALIDHANDLEERR;
    if (s->sm1) {
        if (!out || !outlen || (len % 16) != 0 || *outlen < len)
            return SAR_INVALIDPARAMERR;
        for (ULONG off = 0; off < len; off += 16) {
            ULONG rc = sm1_encrypt(s->dev, in + off, out + off);
            if (rc != SAR_OK)
                return rc;
        }
        *outlen = len;
        return SAR_OK;
    }
    return sym_crypt(s, in, len, out, outlen, 1);
}

ULONG SKF_Decrypt(HANDLE hKey, BYTE *in, ULONG len, BYTE *out, ULONG *outlen)
{
    SYM_CTX *s = (SYM_CTX *)hKey;
    if (!s || s->type != 1 || !in)
        return SAR_INVALIDHANDLEERR;
    return sym_crypt(s, in, len, out, outlen, 0);
}

ULONG SKF_EncryptUpdate(HANDLE hKey, BYTE *in, ULONG len, BYTE *out, ULONG *outlen)
{
    SYM_CTX *s = (SYM_CTX *)hKey;
    if (!s || s->type != 1 || !in)
        return SAR_INVALIDHANDLEERR;
    unsigned char *nb = realloc(s->buf, s->buflen + len);
    if (!nb)
        return SAR_FAIL;
    s->buf = nb;
    memcpy(s->buf + s->buflen, in, len);
    s->buflen += len;
    if (outlen)
        *outlen = 0;
    (void)out;
    return SAR_OK;
}

ULONG SKF_EncryptFinal(HANDLE hKey, BYTE *out, ULONG *outlen)
{
    SYM_CTX *s = (SYM_CTX *)hKey;
    if (!s || s->type != 1)
        return SAR_INVALIDHANDLEERR;
    if (s->sm1) {
        ULONG len = s->buflen;
        ULONG rc = SAR_OK;
        if (!out || !outlen || (len % 16) != 0 || *outlen < len) {
            rc = SAR_INVALIDPARAMERR;
        } else {
            for (ULONG off = 0; off < len; off += 16) {
                rc = sm1_encrypt(s->dev, s->buf + off, out + off);
                if (rc != SAR_OK) break;
            }
            if (rc == SAR_OK) *outlen = len;
        }
        free(s->buf); s->buf = NULL; s->buflen = 0;
        return rc;
    }
    ULONG rc = sym_crypt(s, s->buf, s->buflen, out, outlen, 1);
    free(s->buf);
    s->buf = NULL;
    s->buflen = 0;
    return rc;
}

ULONG SKF_DecryptInit(HANDLE hKey, BLOCKCIPHERPARAM p)
{
    SYM_CTX *s = (SYM_CTX *)hKey;
    if (!s || s->type != 1)
        return SAR_INVALIDHANDLEERR;
    s->param = p;
    s->initialized = 1;
    if (s->buf) { free(s->buf); s->buf = NULL; }
    s->buflen = 0;
    return SAR_OK;
}

ULONG SKF_DecryptUpdate(HANDLE hKey, BYTE *in, ULONG len, BYTE *out, ULONG *outlen)
{
    SYM_CTX *s = (SYM_CTX *)hKey;
    if (!s || s->type != 1 || !in)
        return SAR_INVALIDHANDLEERR;
    unsigned char *nb = realloc(s->buf, s->buflen + len);
    if (!nb)
        return SAR_FAIL;
    s->buf = nb;
    memcpy(s->buf + s->buflen, in, len);
    s->buflen += len;
    if (outlen)
        *outlen = 0;
    (void)out;
    return SAR_OK;
}

ULONG SKF_DecryptFinal(HANDLE hKey, BYTE *out, ULONG *outlen)
{
    SYM_CTX *s = (SYM_CTX *)hKey;
    if (!s || s->type != 1)
        return SAR_INVALIDHANDLEERR;
    ULONG rc = sym_crypt(s, s->buf, s->buflen, out, outlen, 0);
    free(s->buf);
    s->buf = NULL;
    s->buflen = 0;
    return rc;
}

ULONG SKF_DigestInit(DEVHANDLE hDev, ULONG alg, ECCPUBLICKEYBLOB *pub,
                     LPSTR id, ULONG idlen, HANDLE *phHash)
{
    (void)hDev; (void)pub; (void)id; (void)idlen;
    if (!phHash || alg != SGD_SM3)
        return SAR_NOTSUPPORTYETERR;
    HASH_CTX *h = calloc(1, sizeof(*h));
    if (!h)
        return SAR_FAIL;
    h->type = 3;
    h->ctx = EVP_MD_CTX_new();
    if (!h->ctx || EVP_DigestInit_ex(h->ctx, EVP_sm3(), NULL) != 1) {
        EVP_MD_CTX_free(h->ctx);
        free(h);
        return SAR_FAIL;
    }
    *phHash = (HANDLE)h;
    return SAR_OK;
}

ULONG SKF_Digest(HANDLE hHash, BYTE *in, ULONG len, BYTE *out, ULONG *outlen)
{
    HASH_CTX *h = (HASH_CTX *)hHash;
    if (!h || h->type != 3 || !out || !outlen)
        return SAR_INVALIDHANDLEERR;
    unsigned int n = 0;
    if (EVP_Digest(in, len, out, &n, EVP_sm3(), NULL) != 1)
        return SAR_FAIL;
    *outlen = n;
    return SAR_OK;
}

ULONG SKF_DigestUpdate(HANDLE hHash, BYTE *in, ULONG len)
{
    HASH_CTX *h = (HASH_CTX *)hHash;
    if (!h || h->type != 3)
        return SAR_INVALIDHANDLEERR;
    return EVP_DigestUpdate(h->ctx, in, len) == 1 ? SAR_OK : SAR_FAIL;
}

ULONG SKF_DigestFinal(HANDLE hHash, BYTE *out, ULONG *outlen)
{
    HASH_CTX *h = (HASH_CTX *)hHash;
    if (!h || h->type != 3 || !out || !outlen)
        return SAR_INVALIDHANDLEERR;
    unsigned int n = 0;
    if (EVP_DigestFinal_ex(h->ctx, out, &n) != 1)
        return SAR_FAIL;
    *outlen = n;
    return SAR_OK;
}

ULONG SKF_MacInit(HANDLE hKey, BLOCKCIPHERPARAM *p, HANDLE *phMac)
{
    SYM_CTX *k = (SYM_CTX *)hKey;
    if (!k || k->type != 1 || !phMac)
        return SAR_INVALIDHANDLEERR;
    SYM_CTX *m = calloc(1, sizeof(*m));
    if (!m)
        return SAR_FAIL;
    m->type = 2;
    m->alg = k->alg;
    m->keylen = k->keylen;
    memcpy(m->key, k->key, sizeof(m->key));
    if (p) m->param = *p;
    *phMac = (HANDLE)m;
    return SAR_OK;
}

static ULONG mac_compute(SYM_CTX *m, const BYTE *in, ULONG len, BYTE *out,
                         ULONG *outlen)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[16], buf[64];
    int n1 = 0, n2 = 0;
    ULONG padded = (len + 15) & ~15UL;
    if (padded > sizeof(buf))
        return SAR_NO_ROOM;
    memset(buf, 0, sizeof(buf));
    memcpy(buf, in, len);
    memset(iv, 0, sizeof(iv));
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return SAR_FAIL;
    if (EVP_EncryptInit_ex(ctx, EVP_sm4_cbc(), NULL, m->key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return SAR_FAIL;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (EVP_EncryptUpdate(ctx, buf, &n1, buf, (int)padded) != 1 ||
        EVP_EncryptFinal_ex(ctx, buf + n1, &n2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return SAR_FAIL;
    }
    EVP_CIPHER_CTX_free(ctx);
    memcpy(out, buf + padded - 16, 16);
    *outlen = 16;
    return SAR_OK;
}

ULONG SKF_Mac(HANDLE hMac, BYTE *in, ULONG len, BYTE *out, ULONG *outlen)
{
    SYM_CTX *m = (SYM_CTX *)hMac;
    if (!m || m->type != 2)
        return SAR_INVALIDHANDLEERR;
    return mac_compute(m, in, len, out, outlen);
}

ULONG SKF_MacUpdate(HANDLE hMac, BYTE *in, ULONG len)
{
    SYM_CTX *m = (SYM_CTX *)hMac;
    if (!m || m->type != 2)
        return SAR_INVALIDHANDLEERR;
    unsigned char *nb = realloc(m->buf, m->buflen + len);
    if (!nb)
        return SAR_FAIL;
    m->buf = nb;
    memcpy(m->buf + m->buflen, in, len);
    m->buflen += len;
    return SAR_OK;
}

ULONG SKF_MacFinal(HANDLE hMac, BYTE *out, ULONG *outlen)
{
    SYM_CTX *m = (SYM_CTX *)hMac;
    if (!m || m->type != 2)
        return SAR_INVALIDHANDLEERR;
    ULONG rc = mac_compute(m, m->buf, m->buflen, out, outlen);
    free(m->buf);
    m->buf = NULL;
    m->buflen = 0;
    return rc;
}

ULONG SKF_CloseHandle(HANDLE h)
{
    SYM_CTX *s = (SYM_CTX *)h;
    if (!h)
        return SAR_INVALIDHANDLEERR;
    if (s->type == 1 || s->type == 2) {
        free(s->buf);
        free(s);
        return SAR_OK;
    }
    if (s->type == 3) {
        HASH_CTX *hc = (HASH_CTX *)h;
        EVP_MD_CTX_free(hc->ctx);
        free(hc);
        return SAR_OK;
    }
    if (s->type == 4) {
        AGREE_CTX *a = (AGREE_CTX *)h;
        EC_KEY_free(a->eph);
        free(a);
        return SAR_OK;
    }
    return SAR_INVALIDHANDLEERR;
}

/* Per-container certificate EFs:
 *   0x1401 + (slot - 0x1101)  encryption certificate
 *   0x1501 + (slot - 0x1101)  signing certificate
 * This matches the vendor library and SKF_DeleteContainer(). */
static unsigned short cert_ef(const CTN_CTX *c, BOOL sign)
{
    unsigned short slot = c->file_id;
    if (slot < 0x1101 || slot > 0x1105)
        slot = 0x1101;
    return (unsigned short)((sign ? 0x1501 : 0x1401) + (slot - 0x1101));
}

ULONG SKF_ExportCertificate(HCONTAINER hCtn, BOOL sign, BYTE *cert, ULONG *len)
{
    CTN_CTX *c = (CTN_CTX *)hCtn;
    unsigned char fci[256];
    unsigned char *buf = NULL;
    unsigned long flen = sizeof(fci);
    unsigned long n = 0;
    unsigned short file;
    ULONG rc, size = 0;
    if (!c || !c->app || !c->app->dev || !cert || !len)
        return SAR_INVALIDPARAMERR;
    select_app(c->app->dev, c->app->id);
    select_file(c->app->dev, c->key_file, 2);
    file = cert_ef(c, sign);
    rc = select_file_data(c->app->dev, file, 0, fci, &flen);
    if (rc != SAR_OK)
        return rc == SAR_FILE_NOT_EXIST ? SAR_CERTNOTFOUNTERR : rc;
    if (fci_size(fci, flen, &size) != SAR_OK || size == 0)
        size = *len;
    if (size > *len) {
        *len = size;
        return SAR_BUFFER_TOO_SMALL;
    }
    buf = malloc(size);
    if (!buf)
        return SAR_MEMORYERR;
    n = size;
    rc = read_file(c->app->dev, file, 0, buf, &n);
    if (rc != SAR_OK) {
        free(buf);
        return rc;
    }
    memcpy(cert, buf, n);
    *len = (ULONG)n;
    free(buf);
    return SAR_OK;
}
static void cert_coord32(const unsigned char *coord, unsigned char out[32])
{
    int nz = 0;
    for (int i = 0; i < 32; i++)
        if (coord[i]) nz = 1;
    memcpy(out, coord + (nz ? 0 : 32), 32);
}

static ULONG ecc_pub_bytes(CTN_CTX *c, BOOL sign, unsigned char out[64]);

static int cert_key_matches(CTN_CTX *c, BOOL sign,
                            const unsigned char *cert, ULONG len)
{
    const unsigned char *p = cert;
    X509 *x = d2i_X509(NULL, &p, (long)len);
    if (!x)
        return 0;
    EVP_PKEY *pk = X509_get_pubkey(x);
    int ok = 0;
    if (!pk) {
        X509_free(x);
        return 0;
    }
    if (getenv("SKF_DEBUG"))
        fprintf(stderr, "cert_key_matches: pkey=%p id=%d rsa_soft=%p rsa_bits=%lu ecc=%d\n",
                (void *)pk, pk ? EVP_PKEY_base_id(pk) : -1,
                (void *)c->rsa_priv_soft, c->rsa_bits, c->ecc_priv_valid);
    if (pk && (c->rsa_priv_soft || c->rsa_bits)) {
        RSA *r = EVP_PKEY_get1_RSA(pk);
        if (r) {
            const BIGNUM *n = NULL;
            RSA_get0_key(r, &n, NULL, NULL);
            unsigned char be[256];
            int mlen = BN_num_bytes(n);
            if (mlen > 0 && mlen <= 256) {
                BN_bn2bin(n, be);
                if (c->rsa_priv_soft) {
                    int off = MAX_RSA_MODULUS_LEN - mlen;
                    ok = memcmp(c->rsa_priv_soft->Modulus + off, be, mlen) == 0;
                } else {
                    unsigned char rev[256];
                    for (int i = 0; i < mlen; i++)
                        rev[i] = c->rsa_mod[MAX_RSA_MODULUS_LEN - 1 - i];
                    ok = memcmp(rev, be, mlen) == 0;
                }
            }
            RSA_free(r);
        }
    } else {
        BIGNUM *xbn = NULL, *ybn = NULL;
        unsigned char cx[32], cy[32], ax[32], ay[32];
        int coord = 0;
        int gx = EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_PUB_X, &xbn);
        int gy = EVP_PKEY_get_bn_param(pk, OSSL_PKEY_PARAM_EC_PUB_Y, &ybn);
        if (getenv("SKF_DEBUG"))
            fprintf(stderr, "cert_key_matches: getx=%d gety=%d\n", gx, gy);
        if (gx == 1 && gy == 1) {
            BN_bn2binpad(xbn, cx, 32);
            BN_bn2binpad(ybn, cy, 32);
            coord = 1;
        } else {
            EC_KEY *k = EVP_PKEY_get1_EC_KEY(pk);
            if (k) {
                const EC_GROUP *g = EC_KEY_get0_group(k);
                const EC_POINT *pt = EC_KEY_get0_public_key(k);
                BN_free(xbn);
                BN_free(ybn);
                xbn = BN_new(); ybn = BN_new();
                if (xbn && ybn && g && pt &&
                    EC_POINT_get_affine_coordinates(g, pt, xbn, ybn,
                                                    NULL) == 1) {
                    BN_bn2binpad(xbn, cx, 32);
                    BN_bn2binpad(ybn, cy, 32);
                    coord = 1;
                }
                EC_KEY_free(k);
            }
        }
        if (coord) {
            if (getenv("SKF_DEBUG"))
                fprintf(stderr, "cert EC cx=%02x%02x cy=%02x%02x ecc=%d\n",
                        cx[0], cx[1], cy[0], cy[1], c->ecc_priv_valid);
            if (c->ecc_priv_valid) {
                cert_coord32(c->ecc_pub_soft.XCoordinate, ax);
                cert_coord32(c->ecc_pub_soft.YCoordinate, ay);
                ok = memcmp(cx, ax, 32) == 0 &&
                     memcmp(cy, ay, 32) == 0;
                if (getenv("SKF_DEBUG"))
                    fprintf(stderr, "software EC ax=%02x%02x ay=%02x%02x ok=%d\n",
                            ax[0], ax[1], ay[0], ay[1], ok);
            } else {
                unsigned char xy[64];
                ULONG erc = ecc_pub_bytes(c, sign, xy);
                if (erc == SAR_OK) {
                    rev_words32(xy, ax);
                    rev_words32(xy + 32, ay);
                    ok = memcmp(cx, ax, 32) == 0 &&
                         memcmp(cy, ay, 32) == 0;
                    if (getenv("SKF_DEBUG"))
                        fprintf(stderr, "device EC ax=%02x%02x ay=%02x%02x ok=%d\n",
                                ax[0], ax[1], ay[0], ay[1], ok);
                }
            }
        }
        BN_free(xbn);
        BN_free(ybn);
    }
    EVP_PKEY_free(pk);
    X509_free(x);
    return ok;
}

ULONG SKF_ImportCertificate(HCONTAINER hCtn, BOOL sign, BYTE *cert, ULONG len)
{
    CTN_CTX *c = (CTN_CTX *)hCtn;
    unsigned char attr[12] = {0x01,0x0f,0x0f,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    unsigned short file;
    ULONG rc;
    if (!c || !c->app || !c->app->dev)
        return SAR_INVALIDHANDLEERR;
    if (!cert || !len)
        return SAR_INDATAERR;
    if (len > 0xffff)
        return SAR_INDATAERR;
    if (!cert_key_matches(c, sign, cert, len))
        return SAR_OBJERR;
    file = cert_ef(c, sign);
    attr[6] = (unsigned char)(len >> 8);
    attr[7] = (unsigned char)len;
    select_app(c->app->dev, c->app->id);
    select_file(c->app->dev, c->key_file, 2);
    delete_ef(c->app->dev, file);
    rc = create_ef_len(c->app->dev, file, attr, sizeof(attr));
    if (rc != SAR_OK)
        return rc;
    rc = select_file(c->app->dev, file, 2);
    if (rc != SAR_OK)
        return rc;
    return write_selected(c->app->dev, cert, len);
}
static ULONG ecc_pub_bytes(CTN_CTX *c, BOOL sign, unsigned char out[64])
{
    unsigned char cmd[72];
    unsigned char buf[128];
    unsigned long n = sizeof(buf);
    ULONG rc;
    (void)sign;
    rc = select_file(c->app->dev, c->key_file, 2);
    if (rc != SAR_OK)
        return rc == SAR_FILE_NOT_EXIST ? SAR_KEYNOTFOUNTERR : rc;
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x57;
    put_be32(cmd + 4, 0x40);
    rc = apdu(c->app->dev, cmd, sizeof(cmd), buf, &n);
    if (rc != SAR_OK)
        return rc == SAR_FILE_NOT_EXIST ? SAR_KEYNOTFOUNTERR : rc;
    if (n < 64)
        return SAR_FAIL;
    memcpy(out, buf, 64);
    return SAR_OK;
}

ULONG SKF_ExportPublicKey(HCONTAINER hCtn, BOOL sign, BYTE *blob, ULONG *len)
{
    CTN_CTX *c = (CTN_CTX *)hCtn;
    ECCPUBLICKEYBLOB *pub = (ECCPUBLICKEYBLOB *)blob;
    unsigned char xy[64];
    ULONG rc;
    if (!c || !blob || !len || *len < sizeof(ECCPUBLICKEYBLOB))
        return SAR_INVALIDPARAMERR;
    if (c->ecc_priv_valid) {
        memcpy(pub, &c->ecc_pub_soft, sizeof(*pub));
        *len = sizeof(*pub);
        return SAR_OK;
    }
    rc = ecc_pub_bytes(c, sign, xy);
    if (rc != SAR_OK)
        return rc;
    memset(pub, 0, sizeof(*pub));
    pub->BitLen = 256;
    rev_words32(xy, pub->XCoordinate + 32);
    rev_words32(xy + 32, pub->YCoordinate + 32);
    *len = sizeof(ECCPUBLICKEYBLOB);
    return SAR_OK;
}
ULONG SKF_GenECCKeyPair(HCONTAINER hCtn, ULONG alg, ECCPUBLICKEYBLOB *blob)
{
    CTN_CTX *c = (CTN_CTX *)hCtn;
    unsigned char cmd[72], buf[128];
    unsigned long n = sizeof(buf);
    ULONG rc;
    if (!c || !blob)
        return SAR_INVALIDPARAMERR;
    if (alg != SGD_SM2 && alg != SGD_SM2_1 && alg != SGD_SM2_2 &&
        alg != SGD_SM2_3)
        return SAR_INVALIDPARAMERR;
    select_file(c->app->dev, c->key_file, 2);
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x55;
    rc = apdu(c->app->dev, cmd, 8, buf, &n);
    if (rc != SAR_OK)
        return rc;
    n = sizeof(buf);
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x57;
    put_be32(cmd + 4, 0x40);
    rc = apdu(c->app->dev, cmd, sizeof(cmd), buf, &n);
    if (rc != SAR_OK || n < 64)
        return rc == SAR_OK ? SAR_FAIL : rc;
    memset(blob, 0, sizeof(*blob));
    blob->BitLen = 256;
    rev_words32(buf, blob->XCoordinate + 32);
    rev_words32(buf + 32, blob->YCoordinate + 32);
    ctn_clear_ecc(c);
    ctn_clear_rsa(c);
    return SAR_OK;
}
ULONG SKF_GenRSAKeyPair(HCONTAINER hCtn, ULONG bits, RSAPUBLICKEYBLOB *blob)
{
    CTN_CTX *c = (CTN_CTX *)hCtn;
    unsigned char cmd[136], buf[256];
    unsigned long n = sizeof(buf);
    ULONG rc;
    if (!c || !blob || bits != 1024)
        return SAR_INVALIDPARAMERR;
    static const unsigned char rsa_attr[12] =
        {0x19,0x23,0x23,0x00,0x00,0x00,0x02,0xc8,0x00,0x00,0x00,0x00};
    delete_ef(c->app->dev, c->key_file);
    create_ef(c->app->dev, c->key_file, rsa_attr);
    if (c->app->dev->user_pin[0])
        pin_verify(c->app->dev, c->app->id, USER_TYPE,
                   c->app->dev->user_pin, NULL);
    select_file(c->app->dev, c->key_file, 2);
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x50; cmd[2] = 0x00; cmd[3] = 0x30;
    rc = apdu(c->app->dev, cmd, 8, buf, &n);
    if (rc != SAR_OK)
        return rc;
    n = sizeof(buf);
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x51; cmd[2] = 0x01;
    put_be32(cmd + 4, 0x80);
    rc = apdu(c->app->dev, cmd, 8 + 0x80, buf, &n);
    if (rc != SAR_OK || n < 128)
        return rc == SAR_OK ? SAR_FAIL : rc;
    memset(blob, 0, sizeof(*blob));
    blob->AlgID = SGD_RSA;
    blob->BitLen = 1024;
    memcpy(c->rsa_mod + (MAX_RSA_MODULUS_LEN - 128), buf, 128);
    c->rsa_bits = 1024;
    for (int i = 0; i < 128; i++)
        blob->Modulus[MAX_RSA_MODULUS_LEN - 1 - i] = buf[i];
    blob->PublicExponent[0] = 0x00; blob->PublicExponent[1] = 0x01;
    blob->PublicExponent[2] = 0x00; blob->PublicExponent[3] = 0x01;
    ctn_clear_ecc(c);
    free(c->rsa_priv_soft);
    c->rsa_priv_soft = NULL;
    return SAR_OK;
}
ULONG SKF_ImportECCKeyPair(HCONTAINER hCtn, ENVELOPEDKEYBLOB *blob)
{
    CTN_CTX *c = (CTN_CTX *)hCtn;
    if (!c || !c->app || !c->app->dev || !blob)
        return SAR_INVALIDPARAMERR;
    if (blob->PubKey.BitLen != 256)
        return SAR_INVALIDPARAMERR;

    if (blob->ECCCipherBlob.CipherLen != 0) {
        /* Vendor standard ENVELOPEDKEYBLOB: the ECCCipherBlob wraps a
         * session key with the container public key, and cbEncryptedPriKey
         * is the private key encrypted with that session key. */
        if (!c->ecc_priv_valid)
            return SAR_NOTSUPPORTYETERR;
        unsigned char sess[256];
        ULONG sesslen = sizeof(sess);
        int sm2r = sm2_decrypt_std(c->ecc_priv, &blob->ECCCipherBlob,
                                   sess, &sesslen);
        if (sm2r != 0 || sesslen < 16)
            return SAR_INVALIDPARAMERR;
        int bits = blob->ulBits ? (int)blob->ulBits : 256;
        int plen = bits / 8;
        if (plen <= 0 || plen > 32)
            plen = 32;
        unsigned char priv[64];
        ULONG outlen = 0;
        int found = 0;
        for (int off = 32; off >= 0 && !found; off -= 32) {
            outlen = sizeof(priv);
            int sr = sym_decrypt_std(blob->ulSymmAlgID, sess,
                                     blob->cbEncryptedPriKey + off,
                                     (ULONG)plen, priv, &outlen);
            if (sr != 0)
                continue;
            if (outlen >= 32 && ecc_priv_matches(priv, &blob->PubKey)) {
                memcpy(c->ecc_priv, priv, 32);
                found = 1;
            } else if (outlen >= 32) {
                unsigned char rev[32];
                for (int i = 0; i < 32; i++)
                    rev[i] = priv[31 - i];
                if (ecc_priv_matches(rev, &blob->PubKey)) {
                    memcpy(c->ecc_priv, rev, 32);
                    found = 1;
                }
            }
        }
        if (!found)
            return SAR_INVALIDPARAMERR;
        ctn_clear_rsa(c);
        c->ecc_pub_soft = blob->PubKey;
        c->ecc_priv_valid = 1;
        return SAR_OK;
    }

    /* Native extension: cbEncryptedPriKey[0..31] is the plain SM2 scalar. */
    int nonzero = 0;
    for (int i = 0; i < 32; i++)
        if (blob->cbEncryptedPriKey[i])
            nonzero = 1;
    if (!nonzero)
        return SAR_NOTSUPPORTYETERR;
    memset(c->ecc_priv, 0, sizeof(c->ecc_priv));
    memcpy(c->ecc_priv, blob->cbEncryptedPriKey, 32);
    c->ecc_pub_soft = blob->PubKey;
    c->ecc_priv_valid = 1;
    return SAR_OK;
}

static RSA *rsa_from_blob(const RSAPRIVATEKEYBLOB *b)
{
    RSA *r = RSA_new();
    if (!r)
        return NULL;
    BIGNUM *n = BN_bin2bn(b->Modulus, MAX_RSA_MODULUS_LEN, NULL);
    BIGNUM *e = BN_bin2bn(b->PublicExponent, MAX_RSA_EXPONENT_LEN, NULL);
    BIGNUM *d = BN_bin2bn(b->PrivateExponent, MAX_RSA_MODULUS_LEN, NULL);
    if (!n || !e || !d || RSA_set0_key(r, n, e, d) != 1) {
        BN_free(n); BN_free(e); BN_free(d);
        RSA_free(r);
        return NULL;
    }
    return r;
}

static void rsa_to_blob(RSA *r, RSAPRIVATEKEYBLOB *b)
{
    const BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
    memset(b, 0, sizeof(*b));
    b->AlgID = SGD_RSA;
    RSA_get0_key(r, &n, &e, &d);
    RSA_get0_factors(r, &p, &q);
    RSA_get0_crt_params(r, &dmp1, &dmq1, &iqmp);
    b->BitLen = (ULONG)BN_num_bits(n);
    BN_bn2binpad(e, b->PublicExponent, MAX_RSA_EXPONENT_LEN);
    BN_bn2binpad(n, b->Modulus + MAX_RSA_MODULUS_LEN - BN_num_bytes(n),
                 BN_num_bytes(n));
    BN_bn2binpad(d, b->PrivateExponent, MAX_RSA_MODULUS_LEN);
    if (p) BN_bn2binpad(p, b->Prime1, MAX_RSA_MODULUS_LEN / 2);
    if (q) BN_bn2binpad(q, b->Prime2, MAX_RSA_MODULUS_LEN / 2);
    if (dmp1) BN_bn2binpad(dmp1, b->Prime1Exponent, MAX_RSA_MODULUS_LEN / 2);
    if (dmq1) BN_bn2binpad(dmq1, b->Prime2Exponent, MAX_RSA_MODULUS_LEN / 2);
    if (iqmp) BN_bn2binpad(iqmp, b->Coefficient, MAX_RSA_MODULUS_LEN / 2);
}

ULONG SKF_ImportRSAKeyPair(HCONTAINER hCtn, ULONG bits, BYTE *pri, ULONG prilen,
                           BYTE *pub, ULONG publen)
{
    CTN_CTX *c = (CTN_CTX *)hCtn;
    if (!c || !c->app || !c->app->dev || !pri || !prilen)
        return SAR_INVALIDPARAMERR;

    if (pub && publen) {
        if (!c->rsa_priv_soft)
            return SAR_NOTSUPPORTYETERR;
        RSA *rsa = rsa_from_blob(c->rsa_priv_soft);
        if (!rsa)
            return SAR_INVALIDPARAMERR;
        unsigned char sess[512];
        int slen = RSA_private_decrypt((int)publen, pub, sess, rsa,
                                       RSA_PKCS1_PADDING);
        if (slen <= 0)
            slen = RSA_private_decrypt((int)publen, pub, sess, rsa,
                                       RSA_NO_PADDING);
        RSA_free(rsa);
        if (slen <= 0)
            return SAR_INVALIDPARAMERR;
        const unsigned char *sk = sess;
        if (slen > 16)
            sk = sess + slen - 16;

        unsigned char *dec = malloc(prilen + 256);
        if (!dec)
            return SAR_MEMORYERR;
        ULONG declen = prilen + 256;
        int ok = sym_decrypt_std(bits, sk, pri, prilen, dec, &declen) == 0;
        RSAPRIVATEKEYBLOB *blob = NULL;
        RSAPRIVATEKEYBLOB parsed;
        if (ok) {
            if (declen >= sizeof(RSAPRIVATEKEYBLOB)) {
                memcpy(&parsed, dec, sizeof(parsed));
                if (parsed.AlgID == SGD_RSA && parsed.BitLen >= 512 &&
                    parsed.BitLen <= 2048)
                    blob = &parsed;
            }
            if (!blob) {
                const unsigned char *p = dec;
                RSA *r = d2i_RSAPrivateKey(NULL, &p, (long)declen);
                if (r) {
                    rsa_to_blob(r, &parsed);
                    RSA_free(r);
                    blob = &parsed;
                }
            }
        } else if (prilen >= sizeof(RSAPRIVATEKEYBLOB)) {
            memcpy(&parsed, pri, sizeof(parsed));
            if (parsed.AlgID == SGD_RSA && parsed.BitLen >= 512 &&
                parsed.BitLen <= 2048)
                blob = &parsed;
        }
        free(dec);
        if (!blob)
            return SAR_INVALIDPARAMERR;
        RSAPRIVATEKEYBLOB *copy = malloc(sizeof(*copy));
        if (!copy)
            return SAR_MEMORYERR;
        memcpy(copy, blob, sizeof(*copy));
        free(c->rsa_priv_soft);
        c->rsa_priv_soft = copy;
        c->rsa_bits = copy->BitLen;
        memset(c->rsa_mod, 0, sizeof(c->rsa_mod));
        memcpy(c->rsa_mod, copy->Modulus, sizeof(c->rsa_mod));
        ctn_clear_ecc(c);
        return SAR_OK;
    }

    /* Native extension: pbWrappedKey points directly at a private blob. */
    if (prilen < sizeof(RSAPRIVATEKEYBLOB))
        return SAR_NOTSUPPORTYETERR;
    RSAPRIVATEKEYBLOB *b = (RSAPRIVATEKEYBLOB *)pri;
    if (b->BitLen == 0 || b->BitLen > MAX_RSA_MODULUS_LEN * 8)
        return SAR_INVALIDPARAMERR;
    RSAPRIVATEKEYBLOB *copy = malloc(sizeof(*copy));
    if (!copy)
        return SAR_MEMORYERR;
    memcpy(copy, b, sizeof(*copy));
    free(c->rsa_priv_soft);
    c->rsa_priv_soft = copy;
    c->rsa_bits = b->BitLen;
    memset(c->rsa_mod, 0, sizeof(c->rsa_mod));
    memcpy(c->rsa_mod, b->Modulus, sizeof(c->rsa_mod));
    ctn_clear_ecc(c);
    return SAR_OK;
}

static ULONG raw_rsa_priv(const BYTE *mod, const BYTE *exp, ULONG bits,
                          BYTE *in, ULONG len, BYTE *out, ULONG *outlen)
{
    BN_CTX *ctx = BN_CTX_new();
    ULONG mlen = bits / 8;
    if (mlen == 0 || mlen > MAX_RSA_MODULUS_LEN)
        mlen = MAX_RSA_MODULUS_LEN;
    BIGNUM *n = BN_bin2bn(mod + MAX_RSA_MODULUS_LEN - mlen, (int)mlen, NULL);
    BIGNUM *d = BN_bin2bn(exp, MAX_RSA_MODULUS_LEN, NULL);
    BIGNUM *m = BN_bin2bn(in, (int)len, NULL);
    BIGNUM *r = BN_new();
    ULONG need = mlen;
    if (!ctx || !n || !d || !m || !r || !out || !outlen || *outlen < need) {
        BN_CTX_free(ctx); BN_free(n); BN_free(d); BN_free(m); BN_free(r);
        return SAR_INVALIDPARAMERR;
    }
    BN_mod_exp(r, m, d, n, ctx);
    BN_bn2binpad(r, out, (int)need);
    *outlen = need;
    BN_CTX_free(ctx); BN_free(n); BN_free(d); BN_free(m); BN_free(r);
    return SAR_OK;
}

ULONG SKF_RSASignData(HCONTAINER hCtn, BYTE *digest, ULONG len, BYTE *sig, ULONG *siglen)
{
    CTN_CTX *c = (CTN_CTX *)hCtn;
    unsigned char input[128], r54[128], cmd[136], buf[256], exp[256];
    unsigned long n;
    ULONG rc;
    if (!c || !digest || !sig || !siglen || len != 32)
        return SAR_INVALIDPARAMERR;
    memset(input, 0, sizeof(input));
    for (int i = 0; i < 8; i++)
        memcpy(input + 4*i, digest + 4*(7-i), 4);
    if (c->rsa_priv_soft) {
        unsigned char sig_be[256];
        ULONG slen = sizeof(sig_be);
        ULONG rc = raw_rsa_priv(c->rsa_priv_soft->Modulus,
                                c->rsa_priv_soft->PrivateExponent,
                                c->rsa_priv_soft->BitLen, input, 128,
                                sig_be, &slen);
        if (rc != SAR_OK)
            return rc;
        if (*siglen < slen)
            return SAR_INVALIDPARAMERR;
        memcpy(sig, sig_be, slen);
        *siglen = slen;
        return SAR_OK;
    }
    if (c->app->dev->user_pin[0])
        pin_verify(c->app->dev, c->app->id, USER_TYPE,
                   c->app->dev->user_pin, NULL);
    select_file(c->app->dev, c->key_file, 2);
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x54;
    put_be32(cmd + 4, 0x80);
    memcpy(cmd + 8, input, 128);
    n = sizeof(buf);
    rc = apdu(c->app->dev, cmd, 8 + 128, r54, &n);
    if (rc != SAR_OK || n < 128)
        return rc == SAR_OK ? SAR_FAIL : rc;
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x52; cmd[2] = 0x01; cmd[3] = 0xb0;
    put_be32(cmd + 4, 0x80);
    memcpy(cmd + 8, c->rsa_mod + (MAX_RSA_MODULUS_LEN - 128), 128);
    n = 0;
    rc = apdu(c->app->dev, cmd, 8 + 128, buf, &n);
    if (rc != SAR_OK)
        return rc;
    memset(exp, 0, sizeof(exp));
    exp[0] = 0x00; exp[1] = 0x01; exp[2] = 0x00; exp[3] = 0x01;
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x52; cmd[2] = 0x02; cmd[3] = 0xb0;
    put_be32(cmd + 4, 0x80);
    memcpy(cmd + 8, exp, 128);
    n = 0;
    rc = apdu(c->app->dev, cmd, 8 + 128, buf, &n);
    if (rc != SAR_OK)
        return rc;
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x53; cmd[3] = 0x80;
    put_be32(cmd + 4, 0x80);
    memcpy(cmd + 8, r54, 128);
    n = sizeof(buf);
    rc = apdu(c->app->dev, cmd, 8 + 128, buf, &n);
    if (rc != SAR_OK || n < 128)
        return rc == SAR_OK ? SAR_FAIL : rc;
    if (*siglen < 128)
        return SAR_INVALIDPARAMERR;
    memcpy(sig, r54, 128);
    *siglen = 128;
    return SAR_OK;
}
static int rsa_host_verify_any(RSAPUBLICKEYBLOB *pub, BYTE *sig, ULONG siglen,
                               const unsigned char *want, ULONG mlen)
{
    unsigned char mod_rev[256], sig_rev[256], em[256];
    memset(mod_rev, 0, sizeof(mod_rev));
    for (ULONG i = 0; i < mlen; i++)
        mod_rev[MAX_RSA_MODULUS_LEN - 1 - i] =
            pub->Modulus[MAX_RSA_MODULUS_LEN - mlen + i];
    for (int mo = 0; mo < 2; mo++) {
        const unsigned char *mod = mo ? mod_rev : pub->Modulus;
        for (int so = 0; so < 2; so++) {
            for (ULONG i = 0; i < mlen; i++)
                sig_rev[i] = so ? sig[mlen - 1 - i] : sig[i];
            ULONG outlen = sizeof(em);
            if (raw_rsa(mod, pub->PublicExponent, pub->BitLen,
                        sig_rev, mlen, em, &outlen) == SAR_OK &&
                outlen == mlen && memcmp(em, want, mlen) == 0)
                return 0;
        }
    }
    return -1;
}

ULONG SKF_RSAVerify(DEVHANDLE hDev, RSAPUBLICKEYBLOB *pub, BYTE *digest,
                    ULONG len, BYTE *sig, ULONG siglen)
{
    DEV_CTX *d = (DEV_CTX *)hDev;
    unsigned char want[256], mod[128], exp[128], out[256];
    unsigned char cmd[136];
    unsigned long n = sizeof(out);
    ULONG rc;
    if (!d || !pub || !digest || !sig || len != 32)
        return SAR_INVALIDPARAMERR;
    ULONG mlen = pub->BitLen / 8;
    if (mlen == 0 || mlen > MAX_RSA_MODULUS_LEN)
        return SAR_INVALIDPARAMERR;
    if (siglen != mlen)
        return SAR_INVALIDPARAMERR;
    memset(want, 0, sizeof(want));
    for (ULONG i = 0; i < len; i += 4)
        memcpy(want + i, digest + len - 4 - i, 4);
    for (ULONG i = 0; i < mlen; i++)
        mod[i] = pub->Modulus[MAX_RSA_MODULUS_LEN - 1 - i];
    memset(exp, 0, sizeof(exp));
    memcpy(exp, pub->PublicExponent, MAX_RSA_EXPONENT_LEN);

    rc = (mlen <= 128) ? select_file(d, 0x3f00, 0) : SAR_INVALIDPARAMERR;
    if (rc == SAR_OK && mlen <= 128) {
        memset(cmd, 0, sizeof(cmd));
        cmd[0] = 0x80; cmd[1] = 0x52; cmd[2] = 0x01; cmd[3] = 0xb0;
        put_be32(cmd + 4, 0x80);
        memcpy(cmd + 8, mod, 128);
        rc = apdu(d, cmd, 8 + 128, NULL, NULL);
    }
    if (rc == SAR_OK) {
        memset(cmd, 0, sizeof(cmd));
        cmd[0] = 0x80; cmd[1] = 0x52; cmd[2] = 0x02; cmd[3] = 0xb0;
        put_be32(cmd + 4, 0x80);
        memcpy(cmd + 8, exp, 128);
        rc = apdu(d, cmd, 8 + 128, NULL, NULL);
    }
    if (rc == SAR_OK) {
        memset(cmd, 0, sizeof(cmd));
        cmd[0] = 0x80; cmd[1] = 0x53; cmd[3] = 0x80;
        put_be32(cmd + 4, 0x80);
        memcpy(cmd + 8, sig, mlen);
        rc = apdu(d, cmd, 8 + 128, out, &n);
        if (rc == SAR_OK && n >= mlen && memcmp(out, want, mlen) == 0)
            return SAR_OK;
    }
    if (rsa_host_verify_any(pub, sig, siglen, want, mlen) == 0)
        return SAR_OK;
    return SAR_INVALIDPARAMERR;
}
ULONG SKF_ECCSignData(HCONTAINER hCtn, BYTE *digest, ULONG len, ECCSIGNATUREBLOB *sig)
{
    CTN_CTX *c = (CTN_CTX *)hCtn;
    unsigned char cmd[512];
    unsigned char buf[128];
    unsigned long n = sizeof(buf);
    ULONG rc;
    if (!c || !digest || !sig || len != 32)
        return SAR_INVALIDPARAMERR;
    if (c->ecc_priv_valid) {
        memset(sig, 0, sizeof(*sig));
        if (sm2_sign_digest(c->ecc_priv, digest,
                            sig->r + 32, sig->s + 32) != 0)
            return SAR_FAIL;
        return SAR_OK;
    }
    if (getenv("SKF_DEBUG"))
        fprintf(stderr, "sign: user_pin='%s' logged=%d keyfile=%04x\n",
                c->app->dev->user_pin, c->app->dev->user_logged, c->key_file);
    select_file(c->app->dev, c->key_file, 2);
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x56; cmd[2] = 0x01;
    put_be32(cmd + 4, 0x20);
    memcpy(cmd + 8, digest, 32);
    rc = apdu(c->app->dev, cmd, 8 + 32, buf, &n);
    if (rc == SAR_USER_NOT_LOGGED_IN && c->app->dev->user_pin[0]) {
        ULONG pr = pin_verify(c->app->dev, c->app->id, USER_TYPE,
                              c->app->dev->user_pin, NULL);
        if (getenv("SKF_DEBUG"))
            fprintf(stderr, "sign retry pin_verify rc=%lx pin=%s\n",
                    (unsigned long)pr, c->app->dev->user_pin);
        select_file(c->app->dev, c->key_file, 2);
        n = sizeof(buf);
        rc = apdu(c->app->dev, cmd, 8 + 32, buf, &n);
    }
    if (rc != SAR_OK || n < 64)
        return rc == SAR_OK ? SAR_FAIL : rc;
    memset(sig, 0, sizeof(*sig));
    rev_words32(buf, sig->r + 32);
    rev_words32(buf + 32, sig->s + 32);
    return SAR_OK;
}
static void rev_words32(const unsigned char in[32], unsigned char out[32])
{
    for (int i = 0; i < 8; i++)
        memcpy(out + 4 * i, in + 4 * (7 - i), 4);
}

static ULONG select_ecc_app(DEV_CTX *d)
{
    ULONG rc = select_file(d, 0x3f00, 0);
    if (rc != SAR_OK)
        return rc;
    return select_file(d, d->app_id ? d->app_id : 0x2000, 1);
}

static ULONG ecc_verify_dev(DEV_CTX *d, ECCPUBLICKEYBLOB *pub,
                            BYTE *digest, ULONG len, ECCSIGNATUREBLOB *sig)
{
    unsigned char xy[64], cmd[512], buf[128];
    unsigned long n = sizeof(buf);
    ULONG rc;
    if (!d || !pub || !digest || !sig || len != 32)
        return SAR_INVALIDPARAMERR;
    rc = select_ecc_app(d);
    if (rc != SAR_OK)
        return rc;
    rev_words32(pub->XCoordinate + 32, xy);
    rev_words32(pub->YCoordinate + 32, xy + 32);
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x58; cmd[3] = 0x80;
    put_be32(cmd + 4, 0x40);
    memcpy(cmd + 8, xy, 64);
    rc = apdu(d, cmd, 8 + 64, buf, &n);
    if (rc != SAR_OK)
        return rc;
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x56; cmd[2] = 0x02; cmd[3] = 0x80;
    put_be32(cmd + 4, 0x60);
    memcpy(cmd + 8, digest, 32);
    rev_words32(sig->r + 32, cmd + 40);
    rev_words32(sig->s + 32, cmd + 72);
    n = sizeof(buf);
    rc = apdu(d, cmd, 8 + 96, buf, &n);
    return rc;
}

ULONG SKF_ECCVerify(DEVHANDLE hDev, ECCPUBLICKEYBLOB *pub, BYTE *digest,
                    ULONG len, ECCSIGNATUREBLOB *sig)
{
    return ecc_verify_dev((DEV_CTX *)hDev, pub, digest, len, sig);
}
ULONG SKF_ExtECCEncrypt(DEVHANDLE hDev, ECCPUBLICKEYBLOB *pub, BYTE *in,
                        ULONG len, ECCCIPHERBLOB *out)
{
    DEV_CTX *d = (DEV_CTX *)hDev;
    unsigned char xy[64], cmd[512], buf[256];
    unsigned long n = sizeof(buf);
    ULONG rc;
    if (!d || !pub || !in || !out)
        return SAR_INVALIDPARAMERR;
    if (pub->BitLen != 256)
        return SAR_NOTSUPPORTYETERR;
    rc = select_ecc_app(d);
    if (rc != SAR_OK)
        return rc;
    rev_words32(pub->XCoordinate + 32, xy);
    rev_words32(pub->YCoordinate + 32, xy + 32);
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x58; cmd[3] = 0x80;
    put_be32(cmd + 4, 0x40);
    memcpy(cmd + 8, xy, 64);
    rc = apdu(d, cmd, 8 + 64, buf, &n);
    if (rc != SAR_OK)
        return rc;
    memset(cmd, 0, sizeof(cmd));
    cmd[0] = 0x80; cmd[1] = 0x56; cmd[2] = 0x03; cmd[3] = 0x80;
    put_be32(cmd + 4, len);
    memcpy(cmd + 8, in, len);
    n = sizeof(buf);
    rc = apdu(d, cmd, 8 + len, buf, &n);
    if (rc != SAR_OK)
        return rc;
    memset(out, 0, sizeof(*out));
    if (n < 96)
        return SAR_FAIL;
    out->CipherLen = (ULONG)(n - 96);
    if (out->CipherLen > 256)
        out->CipherLen = 256;
    memcpy(out->XCoordinate + 32, buf, 32);
    memcpy(out->YCoordinate + 32, buf + 32, 32);
    memcpy(out->Cipher, buf + 64, out->CipherLen);
    memcpy(out->HASH, buf + 64 + out->CipherLen, 32);
    return SAR_OK;
}
ULONG SKF_ExtECCDecrypt(DEVHANDLE hDev, ECCPRIVATEKEYBLOB *pri, ECCCIPHERBLOB *in,
                        BYTE *out, ULONG *outlen)
{
    DEV_CTX *d = (DEV_CTX *)hDev;
    ULONG got;
    if (!d || !pri || !in || !out || !outlen)
        return SAR_INVALIDPARAMERR;
    if (pri->BitLen != 256)
        return SAR_NOTSUPPORTYETERR;
    if (in->CipherLen == 0 || in->CipherLen > 256)
        return SAR_INVALIDPARAMERR;
    if (*outlen < in->CipherLen)
        return SAR_INVALIDPARAMERR;
    got = *outlen;
    if (sm2_decrypt_std(pri->PrivateKey + 32, in, out, &got) != 0)
        return SAR_DECRYPTPADERR;
    *outlen = got;
    return SAR_OK;
}

ULONG SKF_ExtECCSign(DEVHANDLE hDev, ECCPRIVATEKEYBLOB *pri, BYTE *digest,
                     ULONG len, ECCSIGNATUREBLOB *sig)
{
    DEV_CTX *d = (DEV_CTX *)hDev;
    if (!d || !pri || !digest || !sig)
        return SAR_INVALIDPARAMERR;
    if (pri->BitLen != 256 || len != 32)
        return SAR_NOTSUPPORTYETERR;
    memset(sig, 0, sizeof(*sig));
    if (sm2_sign_digest(pri->PrivateKey + 32, digest,
                        sig->r + 32, sig->s + 32) != 0)
        return SAR_FAIL;
    return SAR_OK;
}

ULONG SKF_ExtECCVerify(DEVHANDLE hDev, ECCPUBLICKEYBLOB *pub, BYTE *digest,
                       ULONG len, ECCSIGNATUREBLOB *sig)
{
    DEV_CTX *d = (DEV_CTX *)hDev;
    if (!d || !pub || !digest || !sig)
        return SAR_INVALIDPARAMERR;
    if (pub->BitLen != 256 || len != 32)
        return SAR_NOTSUPPORTYETERR;
    return sm2_verify_digest(pub, digest, sig->r + 32, sig->s + 32) == 0
               ? SAR_OK : SAR_HASHNOTEQUALERR;
}

ULONG SKF_ECCExportSessionKey(HCONTAINER hCtn, ULONG alg, ECCPUBLICKEYBLOB *pub,
                              ECCCIPHERBLOB *cipher, HANDLE *phKey)
{
    CTN_CTX *c = (CTN_CTX *)hCtn;
    unsigned char key[16];
    ULONG rc;
    if (!c || !pub || !cipher || !phKey)
        return SAR_INVALIDPARAMERR;
    rc = SKF_GenRandom((DEVHANDLE)c->app->dev, key, sizeof(key));
    if (rc != SAR_OK)
        return rc;
    rc = SKF_ExtECCEncrypt((DEVHANDLE)c->app->dev, pub, key, sizeof(key), cipher);
    if (rc != SAR_OK)
        return rc;
    SYM_CTX *s = calloc(1, sizeof(*s));
    if (!s)
        return SAR_FAIL;
    s->type = 1;
    s->alg = alg;
    s->keylen = 16;
    memcpy(s->key, key, 16);
    *phKey = (HANDLE)s;
    return SAR_OK;
}
ULONG SKF_RSAExportSessionKey(HCONTAINER hCtn, ULONG alg, RSAPUBLICKEYBLOB *pub,
                              BYTE *data, ULONG *len, HANDLE *phKey)
{
    CTN_CTX *c = (CTN_CTX *)hCtn;
    unsigned char key[16];
    ULONG rc;
    if (!c || !pub || !data || !len || !phKey)
        return SAR_INVALIDPARAMERR;
    rc = SKF_GenRandom((DEVHANDLE)c->app->dev, key, sizeof(key));
    if (rc != SAR_OK)
        return rc;
    ULONG outlen = *len;
    rc = raw_rsa(pub->Modulus, pub->PublicExponent, pub->BitLen,
                 key, sizeof(key), data, &outlen);
    if (rc != SAR_OK)
        return rc;
    *len = outlen;
    SYM_CTX *s = calloc(1, sizeof(*s));
    if (!s)
        return SAR_FAIL;
    s->type = 1;
    s->alg = alg;
    s->keylen = 16;
    memcpy(s->key, key, 16);
    *phKey = (HANDLE)s;
    return SAR_OK;
}
static ULONG raw_rsa(const BYTE *mod, const BYTE *exp, ULONG bits,
                     BYTE *in, ULONG len, BYTE *out, ULONG *outlen)
{
    BN_CTX *ctx = BN_CTX_new();
    ULONG mlen = bits / 8;
    if (mlen == 0 || mlen > MAX_RSA_MODULUS_LEN)
        mlen = MAX_RSA_MODULUS_LEN;
    BIGNUM *n = BN_bin2bn(mod + MAX_RSA_MODULUS_LEN - mlen, (int)mlen, NULL);
    BIGNUM *e = BN_bin2bn(exp, MAX_RSA_EXPONENT_LEN, NULL);
    BIGNUM *m = BN_bin2bn(in, (int)len, NULL);
    BIGNUM *r = BN_new();
    ULONG need = mlen;
    if (!ctx || !n || !e || !m || !r || !out || !outlen || *outlen < need) {
        BN_CTX_free(ctx); BN_free(n); BN_free(e); BN_free(m); BN_free(r);
        return SAR_INVALIDPARAMERR;
    }
    BN_mod_exp(r, m, e, n, ctx);
    BN_bn2binpad(r, out, (int)need);
    *outlen = need;
    BN_CTX_free(ctx); BN_free(n); BN_free(e); BN_free(m); BN_free(r);
    return SAR_OK;
}

ULONG SKF_ExtRSAPubKeyOperation(DEVHANDLE hDev, RSAPUBLICKEYBLOB *pub, BYTE *in,
                                ULONG len, BYTE *out, ULONG *outlen)
{
    (void)hDev;
    if (!pub || !in || !out || !outlen)
        return SAR_INVALIDPARAMERR;
    return raw_rsa(pub->Modulus, pub->PublicExponent, pub->BitLen,
                   in, len, out, outlen);
}

ULONG SKF_ExtRSAPriKeyOperation(DEVHANDLE hDev, RSAPRIVATEKEYBLOB *pri, BYTE *in,
                                ULONG len, BYTE *out, ULONG *outlen)
{
    (void)hDev;
    if (!pri || !in || !out || !outlen)
        return SAR_INVALIDPARAMERR;
    return raw_rsa(pri->Modulus, pri->PrivateExponent, pri->BitLen,
                   in, len, out, outlen);
}

ULONG SKF_GenExtRSAKey(DEVHANDLE hDev, ULONG bits, RSAPRIVATEKEYBLOB *blob)
{
    (void)hDev;
    if (!blob || bits < 512 || bits > 2048)
        return SAR_INVALIDPARAMERR;
    BIGNUM *e = BN_new();
    RSA *r = RSA_new();
    if (!e || !r || BN_set_word(e, RSA_F4) != 1 ||
        RSA_generate_key_ex(r, (int)bits, e, NULL) != 1) {
        BN_free(e); RSA_free(r);
        return SAR_FAIL;
    }
    const BIGNUM *n = NULL, *d = NULL, *p = NULL, *q = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
    RSA_get0_key(r, &n, &e, &d);
    RSA_get0_factors(r, &p, &q);
    RSA_get0_crt_params(r, &dmp1, &dmq1, &iqmp);
    memset(blob, 0, sizeof(*blob));
    blob->AlgID = SGD_RSA;
    blob->BitLen = bits;
    BN_bn2binpad(n, blob->Modulus, MAX_RSA_MODULUS_LEN);
    BN_bn2binpad(e, blob->PublicExponent, MAX_RSA_EXPONENT_LEN);
    BN_bn2binpad(d, blob->PrivateExponent, MAX_RSA_MODULUS_LEN);
    BN_bn2binpad(p, blob->Prime1, MAX_RSA_MODULUS_LEN / 2);
    BN_bn2binpad(q, blob->Prime2, MAX_RSA_MODULUS_LEN / 2);
    BN_bn2binpad(dmp1, blob->Prime1Exponent, MAX_RSA_MODULUS_LEN / 2);
    BN_bn2binpad(dmq1, blob->Prime2Exponent, MAX_RSA_MODULUS_LEN / 2);
    BN_bn2binpad(iqmp, blob->Coefficient, MAX_RSA_MODULUS_LEN / 2);
    RSA_free(r);
    return SAR_OK;
}
static int ec_curve_nid(void)
{
    static int nid = -1;
    if (nid < 0) {
        nid = NID_sm2;
        EC_KEY *t = EC_KEY_new_by_curve_name(nid);
        if (!t) {
            nid = NID_X9_62_prime256v1;
            t = EC_KEY_new_by_curve_name(nid);
        }
        if (t)
            EC_KEY_free(t);
    }
    return nid;
}

static EC_KEY *ec_key_pub_priv(const unsigned char priv[32],
                               const ECCPUBLICKEYBLOB *pub)
{
    int nid = ec_curve_nid();
    if (!nid)
        return NULL;
    EC_KEY *k = EC_KEY_new_by_curve_name(nid);
    if (!k)
        return NULL;
    const EC_GROUP *g = EC_KEY_get0_group(k);
    BIGNUM *x = BN_bin2bn(pub->XCoordinate + 32, 32, NULL);
    BIGNUM *y = BN_bin2bn(pub->YCoordinate + 32, 32, NULL);
    EC_POINT *p = EC_POINT_new(g);
    BIGNUM *d = priv ? BN_bin2bn(priv, 32, NULL) : NULL;
    int ok = x && y && p &&
             EC_POINT_set_affine_coordinates(g, p, x, y, NULL) == 1 &&
             EC_KEY_set_public_key(k, p) == 1 &&
             (!priv || (d && EC_KEY_set_private_key(k, d) == 1));
    BN_free(x); BN_free(y); BN_free(d); EC_POINT_free(p);
    if (!ok) {
        EC_KEY_free(k);
        return NULL;
    }
    return k;
}

static int sm2_sign_digest(const unsigned char priv[32],
                           const unsigned char digest[32],
                           unsigned char r_out[32], unsigned char s_out[32])
{
    int nid = ec_curve_nid();
    EC_GROUP *g = nid ? EC_GROUP_new_by_curve_name(nid) : NULL;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new(), *d = BN_bin2bn(priv, 32, NULL);
    BIGNUM *e = BN_bin2bn(digest, 32, NULL);
    int ok = 0;
    if (!g || !ctx || !n || !d || !e ||
        EC_GROUP_get_order(g, n, ctx) != 1)
        goto out;
    for (int tries = 0; tries < 64 && !ok; tries++) {
        BIGNUM *k = BN_new(), *r = BN_new(), *s = BN_new();
        BIGNUM *one = BN_new(), *d1 = BN_new(), *inv = BN_new();
        BIGNUM *rd = BN_new(), *kr = BN_new(), *t = BN_new();
        EC_POINT *p = EC_POINT_new(g);
        BIGNUM *x = BN_new();
        int good = k && r && s && one && d1 && inv && rd && kr && t && p && x &&
                   BN_rand_range(k, n) == 1 && !BN_is_zero(k) &&
                   EC_POINT_mul(g, p, k, NULL, NULL, ctx) == 1 &&
                   EC_POINT_get_affine_coordinates(g, p, x, NULL, ctx) == 1 &&
                   BN_mod_add(r, e, x, n, ctx) == 1 && !BN_is_zero(r) &&
                   BN_mod_add(t, r, k, n, ctx) == 1 && !BN_is_zero(t) &&
                   BN_one(one) == 1 &&
                   BN_mod_add(d1, one, d, n, ctx) == 1 &&
                   BN_mod_inverse(inv, d1, n, ctx) != NULL &&
                   BN_mod_mul(rd, r, d, n, ctx) == 1 &&
                   BN_mod_sub(kr, k, rd, n, ctx) == 1 &&
                   BN_mod_mul(s, inv, kr, n, ctx) == 1 && !BN_is_zero(s);
        if (good &&
            BN_bn2binpad(r, r_out, 32) == 32 &&
            BN_bn2binpad(s, s_out, 32) == 32)
            ok = 1;
        BN_free(k); BN_free(r); BN_free(s); BN_free(one); BN_free(d1);
        BN_free(inv); BN_free(rd); BN_free(kr); BN_free(t); BN_free(x);
        EC_POINT_free(p);
    }
out:
    BN_free(n); BN_free(d); BN_free(e);
    BN_CTX_free(ctx);
    EC_GROUP_free(g);
    return ok ? 0 : -1;
}

static int sm2_verify_digest(const ECCPUBLICKEYBLOB *pub,
                             const unsigned char digest[32],
                             const unsigned char r_in[32],
                             const unsigned char s_in[32])
{
    int nid = ec_curve_nid();
    EC_GROUP *g = nid ? EC_GROUP_new_by_curve_name(nid) : NULL;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *n = BN_new(), *e = BN_bin2bn(digest, 32, NULL);
    BIGNUM *r = BN_bin2bn(r_in, 32, NULL), *s = BN_bin2bn(s_in, 32, NULL);
    BIGNUM *t = BN_new(), *rx = BN_new();
    EC_POINT *P = NULL, *X = NULL, *sG = NULL, *tP = NULL;
    EC_KEY *key = ec_key_pub_priv(NULL, pub);
    int ok = 0;
    if (!g || !ctx || !n || !e || !r || !s || !t || !rx || !key ||
        EC_GROUP_get_order(g, n, ctx) != 1)
        goto out;
    if (BN_is_zero(r) || BN_is_zero(s) || BN_cmp(r, n) >= 0 ||
        BN_cmp(s, n) >= 0)
        goto out;
    P = EC_POINT_dup(EC_KEY_get0_public_key(key), g);
    X = EC_POINT_new(g);
    sG = EC_POINT_new(g);
    tP = EC_POINT_new(g);
    if (!P || !X || !sG || !tP ||
        BN_mod_add(t, r, s, n, ctx) != 1 || BN_is_zero(t) ||
        EC_POINT_mul(g, sG, s, NULL, NULL, ctx) != 1 ||
        EC_POINT_mul(g, tP, NULL, P, t, ctx) != 1 ||
        EC_POINT_add(g, X, sG, tP, ctx) != 1 ||
        EC_POINT_get_affine_coordinates(g, X, rx, NULL, ctx) != 1)
        goto out;
    if (BN_mod_add(rx, e, rx, n, ctx) == 1 && BN_cmp(rx, r) == 0)
        ok = 1;
out:
    EC_POINT_free(P); EC_POINT_free(X); EC_POINT_free(sG); EC_POINT_free(tP);
    EC_KEY_free(key);
    BN_free(n); BN_free(e); BN_free(r); BN_free(s); BN_free(t); BN_free(rx);
    BN_CTX_free(ctx);
    EC_GROUP_free(g);
    return ok ? 0 : -1;
}

static void ec_pub_from_key(EC_KEY *k, ECCPUBLICKEYBLOB *pub)
{
    const EC_GROUP *g = EC_KEY_get0_group(k);
    const EC_POINT *p = EC_KEY_get0_public_key(k);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    memset(pub, 0, sizeof(*pub));
    pub->BitLen = 256;
    if (x && y && p && EC_POINT_get_affine_coordinates(g, p, x, y, NULL) == 1) {
        BN_bn2binpad(x, pub->XCoordinate + 32, 32);
        BN_bn2binpad(y, pub->YCoordinate + 32, 32);
    }
    BN_free(x); BN_free(y);
}

static int ec_pub_from_priv(const unsigned char priv[32], ECCPUBLICKEYBLOB *pub)
{
    int nid = ec_curve_nid();
    if (!nid)
        return -1;
    EC_KEY *k = EC_KEY_new_by_curve_name(nid);
    if (!k)
        return -1;
    const EC_GROUP *g = EC_KEY_get0_group(k);
    BIGNUM *d = BN_bin2bn(priv, 32, NULL);
    EC_POINT *p = EC_POINT_new(g);
    int ok = d && p && EC_POINT_mul(g, p, d, NULL, NULL, NULL) == 1 &&
             EC_KEY_set_public_key(k, p) == 1;
    if (ok)
        ec_pub_from_key(k, pub);
    BN_free(d); EC_POINT_free(p); EC_KEY_free(k);
    return ok ? 0 : -1;
}

static void ecc_coord32(const unsigned char *coord, unsigned char out[32])
{
    int first_nonzero = 0;
    for (int i = 0; i < 32; i++)
        if (coord[i]) first_nonzero = 1;
    memcpy(out, coord + (first_nonzero ? 0 : 32), 32);
}

static int ecc_pub_equal(const ECCPUBLICKEYBLOB *a, const ECCPUBLICKEYBLOB *b)
{
    unsigned char ax[32], ay[32], bx[32], by[32];
    if (!a || !b || a->BitLen != b->BitLen)
        return 0;
    ecc_coord32(a->XCoordinate, ax);
    ecc_coord32(a->YCoordinate, ay);
    ecc_coord32(b->XCoordinate, bx);
    ecc_coord32(b->YCoordinate, by);
    return memcmp(ax, bx, 32) == 0 && memcmp(ay, by, 32) == 0;
}

static int ecc_priv_matches(const unsigned char priv[32],
                            const ECCPUBLICKEYBLOB *pub)
{
    ECCPUBLICKEYBLOB calc;
    if (ec_pub_from_priv(priv, &calc) != 0)
        return 0;
    calc.BitLen = pub->BitLen;
    return ecc_pub_equal(&calc, pub);
}

static void sm2_kdf(const unsigned char *z, size_t zlen,
                    unsigned char *out, size_t outlen)
{
    unsigned int ct = 1;
    size_t done = 0;
    while (done < outlen) {
        unsigned char md[32], ctr[4] = {0, 0, 0, 0};
        unsigned int mdlen = 0;
        ctr[0] = (unsigned char)(ct >> 24);
        ctr[1] = (unsigned char)(ct >> 16);
        ctr[2] = (unsigned char)(ct >> 8);
        ctr[3] = (unsigned char)ct;
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (ctx && EVP_DigestInit_ex(ctx, EVP_sm3(), NULL) == 1 &&
            EVP_DigestUpdate(ctx, z, zlen) == 1 &&
            EVP_DigestUpdate(ctx, ctr, 4) == 1 &&
            EVP_DigestFinal_ex(ctx, md, &mdlen) == 1) {
            size_t n = outlen - done;
            if (n > 32) n = 32;
            memcpy(out + done, md, n);
            done += n;
        } else {
            memset(out + done, 0, outlen - done);
            done = outlen;
        }
        EVP_MD_CTX_free(ctx);
        ct++;
    }
}

static int sm2_decrypt_std(const unsigned char priv[32],
                           const ECCCIPHERBLOB *c,
                           unsigned char *out, ULONG *outlen)
{
    int nid = ec_curve_nid();
    if (!nid || !c || c->CipherLen == 0 || c->CipherLen > 256)
        return -1;
    EC_GROUP *g = EC_GROUP_new_by_curve_name(nid);
    EC_POINT *c1 = EC_POINT_new(g);
    BN_CTX *bnctx = BN_CTX_new();
    const unsigned char *px = c->XCoordinate + 32;
    const unsigned char *py = c->YCoordinate + 32;
    BIGNUM *x = BN_bin2bn(px, 32, NULL);
    BIGNUM *y = BN_bin2bn(py, 32, NULL);
    BIGNUM *d = BN_bin2bn(priv, 32, NULL);
    EC_POINT *shared = EC_POINT_new(g);
    int ok = g && c1 && bnctx && x && y && d && shared &&
             EC_POINT_set_affine_coordinates(g, c1, x, y, bnctx) == 1 &&
             EC_POINT_mul(g, shared, NULL, c1, d, bnctx) == 1;
    unsigned char x2[32], y2[32], z[64], kdf[256], c3[32];
    unsigned int c3len = 0;
    if (ok) {
        BIGNUM *sx = BN_new(), *sy = BN_new();
        ok = sx && sy &&
             EC_POINT_get_affine_coordinates(g, shared, sx, sy, bnctx) == 1;
        if (ok) {
            BN_bn2binpad(sx, x2, 32);
            BN_bn2binpad(sy, y2, 32);
        }
        BN_free(sx); BN_free(sy);
    }
    if (ok) {
        memcpy(z, x2, 32);
        memcpy(z + 32, y2, 32);
        sm2_kdf(z, sizeof(z), kdf, c->CipherLen);
        for (ULONG i = 0; i < c->CipherLen; i++)
            out[i] = (unsigned char)(c->Cipher[i] ^ kdf[i]);
        int hash_nonzero = 0;
        for (int i = 0; i < 32; i++)
            if (c->HASH[i]) hash_nonzero = 1;
        if (hash_nonzero) {
            EVP_MD_CTX *md = EVP_MD_CTX_new();
            if (md && EVP_DigestInit_ex(md, EVP_sm3(), NULL) == 1 &&
                EVP_DigestUpdate(md, x2, 32) == 1 &&
                EVP_DigestUpdate(md, out, c->CipherLen) == 1 &&
                EVP_DigestUpdate(md, y2, 32) == 1 &&
                EVP_DigestFinal_ex(md, c3, &c3len) == 1) {
                if (c3len != 32 || memcmp(c3, c->HASH, 32) != 0)
                    ok = 0;
            }
            EVP_MD_CTX_free(md);
        }
    }
    BN_free(x); BN_free(y); BN_free(d);
    EC_POINT_free(c1); EC_POINT_free(shared);
    BN_CTX_free(bnctx); EC_GROUP_free(g);
    if (!ok)
        return -1;
    *outlen = c->CipherLen;
    return 0;
}

static int sym_decrypt_std(ULONG alg, const unsigned char key[16],
                           const unsigned char *in, ULONG inlen,
                           unsigned char *out, ULONG *outlen)
{
    const EVP_CIPHER *cipher = cipher_for(alg);
    if (!cipher)
        return -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16] = {0};
    int n = 0, total = 0;
    int ok = ctx && EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) == 1 &&
             EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
             EVP_DecryptUpdate(ctx, out, &n, in, (int)inlen) == 1;
    if (ok) { total += n; n = 0; ok = EVP_DecryptFinal_ex(ctx, out + total, &n) == 1; }
    if (ok) total += n;
    EVP_CIPHER_CTX_free(ctx);
    if (ok) {
        *outlen = (ULONG)total;
        return 0;
    }
    /* Some wrappers include PKCS#7 padding. */
    ctx = EVP_CIPHER_CTX_new();
    n = total = 0;
    ok = ctx && EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) == 1 &&
         EVP_CIPHER_CTX_set_padding(ctx, 1) == 1 &&
         EVP_DecryptUpdate(ctx, out, &n, in, (int)inlen) == 1;
    if (ok) { total += n; n = 0; ok = EVP_DecryptFinal_ex(ctx, out + total, &n) == 1; }
    if (ok) total += n;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok)
        return -1;
    *outlen = (ULONG)total;
    return 0;
}

static EC_KEY *ec_generate(ECCPUBLICKEYBLOB *pub, unsigned char priv[32])
{
    int nid = ec_curve_nid();
    if (!nid)
        return NULL;
    EC_KEY *k = EC_KEY_new_by_curve_name(nid);
    if (!k || EC_KEY_generate_key(k) != 1) {
        EC_KEY_free(k);
        return NULL;
    }
    ec_pub_from_key(k, pub);
    BN_bn2binpad(EC_KEY_get0_private_key(k), priv, 32);
    return k;
}

static int ecdh_raw(const unsigned char priv[32], const ECCPUBLICKEYBLOB *pub,
                    unsigned char out[32])
{
    EC_KEY *k = ec_key_pub_priv(priv, pub);
    if (!k)
        return -1;
    const EC_POINT *p = EC_KEY_get0_public_key(k);
    int n = ECDH_compute_key(out, 32, p, k, NULL);
    EC_KEY_free(k);
    return n == 32 ? 0 : -1;
}

static void agreement_kdf(const unsigned char shared[32],
                          const unsigned char *id1, ULONG id1len,
                          const unsigned char *id2, ULONG id2len,
                          unsigned char key[16])
{
    const unsigned char *a = id1, *b = id2;
    ULONG alen = id1len, blen = id2len;
    if (alen > blen || (alen == blen && memcmp(a, b, alen) > 0)) {
        a = id2; b = id1; alen = id2len; blen = id1len;
    }
    unsigned char md[32];
    unsigned int mdlen = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *mdalg = EVP_sm3();
    if (!mdalg)
        mdalg = EVP_sha256();
    if (ctx && EVP_DigestInit_ex(ctx, mdalg, NULL) == 1 &&
        EVP_DigestUpdate(ctx, shared, 32) == 1 &&
        EVP_DigestUpdate(ctx, a, alen) == 1 &&
        EVP_DigestUpdate(ctx, b, blen) == 1 &&
        EVP_DigestFinal_ex(ctx, md, &mdlen) == 1) {
        memcpy(key, md, 16);
    } else {
        memcpy(key, shared, 16);
    }
    EVP_MD_CTX_free(ctx);
}

static ULONG agreement_make_key(DEV_CTX *dev, ULONG alg,
                                const unsigned char key[16], HANDLE *phKey)
{
    SYM_CTX *s = calloc(1, sizeof(*s));
    if (!s)
        return SAR_FAIL;
    s->type = 1;
    s->dev = dev;
    s->alg = alg;
    s->keylen = 16;
    memcpy(s->key, key, 16);
    *phKey = (HANDLE)s;
    return SAR_OK;
}

ULONG SKF_GenerateAgreementDataWithECC(HCONTAINER hCtn, ULONG alg,
                                       ECCPUBLICKEYBLOB *temp,
                                       BYTE *id, ULONG idlen,
                                       HANDLE *phAgree)
{
    CTN_CTX *c = (CTN_CTX *)hCtn;
    if (!c || !c->app || !c->app->dev || !temp || !phAgree || idlen > 32 ||
        (!id && idlen))
        return SAR_INVALIDPARAMERR;
    if (!c->ecc_priv_valid)
        return SAR_NOTSUPPORTYETERR;
    AGREE_CTX *a = calloc(1, sizeof(*a));
    if (!a)
        return SAR_FAIL;
    a->type = 4;
    a->dev = c->app->dev;
    a->alg = alg;
    a->eph = ec_generate(temp, a->eph_priv);
    if (!a->eph) {
        free(a);
        return SAR_FAIL;
    }
    memcpy(a->static_priv, c->ecc_priv, 32);
    a->static_pub = c->ecc_pub_soft;
    if (idlen)
        memcpy(a->id, id, idlen);
    a->idlen = idlen;
    *phAgree = (HANDLE)a;
    return SAR_OK;
}

ULONG SKF_GenerateAgreementDataAndKeyWithECC(HANDLE hContainer, ULONG alg,
                                             ECCPUBLICKEYBLOB *sponsor,
                                             ECCPUBLICKEYBLOB *sponsorTemp,
                                             ECCPUBLICKEYBLOB *temp,
                                             BYTE *id, ULONG idlen,
                                             BYTE *sponsorid, ULONG sponsoridlen,
                                             HANDLE *phKey)
{
    CTN_CTX *c = (CTN_CTX *)hContainer;
    if (!c || !c->app || !c->app->dev || !sponsor || !sponsorTemp ||
        !temp || !phKey || idlen > 32 || sponsoridlen > 32 ||
        (!id && idlen) || (!sponsorid && sponsoridlen))
        return SAR_INVALIDPARAMERR;
    if (!c->ecc_priv_valid)
        return SAR_NOTSUPPORTYETERR;
    ECCPUBLICKEYBLOB respTemp;
    unsigned char respPriv[32];
    EC_KEY *eph = ec_generate(&respTemp, respPriv);
    if (!eph)
        return SAR_FAIL;
    unsigned char s1[32], s2[32], shared[32], key[16];
    int ok = ecdh_raw(c->ecc_priv, sponsorTemp, s1) == 0 &&
             ecdh_raw(respPriv, sponsor, s2) == 0;
    EC_KEY_free(eph);
    if (!ok)
        return SAR_FAIL;
    for (int i = 0; i < 32; i++)
        shared[i] = (unsigned char)(s1[i] ^ s2[i]);
    agreement_kdf(shared, id, idlen, sponsorid, sponsoridlen, key);
    *temp = respTemp;
    return agreement_make_key(c->app->dev, alg, key, phKey);
}

ULONG SKF_GenerateKeyWithECC(HANDLE hAgree, ECCPUBLICKEYBLOB *pub,
                             ECCPUBLICKEYBLOB *temp, BYTE *id, ULONG idlen,
                             HANDLE *phKey)
{
    AGREE_CTX *a = (AGREE_CTX *)hAgree;
    if (!a || a->type != 4 || !pub || !temp || !phKey || idlen > 32 ||
        (!id && idlen))
        return SAR_INVALIDPARAMERR;
    unsigned char s1[32], s2[32], shared[32], key[16];
    if (ecdh_raw(a->static_priv, temp, s1) != 0 ||
        ecdh_raw(a->eph_priv, pub, s2) != 0)
        return SAR_FAIL;
    for (int i = 0; i < 32; i++)
        shared[i] = (unsigned char)(s1[i] ^ s2[i]);
    agreement_kdf(shared, a->id, a->idlen, id, idlen, key);
    return agreement_make_key(a->dev, a->alg, key, phKey);
}

ULONG SKF_ImportSessionKey(HCONTAINER hCtn, ULONG alg, BYTE *data, ULONG len, HANDLE *phKey)
{
    CTN_CTX *c = (CTN_CTX *)hCtn;
    if (!c || !c->app || !c->app->dev)
        return SAR_INVALIDHANDLEERR;
    if (!data || !phKey)
        return SAR_INVALIDPARAMERR;
    if (len != 16 && len != 24 && len != 32)
        return SAR_INVALIDPARAMERR;
    if ((alg & 0xff00) != SGD_SM4 && (alg & 0xff00) != SGD_SM1)
        return SAR_NOTSUPPORTYETERR;
    SYM_CTX *s = calloc(1, sizeof(*s));
    if (!s)
        return SAR_FAIL;
    s->type = 1;
    s->dev = c->app->dev;
    s->alg = alg;
    s->keylen = len;
    memcpy(s->key, data, len);
    *phKey = (HANDLE)s;
    return SAR_OK;
}
