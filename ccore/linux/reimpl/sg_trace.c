/* LD_PRELOAD SG_IO tracer for protocol capture. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>

static int (*real_ioctl)(int, unsigned long, ...);
static FILE *logf;

static void ensure_log(void)
{
    if (logf)
        return;
    const char *p = getenv("SG_TRACE");
    if (!p || !*p)
        p = "/tmp/sg_trace.log";
    logf = fopen(p, "a");
    if (!logf)
        logf = stderr;
}

static void dump(const char *tag, const unsigned char *p, int n)
{
    if (!logf)
        return;
    fprintf(logf, "%s", tag);
    for (int i = 0; i < n; i++)
        fprintf(logf, "%02x", p[i]);
    fputc('\n', logf);
    fflush(logf);
}

int ioctl(int fd, unsigned long req, ...)
{
    va_list ap;
    void *arg;

    va_start(ap, req);
    arg = va_arg(ap, void *);
    va_end(ap);

    if (!real_ioctl)
        real_ioctl = dlsym(RTLD_NEXT, "ioctl");

    if (req != SG_IO || !arg)
        return real_ioctl(fd, req, arg);

    sg_io_hdr_t *io = (sg_io_hdr_t *)arg;
    ensure_log();
    fprintf(logf, "REQ dir=%d cmdlen=%d dxfer=%d timeout=%d\n",
            io->dxfer_direction, io->cmd_len, io->dxfer_len, io->timeout);
    dump("CDB ", io->cmdp, io->cmd_len);
    if (io->dxfer_direction == SG_DXFER_TO_DEV && io->dxferp)
        dump("OUT ", io->dxferp, io->dxfer_len > 512 ? 512 : io->dxfer_len);

    int rc = real_ioctl(fd, req, arg);

    fprintf(logf, "RES rc=%d status=%u host=%u driver=%u resid=%d\n",
            rc, io->status, io->host_status, io->driver_status, io->resid);
    if (io->dxfer_direction == SG_DXFER_FROM_DEV && io->dxferp)
        dump("IN  ", io->dxferp, io->dxfer_len > 512 ? 512 : io->dxfer_len);
    fflush(logf);
    return rc;
}
