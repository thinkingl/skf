/*
 * Differential hotplug-event test.
 *
 * Runs SKF_WaitForDevEvent / SKF_CancelWaitForDevEvent against the vendor
 * library and the native reimplementation, toggling USB port power through
 * sysfs.  Requires root and a writable /sys (run in a privileged container
 * with -v /sys:/sys).
 *
 * Usage:
 *   ./skf_event_diff_test ./lib/libskf.so ./reimpl/libskf_native.so
 *
 * Each scenario runs in a fresh child process because the vendor library
 * caches its device list; otherwise a stale cache hides the next hotplug.
 *
 * Optional:
 *   SKF_EVENT_USB=3-4   force the USB device name under /sys/bus/usb/devices
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "skf.h"

typedef ULONG (*wait_fn)(LPSTR, ULONG *, ULONG *);
typedef ULONG (*cancel_fn)(void);

typedef struct lib {
    void *h;
    wait_fn WaitForDevEvent;
    cancel_fn CancelWaitForDevEvent;
} LIB;

typedef struct wait_arg {
    wait_fn fn;
    pthread_t thread;
    ULONG rc;
    ULONG evt;
    ULONG len;
    char name[128];
} WAIT_ARG;

static void *wait_thread(void *p)
{
    WAIT_ARG *a = (WAIT_ARG *)p;
    a->len = sizeof(a->name);
    a->evt = 0xffffffff;
    a->rc = a->fn((LPSTR)a->name, &a->len, &a->evt);
    return NULL;
}

static int load_lib(LIB *l, const char *path)
{
    memset(l, 0, sizeof(*l));
    l->h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!l->h) {
        fprintf(stderr, "dlopen %s: %s\n", path, dlerror());
        return -1;
    }
    l->WaitForDevEvent = (wait_fn)dlsym(l->h, "SKF_WaitForDevEvent");
    l->CancelWaitForDevEvent =
        (cancel_fn)dlsym(l->h, "SKF_CancelWaitForDevEvent");
    if (!l->WaitForDevEvent || !l->CancelWaitForDevEvent) {
        fprintf(stderr, "missing event symbols in %s\n", path);
        return -1;
    }
    return 0;
}

static int write_text(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY);
    ssize_t n;
    if (fd < 0)
        return -1;
    n = write(fd, text, strlen(text));
    close(fd);
    return n == (ssize_t)strlen(text) ? 0 : -1;
}

static int find_usb(char *out, size_t cap)
{
    const char *env = getenv("SKF_EVENT_USB");
    glob_t g;

    if (env && *env) {
        snprintf(out, cap, "%s", env);
        return 0;
    }
    if (glob("/sys/bus/usb/devices/*/idVendor", 0, NULL, &g) != 0)
        return -1;
    for (size_t i = 0; i < g.gl_pathc; i++) {
        char vend[16] = {0};
        FILE *f = fopen(g.gl_pathv[i], "r");
        if (!f)
            continue;
        if (fgets(vend, sizeof(vend), f) &&
            (strstr(vend, "02e3") || strstr(vend, "02E3"))) {
            char *p = strstr(g.gl_pathv[i], "/sys/bus/usb/devices/");
            char *q;
            fclose(f);
            if (!p)
                continue;
            p += strlen("/sys/bus/usb/devices/");
            q = strchr(p, '/');
            if (!q)
                continue;
            snprintf(out, cap, "%.*s", (int)(q - p), p);
            globfree(&g);
            return 0;
        }
        fclose(f);
    }
    globfree(&g);
    return -1;
}

static int port_disable_path(const char *usb, char *out, size_t cap)
{
    char link[256], resolved[PATH_MAX];
    snprintf(link, sizeof(link), "/sys/bus/usb/devices/%s/port", usb);
    if (!realpath(link, resolved))
        return -1;
    snprintf(out, cap, "%s/disable", resolved);
    return 0;
}

static int ccore_sysfs_present(void)
{
    glob_t g;
    int present = 0;

    if (glob("/sys/class/scsi_generic/sg*/device/vendor", 0, NULL, &g) != 0)
        return 0;
    for (size_t i = 0; i < g.gl_pathc; i++) {
        char buf[64] = {0};
        FILE *f = fopen(g.gl_pathv[i], "r");
        if (!f)
            continue;
        if (fgets(buf, sizeof(buf), f) &&
            (strstr(buf, "C*CORE") || strstr(buf, "C*Core") ||
             strstr(buf, "CCore"))) {
            present = 1;
            fclose(f);
            break;
        }
        fclose(f);
    }
    globfree(&g);
    return present;
}

static int wait_present(int ms)
{
    for (int i = 0; i < ms / 100; i++) {
        if (ccore_sysfs_present())
            return 0;
        usleep(100000);
    }
    return -1;
}

static int wait_absent(int ms)
{
    for (int i = 0; i < ms / 100; i++) {
        if (!ccore_sysfs_present())
            return 0;
        usleep(100000);
    }
    return -1;
}

static void base_name(char *name)
{
    size_t n = strlen(name);
    while (n && name[n - 1] >= '0' && name[n - 1] <= '9')
        name[--n] = 0;
}

static int wait_event(LIB *l, int ms, WAIT_ARG *a)
{
    struct timespec ts;
    int rc;

    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }
    rc = pthread_timedjoin_np(a->thread, NULL, &ts);
    if (rc == ETIMEDOUT) {
        l->CancelWaitForDevEvent();
        pthread_join(a->thread, NULL);
        return -1;
    }
    return 0;
}

static void start_wait(LIB *l, WAIT_ARG *a)
{
    memset(a, 0, sizeof(*a));
    a->fn = l->WaitForDevEvent;
    pthread_create(&a->thread, NULL, wait_thread, a);
}

static int run_scenario(LIB *l, const char *usb, const char *scenario,
                        char *out, size_t cap)
{
    char disable[256];
    WAIT_ARG a;
    int timeout;

    if (port_disable_path(usb, disable, sizeof(disable)) != 0) {
        snprintf(out, cap, "cannot resolve port for %s: %s\n",
                 usb, strerror(errno));
        return -1;
    }
    if (access(disable, W_OK) != 0) {
        snprintf(out, cap, "missing %s: %s\n", disable, strerror(errno));
        return -1;
    }

    if (strcmp(scenario, "cancel") == 0) {
        ULONG crc;
        start_wait(l, &a);
        usleep(300000);
        crc = l->CancelWaitForDevEvent();
        pthread_join(a.thread, NULL);
        snprintf(out, cap, "cancel rc=%lx wait=%lx\n",
                 (unsigned long)crc, (unsigned long)a.rc);
        return 0;
    }

    if (strcmp(scenario, "remove") == 0) {
        if (wait_present(10000) != 0) {
            snprintf(out, cap, "device not present before remove\n");
            return -1;
        }
        start_wait(l, &a);
        usleep(300000);
        write_text(disable, "1");
        timeout = wait_event(l, 10000, &a);
        write_text(disable, "0");
        wait_present(15000);
        if (timeout) {
            snprintf(out, cap, "remove timeout\n");
            return -1;
        }
        base_name(a.name);
        snprintf(out, cap, "remove rc=%lx evt=%lu name=%s\n",
                 (unsigned long)a.rc, (unsigned long)a.evt, a.name);
        return 0;
    }

    if (strcmp(scenario, "add") == 0) {
        write_text(disable, "1");
        if (wait_absent(15000) != 0) {
            write_text(disable, "0");
            wait_present(15000);
            snprintf(out, cap, "device still present before add\n");
            return -1;
        }
        start_wait(l, &a);
        usleep(300000);
        write_text(disable, "0");
        timeout = wait_event(l, 10000, &a);
        wait_present(15000);
        if (timeout) {
            write_text(disable, "0");
            wait_present(15000);
            snprintf(out, cap, "add timeout\n");
            return -1;
        }
        base_name(a.name);
        snprintf(out, cap, "add rc=%lx evt=%lu name=%s\n",
                 (unsigned long)a.rc, (unsigned long)a.evt, a.name);
        return 0;
    }

    snprintf(out, cap, "unknown scenario %s\n", scenario);
    return -1;
}

static int capture(const char *self, const char *scenario, const char *lib,
                   char *out, size_t cap)
{
    int p[2];
    pid_t pid;
    ssize_t n;
    size_t off = 0;
    int status = 0;

    if (pipe(p) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        close(p[0]);
        close(p[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(p[1], STDOUT_FILENO);
        close(p[0]);
        close(p[1]);
        execl(self, self, "--run", scenario, lib, (char *)NULL);
        _exit(127);
    }
    close(p[1]);
    while ((n = read(p[0], out + off, cap - 1 - off)) > 0)
        off += (size_t)n;
    close(p[0]);
    waitpid(pid, &status, 0);
    out[off] = 0;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int main(int argc, char **argv)
{
    static const char *scenarios[] = {"cancel", "remove", "add"};
    char usb[64];
    char outa[4096], outb[4096];
    int failures = 0;

    if (argc == 4 && strcmp(argv[1], "--run") == 0) {
        LIB l;
        if (find_usb(usb, sizeof(usb)) != 0) {
            fprintf(stderr, "no CCore USB device found\n");
            return 2;
        }
        if (load_lib(&l, argv[3]) != 0)
            return 2;
        if (run_scenario(&l, usb, argv[2], outa, sizeof(outa)) != 0) {
            fputs(outa, stdout);
            return 1;
        }
        fputs(outa, stdout);
        return 0;
    }

    if (argc < 3) {
        fprintf(stderr, "usage: %s <vendor-lib> <native-lib>\n", argv[0]);
        return 2;
    }
    for (size_t i = 0; i < sizeof(scenarios) / sizeof(scenarios[0]); i++) {
        outa[0] = outb[0] = 0;
        int ra = capture(argv[0], scenarios[i], argv[1], outa, sizeof(outa));
        int rb = capture(argv[0], scenarios[i], argv[2], outb, sizeof(outb));
        if (ra == 0 && rb == 0 && strcmp(outa, outb) == 0) {
            printf("[PASS] %s: %s", scenarios[i], outa);
            continue;
        }
        failures++;
        printf("[DIFF] %s (vendor rc=%d native rc=%d)\n"
               "--- vendor ---\n%s--- native ---\n%s",
               scenarios[i], ra, rb, outa, outb);
    }
    if (failures == 0) {
        printf("[PASS] event differential test: vendor == native\n");
        return 0;
    }
    return 1;
}
