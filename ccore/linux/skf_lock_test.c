/*
 * Differential lock test: SKF_LockDev / SKF_UnlockDev must serialize
 * concurrent callers.  Compares the vendor library with the native
 * reimplementation.
 *
 * Usage: ./skf_lock_test ./lib/libskf.so ./reimpl/libskf_native.so
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "skf.h"

typedef struct lib {
    void *h;
    typeof(&SKF_EnumDev) EnumDev;
    typeof(&SKF_ConnectDev) ConnectDev;
    typeof(&SKF_DisConnectDev) DisConnectDev;
    typeof(&SKF_LockDev) LockDev;
    typeof(&SKF_UnlockDev) UnlockDev;
} LIB;

typedef struct arg {
    LIB *l;
    DEVHANDLE d;
    int active;
    int max_active;
    int total;
    int errors;
} ARG;

static void *worker(void *p)
{
    ARG *a = (ARG *)p;
    for (int i = 0; i < 20; i++) {
        if (a->l->LockDev(a->d, 1000) != SAR_OK) {
            __sync_add_and_fetch(&a->errors, 1);
            continue;
        }
        int cur = __sync_add_and_fetch(&a->active, 1);
        if (cur > a->max_active)
            a->max_active = cur;
        __sync_add_and_fetch(&a->total, 1);
        usleep(2000);
        __sync_sub_and_fetch(&a->active, 1);
        if (a->l->UnlockDev(a->d) != SAR_OK)
            __sync_add_and_fetch(&a->errors, 1);
    }
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
#define SYM(n) do { \
    l->n = (typeof(&SKF_##n))dlsym(l->h, "SKF_" #n); \
    if (!l->n) { fprintf(stderr, "missing SKF_%s\n", #n); return -1; } \
} while (0)
    SYM(EnumDev);
    SYM(ConnectDev);
    SYM(DisConnectDev);
    SYM(LockDev);
    SYM(UnlockDev);
#undef SYM
    return 0;
}

static void run(LIB *l, char *out, size_t cap)
{
    ULONG n = 0;
    char *names;
    DEVHANDLE d = NULL;
    ARG a;

    l->EnumDev(TRUE, NULL, &n);
    names = calloc(1, n + 1);
    if (!names || l->EnumDev(TRUE, (LPSTR)names, &n) != SAR_OK) {
        snprintf(out, cap, "enum failed\n");
        free(names);
        return;
    }
    if (l->ConnectDev((LPSTR)names, &d) != SAR_OK) {
        snprintf(out, cap, "connect failed\n");
        free(names);
        return;
    }

    memset(&a, 0, sizeof(a));
    a.l = l;
    a.d = d;
    pthread_t th[8];
    for (int i = 0; i < 8; i++)
        pthread_create(&th[i], NULL, worker, &a);
    for (int i = 0; i < 8; i++)
        pthread_join(th[i], NULL);

    ULONG r1 = l->LockDev(d, 0);
    ULONG r2 = l->UnlockDev(d);
    ULONG r3 = l->LockDev(NULL, 0);
    ULONG r4 = l->UnlockDev(NULL);
    snprintf(out, cap,
             "lock_valid rc=%lx\n"
             "unlock_valid rc=%lx\n"
             "lock_null rc=%lx\n"
             "unlock_null rc=%lx\n"
             "concurrent max_active=%d total=%d errors=%d\n",
             (unsigned long)r1, (unsigned long)r2,
             (unsigned long)r3, (unsigned long)r4,
             a.max_active, a.total, a.errors);
    l->DisConnectDev(d);
    free(names);
}

int main(int argc, char **argv)
{
    LIB vendor, native;
    char outa[2048], outb[2048];

    if (argc < 3) {
        fprintf(stderr, "usage: %s <vendor-lib> <native-lib>\n", argv[0]);
        return 2;
    }
    if (load_lib(&vendor, argv[1]) || load_lib(&native, argv[2]))
        return 2;
    outa[0] = outb[0] = 0;
    run(&vendor, outa, sizeof(outa));
    run(&native, outb, sizeof(outb));
    if (strcmp(outa, outb) == 0) {
        printf("[PASS] lock differential test: vendor == native\n%s", outa);
        return 0;
    }
    printf("[DIFF] vendor != native\n--- vendor ---\n%s--- native ---\n%s",
           outa, outb);
    return 1;
}
