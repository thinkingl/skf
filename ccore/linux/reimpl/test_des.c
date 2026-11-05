#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef void (*des_fn)(const unsigned char *, unsigned char *, long,
                       const unsigned char *, int);
typedef void (*des_cbc_fn)(const unsigned char *, unsigned char *, long,
                           const unsigned char *, const unsigned char *, int);

int main(int argc, char **argv)
{
    const char *lib = argc > 1 ? argv[1] : "./lib/libskf.so";
    void *h = dlopen(lib, RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
    void *sym = dlsym(h, "SKF_EnumDev");
    Dl_info info;
    if (!sym || !dladdr(sym, &info)) { fprintf(stderr, "dladdr failed\n"); return 1; }
    unsigned char *base = (unsigned char *)info.dli_fbase;
    des_fn des_ecb = (des_fn)(base + 0x3d7d0);
    des_cbc_fn des_cbc = (des_cbc_fn)(base + 0x3d900);

    unsigned char key[8] = {0x34,0x30,0x48,0x35,0x32,0x04,0x4f,0x43};
    unsigned char iv[8]  = {0x00,0x00,0x00,0x00,0x42,0x19,0x4e,0x87};
    unsigned char rnd[8] = {0x42,0x19,0x4e,0x87,0xeb,0x15,0x4f,0x88};
    unsigned char kout[8] = {0};
    unsigned char pin[16] = {'1','2','3','4','5','6',0,0,0,0,0,0,0,0,0,0};
    unsigned char pout[16] = {0};

    des_cbc(rnd, kout, 8, key, iv, 1);
    printf("DES-CBC kout: ");
    for (int i = 0; i < 8; i++) printf("%02x", kout[i]);
    printf("\n");
    des_ecb(pin, pout, 16, kout, 1);
    printf("DES-ECB pout: ");
    for (int i = 0; i < 16; i++) printf("%02x", pout[i]);
    printf("\n");

    /* standard DES test vector: key 133457799BBCDFF1, plain 0123456789ABCDEF */
    unsigned char tk[8] = {0x13,0x34,0x57,0x79,0x9b,0xbc,0xdf,0xf1};
    unsigned char tp[8] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef};
    unsigned char to[8] = {0};
    des_ecb(tp, to, 8, tk, 1);
    printf("DES test out: ");
    for (int i = 0; i < 8; i++) printf("%02x", to[i]);
    printf(" (expect 85e813540f0ab405)\n");
    dlclose(h);
    return 0;
}
