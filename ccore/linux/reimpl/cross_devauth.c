#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skf.h"

typedef ULONG (*fn_Enum)(BOOL, LPSTR, ULONG *);
typedef ULONG (*fn_Connect)(LPSTR, DEVHANDLE *);
typedef ULONG (*fn_Disc)(DEVHANDLE);
typedef ULONG (*fn_Info)(DEVHANDLE, DEVINFO *);
typedef ULONG (*fn_Rand)(DEVHANDLE, BYTE *, ULONG);
typedef ULONG (*fn_Set)(DEVHANDLE, BYTE *, ULONG, HANDLE *);
typedef ULONG (*fn_Init)(HANDLE, BLOCKCIPHERPARAM);
typedef ULONG (*fn_Enc)(HANDLE, BYTE *, ULONG, BYTE *, ULONG *);
typedef ULONG (*fn_Auth)(DEVHANDLE, BYTE *, ULONG);

static void *load(const char *path, void **h, fn_Enum *e, fn_Connect *c, fn_Disc *d,
                  fn_Info *i, fn_Rand *r, fn_Set *s, fn_Init *in, fn_Enc *en,
                  fn_Auth *a)
{
    *h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!*h) { fprintf(stderr, "dlopen %s: %s\n", path, dlerror()); exit(1); }
    *e = (fn_Enum)dlsym(*h, "SKF_EnumDev");
    *c = (fn_Connect)dlsym(*h, "SKF_ConnectDev");
    *d = (fn_Disc)dlsym(*h, "SKF_DisConnectDev");
    *i = (fn_Info)dlsym(*h, "SKF_GetDevInfo");
    *r = (fn_Rand)dlsym(*h, "SKF_GenRandom");
    *s = (fn_Set)dlsym(*h, "SKF_SetSymmKey");
    *in = (fn_Init)dlsym(*h, "SKF_EncryptInit");
    *en = (fn_Enc)dlsym(*h, "SKF_Encrypt");
    *a = (fn_Auth)dlsym(*h, "SKF_DevAuth");
    return *h;
}

static char *enum_name(fn_Enum e)
{
    ULONG len = 0;
    e(TRUE, NULL, &len);
    char *n = calloc(1, len + 1);
    e(TRUE, n, &len);
    return n;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 1;
    void *ho, *hn;
    fn_Enum eo, en; fn_Connect co, cn; fn_Disc do_, dn; fn_Info io, inn;
    fn_Rand ro, rn; fn_Set so, sn; fn_Init ino, inn2; fn_Enc enco, encn;
    fn_Auth ao, an;
    load("/work/linux/lib/libskf.so", &ho, &eo, &co, &do_, &io, &ro, &so, &ino, &enco, &ao);
    load("/work/linux/reimpl/libskf_native.so", &hn, &en, &cn, &dn, &inn, &rn, &sn, &inn2, &encn, &an);
    char *no = enum_name(eo), *nn = enum_name(en);
    DEVHANDLE devo = NULL, devn = NULL;
    printf("connect orig=%lx native=%lx\n", (unsigned long)co(no, &devo), (unsigned long)cn(nn, &devn));
    DEVINFO info; memset(&info, 0, sizeof(info));
    io(devo, &info);
    printf("alg=0x%lx\n", (unsigned long)info.DevAuthAlgId);
    BYTE ch[16]; memset(ch, 0, sizeof(ch));
    printf("rand orig=%lx\n", (unsigned long)ro(devo, ch, 8));
    printf("challenge: "); for (int i=0;i<8;i++) printf("%02x", ch[i]); printf("\n");
    BYTE outo[32], outn[32]; ULONG lo = sizeof(outo), ln = sizeof(outn);
    HANDLE h;
    so(devo, (BYTE *)argv[1], info.DevAuthAlgId, &h);
    BLOCKCIPHERPARAM p; memset(&p, 0, sizeof(p));
    ino(h, p);
    ULONG rco = enco(h, ch, 16, outo, &lo);
    printf("orig enc=0x%lx: ", (unsigned long)rco); for (ULONG i=0;i<lo;i++) printf("%02x", outo[i]); printf("\n");
    so(devo, (BYTE *)argv[1], info.DevAuthAlgId, &h);
    ino(h, p);
    rco = enco(h, ch, 16, outo, &lo);
    printf("orig enc2=0x%lx: ", (unsigned long)rco); for (ULONG i=0;i<lo;i++) printf("%02x", outo[i]); printf("\n");
    sn(devn, (BYTE *)argv[1], info.DevAuthAlgId, &h);
    inn2(h, p);
    ULONG rcn = encn(h, ch, 16, outn, &ln);
    printf("native enc=0x%lx: ", (unsigned long)rcn); for (ULONG i=0;i<ln;i++) printf("%02x", outn[i]); printf("\n");
    printf("orig auth(native cipher)=0x%lx\n", (unsigned long)ao(devo, outn, ln));
    printf("native auth(native cipher)=0x%lx\n", (unsigned long)an(devn, outn, ln));
    do_(devo); dn(devn);
    return 0;
}
