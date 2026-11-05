#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "skf.h"

static void mark(const char *s)
{
    const char *p = getenv("SG_TRACE"); if (!p || !*p) p = "/tmp/sg_trace.log";
    int fd = open(p, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { dprintf(fd, "=== MARK %s ===\n", s); close(fd); }
}
static void pr(const char *w, ULONG rc) { printf("%-28s 0x%08lx\n", w, (unsigned long)rc); }

int main(int argc, char **argv)
{
    if (argc < 2) return 1;
    ULONG len = 0; SKF_EnumDev(TRUE, NULL, &len);
    char *names = calloc(1, len + 1); SKF_EnumDev(TRUE, (LPSTR)names, &len);
    DEVHANDLE dev = NULL;
    if (SKF_ConnectDev((LPSTR)names, &dev) != SAR_OK) return 1;
    DEVINFO info; memset(&info, 0, sizeof(info));
    SKF_GetDevInfo(dev, &info);
    printf("DevAuthAlgId=0x%lx\n", (unsigned long)info.DevAuthAlgId);
    ULONG alg = info.DevAuthAlgId;
    if (alg != SGD_SM1_ECB && alg != SGD_SM4_ECB) alg = SGD_SM4_ECB;
    BYTE ch[16]; memset(ch, 0, sizeof(ch));
    mark("GenRandom");
    ULONG rc = SKF_GenRandom(dev, ch, 8); pr("GenRandom", rc);
    HANDLE hk = NULL;
    mark("SetSymmKey");
    rc = SKF_SetSymmKey(dev, (BYTE *)argv[1], alg, &hk); pr("SetSymmKey", rc);
    BLOCKCIPHERPARAM p; memset(&p, 0, sizeof(p));
    mark("EncryptInit");
    rc = SKF_EncryptInit(hk, p); pr("EncryptInit", rc);
    BYTE out[32]; ULONG outlen = sizeof(out);
    mark("Encrypt");
    rc = SKF_Encrypt(hk, ch, sizeof(ch), out, &outlen); pr("Encrypt", rc);
    printf("cipher len=%lu: ", (unsigned long)outlen);
    for (ULONG i = 0; i < outlen; i++) printf("%02x", out[i]);
    printf("\n");
    if (hk) SKF_CloseHandle(hk);
    mark("DevAuth");
    rc = SKF_DevAuth(dev, out, outlen); pr("DevAuth", rc);
    mark("Done");
    SKF_DisConnectDev(dev);
    free(names);
    return 0;
}
