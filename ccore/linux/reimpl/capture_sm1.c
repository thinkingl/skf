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
int main(void)
{
    ULONG len = 0; SKF_EnumDev(TRUE, NULL, &len);
    char *names = calloc(1, len + 1); SKF_EnumDev(TRUE, (LPSTR)names, &len);
    DEVHANDLE dev = NULL;
    if (SKF_ConnectDev((LPSTR)names, &dev) != SAR_OK) return 1;
    BYTE key[16];
    for (int i = 0; i < 16; i++) key[i] = (BYTE)(0x10 + i);
    BLOCKCIPHERPARAM p; memset(&p, 0, sizeof(p));
    HANDLE h = NULL;
    mark("SetSymmKeySM1");
    ULONG rc = SKF_SetSymmKey(dev, key, SGD_SM1_ECB, &h);
    printf("SetSymmKeySM1 0x%lx\n", (unsigned long)rc);
    if (rc != SAR_OK) return 1;
    mark("EncryptInitSM1");
    rc = SKF_EncryptInit(h, p); printf("EncryptInit 0x%lx\n", (unsigned long)rc);
    BYTE plain[16], enc[32]; for (int i=0;i<16;i++) plain[i]=(BYTE)i;
    ULONG enclen = sizeof(enc);
    mark("EncryptSM1");
    rc = SKF_Encrypt(h, plain, 16, enc, &enclen); printf("Encrypt 0x%lx len=%lu: ", (unsigned long)rc, (unsigned long)enclen);
    for (ULONG i = 0; i < enclen; i++) printf("%02x", enc[i]);
    printf("\n");
    SKF_CloseHandle(h);
    SKF_DisConnectDev(dev);
    free(names);
    return 0;
}
