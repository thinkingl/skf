#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "skf.h"

static void mark(const char *s)
{
    const char *p = getenv("SG_TRACE");
    if (!p || !*p) p = "/tmp/sg_trace.log";
    int fd = open(p, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { dprintf(fd, "=== MARK %s ===\n", s); close(fd); }
}
static void pr(const char *w, ULONG rc) { printf("%-30s 0x%08lx\n", w, (unsigned long)rc); }

int main(void)
{
    ULONG len = 0;
    SKF_EnumDev(TRUE, NULL, &len);
    char *names = calloc(1, len + 1);
    SKF_EnumDev(TRUE, (LPSTR)names, &len);
    DEVHANDLE dev = NULL;
    if (SKF_ConnectDev((LPSTR)names, &dev) != SAR_OK) return 1;

    BYTE key[16];
    for (int i = 0; i < 16; i++) key[i] = (BYTE)(0x10 + i);
    BLOCKCIPHERPARAM p;
    memset(&p, 0, sizeof(p));
    p.IVLen = 0;
    p.PaddingType = 0;

    HANDLE h = NULL;
    mark("SetSymmKey");
    ULONG rc = SKF_SetSymmKey(dev, key, SGD_SM4_ECB, &h);
    pr("SetSymmKey", rc);

    BYTE plain[16], enc[32], dec[32];
    for (int i = 0; i < 16; i++) plain[i] = (BYTE)i;
    ULONG enclen = sizeof(enc), declen = sizeof(dec);
    mark("EncryptInit");
    rc = SKF_EncryptInit(h, p); pr("EncryptInit", rc);
    mark("Encrypt");
    rc = SKF_Encrypt(h, plain, sizeof(plain), enc, &enclen); pr("Encrypt", rc);
    mark("DecryptInit");
    rc = SKF_DecryptInit(h, p); pr("DecryptInit", rc);
    mark("Decrypt");
    rc = SKF_Decrypt(h, enc, enclen, dec, &declen); pr("Decrypt", rc);

    HANDLE hm = NULL;
    mark("SetSymmKeyMAC");
    ULONG mr = SKF_SetSymmKey(dev, key, SGD_SM4_MAC, &hm);
    pr("SetSymmKeyMAC", mr);
    HANDLE hmac = NULL;
    mark("MacInit");
    ULONG ar = SKF_MacInit(hm, &p, &hmac); pr("MacInit", ar);
    BYTE mac[32]; ULONG maclen = sizeof(mac);
    mark("Mac");
    ar = SKF_Mac(hmac, plain, sizeof(plain), mac, &maclen); pr("Mac", ar);
    mark("CloseMAC");
    SKF_CloseHandle(hmac);

    HANDLE hh = NULL;
    mark("DigestInit");
    ULONG dr = SKF_DigestInit(dev, SGD_SM3, NULL, NULL, 0, &hh); pr("DigestInit", dr);
    BYTE hash[32]; ULONG hlen = sizeof(hash);
    mark("Digest");
    dr = SKF_Digest(hh, plain, sizeof(plain), hash, &hlen); pr("Digest", dr);
    mark("CloseHash");
    SKF_CloseHandle(hh);
    mark("CloseKey");
    SKF_CloseHandle(h);
    mark("Disconnect");
    SKF_DisConnectDev(dev);
    free(names);
    return 0;
}
