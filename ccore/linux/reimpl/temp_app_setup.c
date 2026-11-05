#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skf.h"

static int devauth(DEVHANDLE dev, const char *key)
{
    DEVINFO info;
    memset(&info, 0, sizeof(info));
    if (SKF_GetDevInfo(dev, &info) != SAR_OK) return -1;
    ULONG alg = info.DevAuthAlgId;
    if (alg != SGD_SM1_ECB && alg != SGD_SM4_ECB) alg = SGD_SM4_ECB;
    BYTE ch[16]; memset(ch, 0, sizeof(ch));
    if (SKF_GenRandom(dev, ch, 8) != SAR_OK) return -1;
    HANDLE hk = NULL;
    if (SKF_SetSymmKey(dev, (BYTE *)key, alg, &hk) != SAR_OK) return -1;
    BLOCKCIPHERPARAM p; memset(&p, 0, sizeof(p));
    if (SKF_EncryptInit(hk, p) != SAR_OK) return -1;
    BYTE out[32]; ULONG outlen = sizeof(out);
    if (SKF_Encrypt(hk, ch, sizeof(ch), out, &outlen) != SAR_OK) return -1;
    SKF_CloseHandle(hk);
    return SKF_DevAuth(dev, out, outlen) == SAR_OK ? 0 : -1;
}

int main(int argc, char **argv)
{
    if (argc < 3) { fprintf(stderr, "usage: %s AUTH_KEY APP_NAME\n", argv[0]); return 1; }
    ULONG len = 0;
    SKF_EnumDev(TRUE, NULL, &len);
    char *names = calloc(1, len + 1);
    SKF_EnumDev(TRUE, (LPSTR)names, &len);
    DEVHANDLE dev = NULL;
    if (SKF_ConnectDev((LPSTR)names, &dev) != SAR_OK) return 1;
    if (devauth(dev, argv[1]) != 0) { fprintf(stderr, "devauth failed\n"); return 1; }
    HAPPLICATION app = NULL;
    ULONG rc = SKF_CreateApplication(dev, argv[2], (LPSTR)"123456", 6,
                                     (LPSTR)"123456", 6, SECURE_ANYONE_ACCOUNT, &app);
    printf("CreateApplication %s: 0x%lx\n", argv[2], (unsigned long)rc);
    if (app) SKF_CloseApplication(app);
    SKF_DisConnectDev(dev);
    free(names);
    return rc == SAR_OK ? 0 : 1;
}
