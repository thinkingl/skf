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

static int devauth(DEVHANDLE dev, const char *key)
{
    DEVINFO i;
    memset(&i, 0, sizeof(i));
    if (SKF_GetDevInfo(dev, &i) != SAR_OK) return -1;
    ULONG alg = i.DevAuthAlgId;
    if (alg != SGD_SM1_ECB && alg != SGD_SM4_ECB) alg = SGD_SM4_ECB;
    BYTE ch[16];
    memset(ch, 0, sizeof(ch));
    if (SKF_GenRandom(dev, ch, 8) != SAR_OK) return -1;
    HANDLE h = NULL;
    if (SKF_SetSymmKey(dev, (BYTE *)key, alg, &h) != SAR_OK) return -1;
    BLOCKCIPHERPARAM p;
    memset(&p, 0, sizeof(p));
    if (SKF_EncryptInit(h, p) != SAR_OK) return -1;
    BYTE o[32];
    ULONG ol = sizeof(o);
    if (SKF_Encrypt(h, ch, 16, o, &ol) != SAR_OK) return -1;
    SKF_CloseHandle(h);
    return SKF_DevAuth(dev, o, ol) == SAR_OK ? 0 : -1;
}

static void show_list(HAPPLICATION app, const char *tag)
{
    ULONG len = 0;
    ULONG rc = SKF_EnumFiles(app, NULL, &len);
    printf("%s EnumFiles rc=0x%lx len=%lu:", tag, (unsigned long)rc, (unsigned long)len);
    if (rc == SAR_OK && len) {
        char *buf = calloc(1, len + 1);
        rc = SKF_EnumFiles(app, (LPSTR)buf, &len);
        for (char *p = buf; p < buf + len && *p; p += strlen(p) + 1)
            printf(" [%s]", p);
        free(buf);
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <authkey> <app> <userpin>\n", argv[0]);
        return 1;
    }
    const char *authkey = argv[1], *appname = argv[2], *pin = argv[3];
    ULONG len = 0;
    SKF_EnumDev(TRUE, NULL, &len);
    char *names = calloc(1, len + 1);
    SKF_EnumDev(TRUE, (LPSTR)names, &len);
    DEVHANDLE dev = NULL;
    if (SKF_ConnectDev((LPSTR)names, &dev) != SAR_OK) return 1;
    mark("devauth");
    printf("devauth=%d\n", devauth(dev, authkey));

    HAPPLICATION app = NULL;
    mark("createapp");
    ULONG rc = SKF_CreateApplication(dev, (LPSTR)appname, (LPSTR)"123456", 6,
                                     (LPSTR)"123456", 6, SECURE_ANYONE_ACCOUNT, &app);
    printf("CreateApplication 0x%lx\n", (unsigned long)rc);
    if (app) SKF_CloseApplication(app);

    mark("openapp");
    rc = SKF_OpenApplication(dev, (LPSTR)appname, &app);
    printf("OpenApplication 0x%lx\n", (unsigned long)rc);
    ULONG retry = 0;
    if (rc == SAR_OK)
        printf("VerifyPIN 0x%lx\n", (unsigned long)SKF_VerifyPIN(app, USER_TYPE, (LPSTR)pin, &retry));

    mark("createf1");
    rc = SKF_CreateFile(app, (LPSTR)"F1.TXT", 16, SECURE_ANYONE_ACCOUNT, SECURE_ANYONE_ACCOUNT);
    printf("CreateFile F1 0x%lx\n", (unsigned long)rc);
    mark("createf2");
    rc = SKF_CreateFile(app, (LPSTR)"F2.BIN", 100, SECURE_ANYONE_ACCOUNT, SECURE_ANYONE_ACCOUNT);
    printf("CreateFile F2 0x%lx\n", (unsigned long)rc);
    mark("enum");
    show_list(app, "after create");
    FILEATTRIBUTE info;
    memset(&info, 0, sizeof(info));
    rc = SKF_GetFileInfo(app, (LPSTR)"F1.TXT", &info);
    printf("Info F1 rc=0x%lx size=%lu r=%lx w=%lx name=%s\n", (unsigned long)rc,
           (unsigned long)info.FileSize, (unsigned long)info.ReadRights,
           (unsigned long)info.WriteRights, info.FileName);
    memset(&info, 0, sizeof(info));
    rc = SKF_GetFileInfo(app, (LPSTR)"F2.BIN", &info);
    printf("Info F2 rc=0x%lx size=%lu r=%lx w=%lx name=%s\n", (unsigned long)rc,
           (unsigned long)info.FileSize, (unsigned long)info.ReadRights,
           (unsigned long)info.WriteRights, info.FileName);

    mark("writef1");
    BYTE d1[16];
    for (int i = 0; i < 16; i++) d1[i] = (BYTE)(0xa0 + i);
    printf("WriteFile F1 0x%lx\n", (unsigned long)SKF_WriteFile(app, (LPSTR)"F1.TXT", 0, d1, 16));
    mark("writef2");
    BYTE d2[100];
    for (int i = 0; i < 100; i++) d2[i] = (BYTE)i;
    printf("WriteFile F2 0x%lx\n", (unsigned long)SKF_WriteFile(app, (LPSTR)"F2.BIN", 0, d2, 100));
    mark("readf1");
    BYTE out[128];
    ULONG olen = sizeof(out);
    rc = SKF_ReadFile(app, (LPSTR)"F1.TXT", 0, 16, out, &olen);
    printf("ReadFile F1 rc=0x%lx len=%lu data=", (unsigned long)rc, (unsigned long)olen);
    for (ULONG i = 0; i < olen; i++) printf("%02x", out[i]);
    printf("\n");
    mark("readf2");
    olen = sizeof(out);
    rc = SKF_ReadFile(app, (LPSTR)"F2.BIN", 0, 100, out, &olen);
    printf("ReadFile F2 rc=0x%lx len=%lu first=", (unsigned long)rc, (unsigned long)olen);
    for (ULONG i = 0; i < (olen < 8 ? olen : 8); i++) printf("%02x", out[i]);
    printf("\n");
    mark("deletef1");
    printf("DeleteFile F1 0x%lx\n", (unsigned long)SKF_DeleteFile(app, (LPSTR)"F1.TXT"));
    mark("enum2");
    show_list(app, "after delete F1");
    mark("deletef2");
    printf("DeleteFile F2 0x%lx\n", (unsigned long)SKF_DeleteFile(app, (LPSTR)"F2.BIN"));
    SKF_CloseApplication(app);
    SKF_DisConnectDev(dev);

    mark("reconnect");
    dev = NULL;
    if (SKF_ConnectDev((LPSTR)names, &dev) != SAR_OK) return 1;
    printf("devauth2=%d\n", devauth(dev, authkey));
    mark("deleteapp");
    printf("DeleteApplication 0x%lx\n", (unsigned long)SKF_DeleteApplication(dev, (LPSTR)appname));
    SKF_DisConnectDev(dev);
    free(names);
    return 0;
}
