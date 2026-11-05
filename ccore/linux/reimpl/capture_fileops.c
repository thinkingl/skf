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

static void dump_list(const char *what, const char *buf, ULONG len)
{
    printf("%s len=%lu:", what, (unsigned long)len);
    for (const char *p = buf; p < buf + len && *p; p += strlen(p) + 1)
        printf(" [%s]", p);
    printf("\n");
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        fprintf(stderr, "usage: %s <authkey> <app> <userpin> <file>\n", argv[0]);
        return 1;
    }
    const char *authkey = argv[1], *appname = argv[2];
    const char *pin = argv[3], *filename = argv[4];

    ULONG len = 0;
    SKF_EnumDev(TRUE, NULL, &len);
    char *names = calloc(1, len + 1);
    SKF_EnumDev(TRUE, (LPSTR)names, &len);
    DEVHANDLE dev = NULL;
    if (SKF_ConnectDev((LPSTR)names, &dev) != SAR_OK) return 1;
    mark("devauth");
    printf("devauth=%d\n", devauth(dev, authkey));

    HAPPLICATION app = NULL;
    ULONG rc;
    mark("createapp");
    rc = SKF_CreateApplication(dev, (LPSTR)appname, (LPSTR)"123456", 6,
                               (LPSTR)"123456", 6, SECURE_ANYONE_ACCOUNT, &app);
    printf("CreateApplication 0x%lx\n", (unsigned long)rc);
    if (app) SKF_CloseApplication(app);

    mark("openapp");
    app = NULL;
    rc = SKF_OpenApplication(dev, (LPSTR)appname, &app);
    printf("OpenApplication 0x%lx\n", (unsigned long)rc);
    if (rc == SAR_OK) {
        ULONG retry = 0;
        rc = SKF_VerifyPIN(app, USER_TYPE, (LPSTR)pin, &retry);
        printf("VerifyPIN 0x%lx\n", (unsigned long)rc);

        mark("enumfiles");
        ULONG flen = 0;
        rc = SKF_EnumFiles(app, NULL, &flen);
        printf("EnumFiles(1) 0x%lx len=%lu\n", (unsigned long)rc, (unsigned long)flen);
        char *files = calloc(1, flen + 1);
        rc = SKF_EnumFiles(app, (LPSTR)files, &flen);
        printf("EnumFiles(2) 0x%lx len=%lu\n", (unsigned long)rc, (unsigned long)flen);
        dump_list("files", files, flen);
        free(files);

        mark("createfile");
        rc = SKF_CreateFile(app, (LPSTR)filename, 64,
                            SECURE_ANYONE_ACCOUNT, SECURE_ANYONE_ACCOUNT);
        printf("CreateFile 0x%lx\n", (unsigned long)rc);

        mark("enumfiles2");
        flen = 0;
        rc = SKF_EnumFiles(app, NULL, &flen);
        printf("EnumFiles(3) 0x%lx len=%lu\n", (unsigned long)rc, (unsigned long)flen);
        files = calloc(1, flen + 1);
        rc = SKF_EnumFiles(app, (LPSTR)files, &flen);
        printf("EnumFiles(4) 0x%lx len=%lu\n", (unsigned long)rc, (unsigned long)flen);
        dump_list("files2", files, flen);
        free(files);

        mark("getinfo");
        FILEATTRIBUTE info;
        memset(&info, 0, sizeof(info));
        rc = SKF_GetFileInfo(app, (LPSTR)filename, &info);
        printf("GetFileInfo 0x%lx size=%lu r=%lx w=%lx name=%s\n",
               (unsigned long)rc, (unsigned long)info.FileSize,
               (unsigned long)info.ReadRights, (unsigned long)info.WriteRights,
               info.FileName);

        mark("writefile");
        BYTE data[] = "hello-skf-file";
        rc = SKF_WriteFile(app, (LPSTR)filename, 0, data, sizeof(data));
        printf("WriteFile 0x%lx\n", (unsigned long)rc);

        mark("readfile");
        BYTE out[128];
        ULONG outlen = sizeof(out);
        rc = SKF_ReadFile(app, (LPSTR)filename, 0, sizeof(data), out, &outlen);
        printf("ReadFile 0x%lx len=%lu data=", (unsigned long)rc, (unsigned long)outlen);
        for (ULONG i = 0; i < outlen; i++) printf("%02x", out[i]);
        printf("\n");

        mark("deletefile");
        rc = SKF_DeleteFile(app, (LPSTR)filename);
        printf("DeleteFile 0x%lx\n", (unsigned long)rc);
        SKF_CloseApplication(app);
    }

    SKF_DisConnectDev(dev);
    mark("reconnect");
    dev = NULL;
    if (SKF_ConnectDev((LPSTR)names, &dev) != SAR_OK) return 1;
    printf("devauth2=%d\n", devauth(dev, authkey));
    mark("deleteapp");
    rc = SKF_DeleteApplication(dev, (LPSTR)appname);
    printf("DeleteApplication 0x%lx\n", (unsigned long)rc);
    SKF_DisConnectDev(dev);
    free(names);
    return 0;
}
