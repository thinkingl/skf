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
    if (fd >= 0) {
        dprintf(fd, "=== MARK %s ===\n", s);
        close(fd);
    }
}

static void pr(const char *what, ULONG rc)
{
    printf("%-32s rc=0x%08lx\n", what, (unsigned long)rc);
}

int main(void)
{
    ULONG len = 0, rc = SKF_EnumDev(TRUE, NULL, &len);
    char *names = calloc(1, len + 1 ? len + 1 : 1);
    mark("EnumDev");
    rc = SKF_EnumDev(TRUE, (LPSTR)names, &len);
    pr("EnumDev", rc);

    DEVHANDLE hDev = NULL;
    mark("ConnectDev");
    rc = SKF_ConnectDev((LPSTR)names, &hDev);
    pr("ConnectDev", rc);
    if (rc != SAR_OK) return 1;

    DEVINFO info;
    memset(&info, 0, sizeof(info));
    mark("GetDevInfo");
    rc = SKF_GetDevInfo(hDev, &info);
    pr("GetDevInfo", rc);
    printf("  manufacturer=%s serial=%s fw=%u.%u\n", info.Manufacturer,
           info.SerialNumber, info.FirmwareVersion.major, info.FirmwareVersion.minor);

    ULONG alen = 0;
    mark("EnumApplication-null");
    rc = SKF_EnumApplication(hDev, NULL, &alen);
    pr("EnumApplication(NULL)", rc);
    char *apps = calloc(1, alen + 1);
    mark("EnumApplication");
    rc = SKF_EnumApplication(hDev, (LPSTR)apps, &alen);
    pr("EnumApplication", rc);
    printf("  apps:");
    for (char *p = apps; p < apps + alen && *p; p += strlen(p) + 1)
        printf(" %s", p);
    printf("\n");

    HAPPLICATION hApp = NULL;
    mark("OpenApplication");
    rc = SKF_OpenApplication(hDev, (LPSTR)"KEDA", &hApp);
    pr("OpenApplication(KEDA)", rc);
    if (rc != SAR_OK) return 1;

    ULONG max = 0, remain = 0;
    BOOL def = 0;
    mark("GetPINInfo-USER");
    rc = SKF_GetPINInfo(hApp, USER_TYPE, &max, &remain, &def);
    pr("GetPINInfo(USER)", rc);
    printf("  max=%lu remain=%lu default=%d\n", (unsigned long)max,
           (unsigned long)remain, def);

    ULONG retry = 0;
    mark("VerifyPIN");
    rc = SKF_VerifyPIN(hApp, USER_TYPE, (LPSTR)"123456", &retry);
    pr("VerifyPIN(123456)", rc);
    printf("  retry=%lu\n", (unsigned long)retry);

    ULONG clen = 0;
    mark("EnumContainer-null");
    rc = SKF_EnumContainer(hApp, NULL, &clen);
    pr("EnumContainer(NULL)", rc);
    char *ctns = calloc(1, clen + 1);
    mark("EnumContainer");
    rc = SKF_EnumContainer(hApp, (LPSTR)ctns, &clen);
    pr("EnumContainer", rc);
    printf("  containers:");
    for (char *p = ctns; p < ctns + clen && *p; p += strlen(p) + 1)
        printf(" %s", p);
    printf("\n");

    HCONTAINER hCtn = NULL;
    mark("OpenContainer");
    rc = SKF_OpenContainer(hApp, (LPSTR)"K01231-85422873-3457921", &hCtn);
    pr("OpenContainer", rc);

    if (hCtn) {
        ULONG type = 0;
        mark("GetContainerType");
        rc = SKF_GetContainerType(hCtn, &type);
        pr("GetContainerType", rc);
        printf("  type=0x%lx\n", (unsigned long)type);
    }

    BYTE rnd[32];
    memset(rnd, 0, sizeof(rnd));
    mark("GenRandom");
    rc = SKF_GenRandom(hDev, rnd, sizeof(rnd));
    pr("GenRandom(32)", rc);

    if (hCtn) {
        mark("CloseContainer");
        rc = SKF_CloseContainer(hCtn);
        pr("CloseContainer", rc);
    }
    mark("CloseApplication");
    rc = SKF_CloseApplication(hApp);
    pr("CloseApplication", rc);
    mark("DisConnectDev");
    rc = SKF_DisConnectDev(hDev);
    pr("DisConnectDev", rc);
    free(names);
    free(apps);
    free(ctns);
    return 0;
}
