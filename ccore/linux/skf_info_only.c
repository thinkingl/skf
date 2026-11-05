#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skf.h"

int main(void)
{
    ULONG len = 0, rc = SKF_EnumDev(TRUE, NULL, &len);
    char *names = NULL;
    if (rc == SAR_OK && len) {
        names = calloc(1, len + 1);
        rc = SKF_EnumDev(TRUE, (LPSTR)names, &len);
    }
    printf("EnumDev rc=0x%lx name=%s\n", (unsigned long)rc, names ? names : "?");
    DEVHANDLE hDev = NULL;
    rc = SKF_ConnectDev((LPSTR)names, &hDev);
    printf("ConnectDev rc=0x%lx\n", (unsigned long)rc);
    if (rc == SAR_OK) {
        DEVINFO info;
        memset(&info, 0, sizeof(info));
        rc = SKF_GetDevInfo(hDev, &info);
        printf("GetDevInfo rc=0x%lx manufacturer=%s serial=%s fw=%u.%u\n",
               (unsigned long)rc, info.Manufacturer, info.SerialNumber,
               info.FirmwareVersion.major, info.FirmwareVersion.minor);
        SKF_DisConnectDev(hDev);
    }
    free(names);
    return 0;
}
