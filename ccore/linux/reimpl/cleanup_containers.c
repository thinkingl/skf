#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skf.h"

int main(void)
{
    ULONG len = 0;
    SKF_EnumDev(TRUE, NULL, &len);
    char *names = calloc(1, len + 1);
    SKF_EnumDev(TRUE, (LPSTR)names, &len);
    DEVHANDLE dev = NULL;
    if (SKF_ConnectDev((LPSTR)names, &dev) != SAR_OK) return 1;
    HAPPLICATION app = NULL;
    if (SKF_OpenApplication(dev, (LPSTR)"KEDA", &app) != SAR_OK) return 1;
    ULONG retry = 0;
    if (SKF_VerifyPIN(app, USER_TYPE, (LPSTR)"123456", &retry) != SAR_OK) return 1;
    ULONG clen = 0;
    SKF_EnumContainer(app, NULL, &clen);
    char *ctns = calloc(1, clen + 1);
    SKF_EnumContainer(app, (LPSTR)ctns, &clen);
    for (char *p = ctns; p < ctns + clen && *p; p += strlen(p) + 1) {
        if (strncmp(p, "SKFC", 4) == 0) {
            ULONG rc = SKF_DeleteContainer(app, (LPSTR)p);
            printf("delete %s: 0x%lx\n", p, (unsigned long)rc);
        }
    }
    SKF_CloseApplication(app);
    SKF_DisConnectDev(dev);
    free(names); free(ctns);
    return 0;
}
