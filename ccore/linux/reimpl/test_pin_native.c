#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skf.h"

static void pr(const char *w, ULONG rc) { printf("%-36s 0x%08lx\n", w, (unsigned long)rc); }

int main(int argc, char **argv)
{
    if (argc < 2) return 1;
    ULONG len = 0;
    SKF_EnumDev(TRUE, NULL, &len);
    char *names = calloc(1, len + 1);
    SKF_EnumDev(TRUE, (LPSTR)names, &len);
    DEVHANDLE dev = NULL;
    if (SKF_ConnectDev((LPSTR)names, &dev) != SAR_OK) return 1;
    HAPPLICATION app = NULL;
    ULONG rc = SKF_OpenApplication(dev, argv[1], &app);
    pr("OpenApplication", rc);
    if (rc != SAR_OK) return 1;
    ULONG retry = 0;
    rc = SKF_VerifyPIN(app, USER_TYPE, (LPSTR)"123456", &retry);
    pr("VerifyPIN(123456)", rc);
    rc = SKF_ChangePIN(app, USER_TYPE, (LPSTR)"123456", (LPSTR)"654321", &retry);
    pr("ChangePIN(123456->654321)", rc);
    retry = 0;
    rc = SKF_VerifyPIN(app, USER_TYPE, (LPSTR)"654321", &retry);
    pr("VerifyPIN(654321)", rc);
    retry = 0;
    rc = SKF_ChangePIN(app, USER_TYPE, (LPSTR)"654321", (LPSTR)"123456", &retry);
    pr("ChangePIN(654321->123456)", rc);
    for (int i = 0; i < 6; i++) { retry = 0; SKF_VerifyPIN(app, USER_TYPE, (LPSTR)"000000", &retry); }
    retry = 0;
    rc = SKF_UnblockPIN(app, (LPSTR)"123456", (LPSTR)"123456", &retry);
    pr("UnblockPIN(admin 123456)", rc);
    retry = 0;
    rc = SKF_VerifyPIN(app, USER_TYPE, (LPSTR)"123456", &retry);
    pr("VerifyPIN(after unblock)", rc);
    SKF_CloseApplication(app);
    SKF_DisConnectDev(dev);
    free(names);
    return 0;
}
