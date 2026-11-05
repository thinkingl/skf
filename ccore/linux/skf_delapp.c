#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skf.h"

static const char *errname(ULONG r) {
    switch (r) {
    case SAR_OK: return "SAR_OK";
    case SAR_FAIL: return "SAR_FAIL";
    case SAR_UNKNOWNERR: return "SAR_UNKNOWNERR";
    case SAR_INVALIDHANDLEERR: return "SAR_INVALIDHANDLEERR";
    case SAR_INVALIDPARAMERR: return "SAR_INVALIDPARAMERR";
    case SAR_USER_NOT_LOGGED_IN: return "SAR_USER_NOT_LOGGED_IN";
    case SAR_PIN_INCORRECT: return "SAR_PIN_INCORRECT";
    case SAR_PIN_LOCKED: return "SAR_PIN_LOCKED";
    case SAR_FILE_NOT_EXIST: return "SAR_FILE_NOT_EXIST";
    case SAR_APPLICATION_EXISTS: return "SAR_APPLICATION_EXISTS";
    case SAR_APPLICATION_NOT_EXISTS: return "SAR_APPLICATION_NOT_EXISTS";
    default: return "?";
    }
}

static int has_app(const char *list, ULONG len, const char *name) {
    for (const char *p = list; p < list + len && *p; p += strlen(p) + 1)
        if (strcmp(p, name) == 0) return 1;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s DEVICE_AUTH_KEY APP_NAME\n", argv[0]);
        return 1;
    }
    const char *key = argv[1];
    const char *app = argv[2];
    if (strlen(key) != 16) {
        fprintf(stderr, "device auth key must be 16 bytes\n");
        return 1;
    }

    ULONG len = 0, rc = SKF_EnumDev(TRUE, NULL, &len);
    char *names = NULL;
    if (rc == SAR_OK && len > 0) {
        names = calloc(1, len + 1);
        rc = SKF_EnumDev(TRUE, (LPSTR)names, &len);
    }
    if (rc != SAR_OK || !names) { fprintf(stderr, "EnumDev: 0x%lx\n", (unsigned long)rc); return 1; }

    DEVHANDLE hDev = NULL;
    rc = SKF_ConnectDev((LPSTR)names, &hDev);
    if (rc != SAR_OK) { fprintf(stderr, "ConnectDev: 0x%lx\n", (unsigned long)rc); return 1; }

    DEVINFO info;
    memset(&info, 0, sizeof(info));
    rc = SKF_GetDevInfo(hDev, &info);
    if (rc != SAR_OK) { fprintf(stderr, "GetDevInfo: 0x%lx\n", (unsigned long)rc); SKF_DisConnectDev(hDev); return 1; }

    ULONG alg = info.DevAuthAlgId;
    if (alg != SGD_SM1_ECB && alg != SGD_SM4_ECB) alg = SGD_SM4_ECB;

    BYTE challenge[16];
    memset(challenge, 0, sizeof(challenge));
    rc = SKF_GenRandom(hDev, challenge, 8);
    HANDLE hKey = NULL;
    if (rc == SAR_OK) rc = SKF_SetSymmKey(hDev, (BYTE *)key, alg, &hKey);
    BLOCKCIPHERPARAM param;
    memset(&param, 0, sizeof(param));
    if (rc == SAR_OK) rc = SKF_EncryptInit(hKey, param);
    BYTE wrapped[32];
    ULONG wrappedlen = sizeof(wrapped);
    if (rc == SAR_OK) rc = SKF_Encrypt(hKey, challenge, 16, wrapped, &wrappedlen);
    if (hKey) SKF_CloseHandle(hKey);
    if (rc == SAR_OK) rc = SKF_DevAuth(hDev, wrapped, wrappedlen);
    printf("DevAuth: rc=0x%08lx (%s) alg=0x%lx\n", (unsigned long)rc, errname(rc), (unsigned long)alg);
    if (rc != SAR_OK) { SKF_DisConnectDev(hDev); return 1; }

    ULONG alen = 0;
    rc = SKF_EnumApplication(hDev, NULL, &alen);
    char *apps = NULL;
    if (rc == SAR_OK && alen > 0) {
        apps = calloc(1, alen + 1);
        rc = SKF_EnumApplication(hDev, (LPSTR)apps, &alen);
    }
    if (rc != SAR_OK) { fprintf(stderr, "EnumApplication: 0x%lx\n", (unsigned long)rc); SKF_DisConnectDev(hDev); return 1; }
    printf("apps before: ");
    for (const char *p = apps; p < apps + alen && *p; p += strlen(p) + 1) printf("%s ", p);
    printf("\n");
    if (!has_app(apps, alen, app)) { printf("app %s does not exist\n", app); SKF_DisConnectDev(hDev); return 0; }

    rc = SKF_DeleteApplication(hDev, (LPSTR)app);
    printf("DeleteApplication(direct): rc=0x%08lx (%s)\n", (unsigned long)rc, errname(rc));

    if (rc != SAR_OK) {
        HAPPLICATION hApp = NULL;
        rc = SKF_OpenApplication(hDev, (LPSTR)app, &hApp);
        printf("OpenApplication: rc=0x%08lx (%s)\n", (unsigned long)rc, errname(rc));
        if (rc == SAR_OK) {
            ULONG retry = 0;
            rc = SKF_VerifyPIN(hApp, ADMIN_TYPE, (LPSTR)"123456", &retry);
            printf("VerifyPIN(ADMIN 123456): rc=0x%08lx (%s) retry=%lu\n",
                   (unsigned long)rc, errname(rc), (unsigned long)retry);
            rc = SKF_DeleteApplication(hDev, (LPSTR)app);
            printf("DeleteApplication(while open): rc=0x%08lx (%s)\n", (unsigned long)rc, errname(rc));
            SKF_CloseApplication(hApp);
        }
    }

    alen = 0;
    rc = SKF_EnumApplication(hDev, NULL, &alen);
    free(apps); apps = NULL;
    if (rc == SAR_OK && alen > 0) {
        apps = calloc(1, alen + 1);
        rc = SKF_EnumApplication(hDev, (LPSTR)apps, &alen);
    }
    printf("apps after: ");
    for (const char *p = apps; p < apps + alen && *p; p += strlen(p) + 1) printf("%s ", p);
    printf("\n");

    SKF_DisConnectDev(hDev);
    free(names);
    free(apps);
    return 0;
}
