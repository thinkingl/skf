#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skf.h"

static const char *errname(ULONG r) {
    switch (r) {
    case SAR_OK: return "SAR_OK";
    case SAR_FAIL: return "SAR_FAIL";
    case SAR_UNKNOWNERR: return "SAR_UNKNOWNERR";
    case SAR_NOTSUPPORTYETERR: return "SAR_NOTSUPPORTYETERR";
    case SAR_INVALIDHANDLEERR: return "SAR_INVALIDHANDLEERR";
    case SAR_INVALIDPARAMERR: return "SAR_INVALIDPARAMERR";
    case SAR_PIN_INCORRECT: return "SAR_PIN_INCORRECT";
    case SAR_PIN_LOCKED: return "SAR_PIN_LOCKED";
    case SAR_PIN_INVALID: return "SAR_PIN_INVALID";
    case SAR_PIN_LEN_RANGE: return "SAR_PIN_LEN_RANGE";
    case SAR_USER_PIN_NOT_INITIALIZED: return "SAR_USER_PIN_NOT_INITIALIZED";
    case SAR_USER_TYPE_INVALID: return "SAR_USER_TYPE_INVALID";
    case SAR_APPLICATION_NOT_EXISTS: return "SAR_APPLICATION_NOT_EXISTS";
    default: return "?";
    }
}

static void pin_info(HAPPLICATION app, ULONG type, const char *label) {
    ULONG max = 0, remain = 0;
    BOOL def = 0;
    LONG r = SKF_GetPINInfo(app, type, &max, &remain, &def);
    printf("    %-10s type=%lu GetPINInfo r=0x%lx (%s) max=%lu remain=%lu default=%ld\n",
           label, (unsigned long)type, (unsigned long)r, errname((ULONG)r),
           (unsigned long)max, (unsigned long)remain, (long)def);
}

int main(int argc, char **argv) {
    const char *pin = argc > 1 ? argv[1] : "123456";
    ULONG len = 0;
    ULONG r = SKF_EnumDev(TRUE, NULL, &len);
    if (r != SAR_OK || len == 0) {
        printf("SKF_EnumDev r=0x%lx (%s) len=%lu\n", (unsigned long)r, errname(r), (unsigned long)len);
        return 1;
    }
    char *names = calloc(1, len + 1);
    r = SKF_EnumDev(TRUE, (LPSTR)names, &len);
    if (r != SAR_OK) return 1;

    char *devname = names;
    printf("device: %s\n", devname);
    DEVHANDLE h = NULL;
    r = SKF_ConnectDev((LPSTR)devname, &h);
    printf("SKF_ConnectDev r=0x%lx (%s)\n", (unsigned long)r, errname(r));
    if (r != SAR_OK) return 1;

    ULONG alen = 0;
    r = SKF_EnumApplication(h, NULL, &alen);
    if (r != SAR_OK || alen == 0) {
        printf("SKF_EnumApplication r=0x%lx (%s) len=%lu\n", (unsigned long)r, errname(r), (unsigned long)alen);
        SKF_DisConnectDev(h);
        return 1;
    }
    char *apps = calloc(1, alen + 1);
    r = SKF_EnumApplication(h, (LPSTR)apps, &alen);
    if (r != SAR_OK) return 1;

    for (char *a = apps; a < apps + alen && *a; a += strlen(a) + 1) {
        printf("\napp: %s\n", a);
        HAPPLICATION ha = NULL;
        r = SKF_OpenApplication(h, (LPSTR)a, &ha);
        printf("  SKF_OpenApplication r=0x%lx (%s) handle=%p\n", (unsigned long)r, errname(r), ha);
        if (r != SAR_OK) continue;

        pin_info(ha, ADMIN_TYPE, "ADMIN");
        pin_info(ha, USER_TYPE, "USER");

        SKF_CloseApplication(ha);
    }

    printf("\n-- try PIN %s on KEDA/USER --\n", pin);
    HAPPLICATION ha = NULL;
    r = SKF_OpenApplication(h, (LPSTR)"KEDA", &ha);
    if (r != SAR_OK) {
        printf("open KEDA r=0x%lx (%s)\n", (unsigned long)r, errname(r));
    } else {
        ULONG max = 0, remain = 0;
        BOOL def = 0;
        LONG gi = SKF_GetPINInfo(ha, USER_TYPE, &max, &remain, &def);
        printf("KEDA/USER GetPINInfo r=0x%lx (%s) max=%lu remain=%lu default=%ld\n",
               (unsigned long)gi, errname((ULONG)gi), (unsigned long)max,
               (unsigned long)remain, (long)def);

        BOOL can_try = (gi != SAR_OK) || (remain > 1) || def;
        if (!can_try) {
            printf("not trying: remaining attempts too low (%lu)\n", (unsigned long)remain);
        } else {
            ULONG retry = 0;
            ULONG vr = SKF_VerifyPIN(ha, USER_TYPE, (LPSTR)pin, &retry);
            printf("KEDA/USER VerifyPIN(%s) r=0x%lx (%s) retry=%lu\n", pin,
                   (unsigned long)vr, errname(vr), (unsigned long)retry);
        }
        SKF_CloseApplication(ha);
    }

    free(apps);
    free(names);
    SKF_DisConnectDev(h);
    return 0;
}
