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
    case SAR_FILEERR: return "SAR_FILEERR";
    case SAR_INVALIDHANDLEERR: return "SAR_INVALIDHANDLEERR";
    case SAR_INVALIDPARAMERR: return "SAR_INVALIDPARAMERR";
    case SAR_READFILEERR: return "SAR_READFILEERR";
    case SAR_NAMELENERR: return "SAR_NAMELENERR";
    case SAR_DEVICE_REMOVED: return "SAR_DEVICE_REMOVED";
    default: return "?";
    }
}

int main(void) {
    ULONG len = 0;
    ULONG r = SKF_EnumDev(TRUE, NULL, &len);
    printf("SKF_EnumDev(NULL) r=0x%lx (%s) len=%lu\n", (unsigned long)r, errname(r), (unsigned long)len);
    if (r != SAR_OK || len == 0) return 1;

    char *names = calloc(1, len + 1);
    r = SKF_EnumDev(TRUE, (LPSTR)names, &len);
    printf("SKF_EnumDev(list) r=0x%lx (%s) len=%lu\n", (unsigned long)r, errname(r), (unsigned long)len);
    if (r != SAR_OK) return 1;

    for (char *p = names; p < names + len && *p; p += strlen(p) + 1) {
        printf("\ndevice: %s\n", p);

        ULONG state = 0;
        ULONG sr = SKF_GetDevState((LPSTR)p, &state);
        printf("  SKF_GetDevState r=0x%lx (%s) state=0x%lx\n", (unsigned long)sr, errname(sr), (unsigned long)state);

        DEVHANDLE h = NULL;
        r = SKF_ConnectDev((LPSTR)p, &h);
        printf("  SKF_ConnectDev r=0x%lx (%s) handle=%p\n", (unsigned long)r, errname(r), h);
        if (r != SAR_OK) continue;

        DEVINFO info;
        memset(&info, 0, sizeof(info));
        r = SKF_GetDevInfo(h, &info);
        printf("  SKF_GetDevInfo r=0x%lx (%s)\n", (unsigned long)r, errname(r));
        if (r == SAR_OK) {
            printf("    Version=%u.%u\n", info.Version.major, info.Version.minor);
            printf("    Manufacturer=%.64s\n", info.Manufacturer);
            printf("    Issuer=%.64s\n", info.Issuer);
            printf("    Label=%.32s\n", info.Label);
            printf("    SerialNumber=%.32s\n", info.SerialNumber);
            printf("    HWVersion=%u.%u FirmwareVersion=%u.%u\n",
                   info.HWVersion.major, info.HWVersion.minor,
                   info.FirmwareVersion.major, info.FirmwareVersion.minor);
            printf("    AlgSymCap=0x%lx AlgAsymCap=0x%lx AlgHashCap=0x%lx\n",
                   (unsigned long)info.AlgSymCap, (unsigned long)info.AlgAsymCap, (unsigned long)info.AlgHashCap);
            printf("    TotalSpace=%lu FreeSpace=%lu MaxECCBufferSize=%lu MaxBufferSize=%lu\n",
                   (unsigned long)info.TotalSpace, (unsigned long)info.FreeSpace,
                   (unsigned long)info.MaxECCBufferSize, (unsigned long)info.MaxBufferSize);
        }

        ULONG alen = 0;
        r = SKF_EnumApplication(h, NULL, &alen);
        printf("  SKF_EnumApplication(NULL) r=0x%lx (%s) len=%lu\n", (unsigned long)r, errname(r), (unsigned long)alen);
        if (r == SAR_OK && alen > 0) {
            char *apps = calloc(1, alen + 1);
            r = SKF_EnumApplication(h, (LPSTR)apps, &alen);
            printf("  SKF_EnumApplication(list) r=0x%lx (%s) len=%lu\n", (unsigned long)r, errname(r), (unsigned long)alen);
            if (r == SAR_OK) {
                for (char *a = apps; a < apps + alen && *a; a += strlen(a) + 1) {
                    printf("    app: %s\n", a);
                    HAPPLICATION ha = NULL;
                    ULONG ar = SKF_OpenApplication(h, (LPSTR)a, &ha);
                    printf("      SKF_OpenApplication r=0x%lx (%s) handle=%p\n", (unsigned long)ar, errname(ar), ha);
                    if (ar == SAR_OK) {
                        ULONG clen = 0;
                        ULONG cr = SKF_EnumContainer(ha, NULL, &clen);
                        printf("      SKF_EnumContainer(NULL) r=0x%lx (%s) len=%lu\n", (unsigned long)cr, errname(cr), (unsigned long)clen);
                        if (cr == SAR_OK && clen > 0) {
                            char *ctns = calloc(1, clen + 1);
                            cr = SKF_EnumContainer(ha, (LPSTR)ctns, &clen);
                            printf("      SKF_EnumContainer(list) r=0x%lx (%s) len=%lu\n", (unsigned long)cr, errname(cr), (unsigned long)clen);
                            if (cr == SAR_OK) {
                                for (char *c = ctns; c < ctns + clen && *c; c += strlen(c) + 1)
                                    printf("        container: %s\n", c);
                            }
                            free(ctns);
                        }
                        SKF_CloseApplication(ha);
                    }
                }
            }
            free(apps);
        }

        BYTE rnd[16];
        memset(rnd, 0, sizeof(rnd));
        r = SKF_GenRandom(h, rnd, sizeof(rnd));
        printf("  SKF_GenRandom r=0x%lx (%s) data=", (unsigned long)r, errname(r));
        for (size_t k = 0; k < sizeof(rnd); k++) printf("%02x", rnd[k]);
        printf("\n");

        r = SKF_DisConnectDev(h);
        printf("  SKF_DisConnectDev r=0x%lx (%s)\n", (unsigned long)r, errname(r));
    }

    free(names);
    return 0;
}
