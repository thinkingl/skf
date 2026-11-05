#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "skf.h"

static FILE *rep;
static int failures;

static const char *errname(ULONG r) {
    switch (r) {
    case SAR_OK: return "SAR_OK";
    case SAR_FILE_NOT_EXIST: return "SAR_FILE_NOT_EXIST";
    case SAR_FILE_ALREADY_EXIST: return "SAR_FILE_ALREADY_EXIST";
    case SAR_APPLICATION_NOT_EXISTS: return "SAR_APPLICATION_NOT_EXISTS";
    case SAR_APPLICATION_EXISTS: return "SAR_APPLICATION_EXISTS";
    case SAR_INVALIDHANDLEERR: return "SAR_INVALIDHANDLEERR";
    case SAR_INVALIDPARAMERR: return "SAR_INVALIDPARAMERR";
    case SAR_USER_PIN_NOT_INITIALIZED: return "SAR_USER_PIN_NOT_INITIALIZED";
    case SAR_USER_NOT_LOGGED_IN: return "SAR_USER_NOT_LOGGED_IN";
    case SAR_PIN_INCORRECT: return "SAR_PIN_INCORRECT";
    case SAR_PIN_LOCKED: return "SAR_PIN_LOCKED";
    case SAR_NO_ROOM: return "SAR_NO_ROOM";
    default: return "?";
    }
}

static void rec(const char *what, ULONG rc, const char *note) {
    const char *status = rc == SAR_OK ? "PASS" : "FAIL";
    if (rc != SAR_OK) failures++;
    fprintf(rep, "| `%s` | %s | `0x%08lx` (%s) | %s |\n",
            what, status, (unsigned long)rc, errname(rc), note ? note : "");
    printf("[%s] %-32s rc=0x%08lx (%s) %s\n",
           status, what, (unsigned long)rc, errname(rc), note ? note : "");
}

static void rec_skip(const char *what, ULONG rc, const char *note) {
    fprintf(rep, "| `%s` | SKIP | `0x%08lx` (%s) | %s |\n",
            what, (unsigned long)rc, errname(rc), note ? note : "");
    printf("[SKIP] %-32s rc=0x%08lx (%s) %s\n",
           what, (unsigned long)rc, errname(rc), note ? note : "");
}

static int has_name(const char *list, ULONG len, const char *name) {
    for (const char *p = list; p < list + len && *p; p += strlen(p) + 1)
        if (strcmp(p, name) == 0) return 1;
    return 0;
}

int main(void) {
    rep = fopen("destructive-report.md", "w");
    if (!rep) { perror("destructive-report.md"); return 1; }

    unsigned id = (unsigned)getpid() % 100000;
    char appname[32], ctnname[32], filename[32];
    snprintf(appname, sizeof(appname), "SKFT%u", id);
    snprintf(ctnname, sizeof(ctnname), "SKFC%u", id);
    snprintf(filename, sizeof(filename), "SKFF%u.TMP", id);

    fprintf(rep, "# SKF destructive app/container test\n\n");
    fprintf(rep, "Temporary names: app `%s`, container `%s`, file `%s`\n\n",
            appname, ctnname, filename);
    fprintf(rep, "| Operation | Status | Return | Note |\n");
    fprintf(rep, "| --- | --- | --- | --- |\n");

    ULONG len = 0, rc = SKF_EnumDev(TRUE, NULL, &len);
    char *names = NULL;
    if (rc == SAR_OK && len > 0) {
        names = calloc(1, len + 1);
        rc = SKF_EnumDev(TRUE, (LPSTR)names, &len);
    }
    rec("SKF_EnumDev", rc, "find device");
    if (rc != SAR_OK || !names) return 1;

    DEVHANDLE hDev = NULL;
    rc = SKF_ConnectDev((LPSTR)names, &hDev);
    rec("SKF_ConnectDev", rc, names);
    if (rc != SAR_OK || !hDev) return 1;

    ULONG alen = 0;
    rc = SKF_EnumApplication(hDev, NULL, &alen);
    char *apps = NULL;
    if (rc == SAR_OK && alen > 0) {
        apps = calloc(1, alen + 1);
        rc = SKF_EnumApplication(hDev, (LPSTR)apps, &alen);
    }
    rec("SKF_EnumApplication", rc, "before test");
    int app_exists = apps && has_name(apps, alen, appname);

    HAPPLICATION hApp = NULL;
    int created_app = 0;
    if (!app_exists) {
        rc = SKF_CreateApplication(hDev, (LPSTR)appname, (LPSTR)"123456", 6,
                                   (LPSTR)"123456", 6, SECURE_ANYONE_ACCOUNT, &hApp);
        if (rc == SAR_USER_NOT_LOGGED_IN)
            rec_skip("SKF_CreateApplication", rc,
                     "needs device auth; using KEDA for the container test");
        else
            rec("SKF_CreateApplication", rc, appname);
        created_app = (rc == SAR_OK);
    } else {
        rec("SKF_CreateApplication", SAR_APPLICATION_EXISTS, "name collision; not created");
    }

    if (created_app) {
        ULONG retry = 0;
        if (hApp) {
            rc = SKF_CloseApplication(hApp);
            rec("SKF_CloseApplication(after create)", rc, appname);
            hApp = NULL;
        }
        rc = SKF_OpenApplication(hDev, (LPSTR)appname, &hApp);
        rec("SKF_OpenApplication(temp)", rc, appname);
        if (rc == SAR_OK) {
            rc = SKF_VerifyPIN(hApp, USER_TYPE, (LPSTR)"123456", &retry);
            rec("SKF_VerifyPIN(temp 123456)", rc, "new app user PIN");

            rc = SKF_ChangePIN(hApp, USER_TYPE, (LPSTR)"123456", (LPSTR)"654321", &retry);
            rec("SKF_ChangePIN(temp 123456->654321)", rc, "change only the temporary app PIN");
            if (rc == SAR_OK) {
                rc = SKF_VerifyPIN(hApp, USER_TYPE, (LPSTR)"654321", &retry);
                rec("SKF_VerifyPIN(temp 654321)", rc, "verify changed temp PIN");
                retry = 0;
                rc = SKF_ChangePIN(hApp, USER_TYPE, (LPSTR)"654321", (LPSTR)"123456", &retry);
                rec("SKF_ChangePIN(temp 654321->123456)", rc, "restore temp PIN");
            }

            rc = SKF_CreateFile(hApp, (LPSTR)filename, 64,
                                SECURE_ANYONE_ACCOUNT, SECURE_ANYONE_ACCOUNT);
            rec("SKF_CreateFile(temp)", rc, filename);
            if (rc == SAR_OK) {
                BYTE data[] = "hello-skf";
                rc = SKF_WriteFile(hApp, (LPSTR)filename, 0, data, sizeof(data));
                rec("SKF_WriteFile(temp)", rc, filename);
                BYTE out[64];
                ULONG outlen = sizeof(out);
                rc = SKF_ReadFile(hApp, (LPSTR)filename, 0, sizeof(data), out, &outlen);
                rec("SKF_ReadFile(temp)", rc, filename);
                FILEATTRIBUTE fa;
                memset(&fa, 0, sizeof(fa));
                rc = SKF_GetFileInfo(hApp, (LPSTR)filename, &fa);
                rec("SKF_GetFileInfo(temp)", rc, filename);
                rc = SKF_DeleteFile(hApp, (LPSTR)filename);
                rec("SKF_DeleteFile(temp)", rc, filename);
            }

        }
    }

    /* Container test: use the temporary app if it exists, otherwise KEDA. */
    HAPPLICATION hCApp = hApp;
    int temp_app_open = 0;
    if (created_app && hApp) {
        temp_app_open = 1;
    } else {
        HAPPLICATION hKeda = NULL;
        rc = SKF_OpenApplication(hDev, (LPSTR)"KEDA", &hKeda);
        rec("SKF_OpenApplication(KEDA)", rc, "fallback for container test");
        if (rc == SAR_OK) {
            ULONG retry = 0;
            rc = SKF_VerifyPIN(hKeda, USER_TYPE, (LPSTR)"123456", &retry);
            rec("SKF_VerifyPIN(KEDA 123456)", rc, "container test");
            hCApp = hKeda;
        }
    }

    if (hCApp) {
        if (temp_app_open) {
            HCONTAINER hCtn = NULL;
            rc = SKF_CreateContainer(hCApp, (LPSTR)ctnname, &hCtn);
            rec("SKF_CreateContainer(temp app)", rc, ctnname);
            if (rc == SAR_OK && hCtn) {
                ULONG ctype = 0;
                rc = SKF_GetContainerType(hCtn, &ctype);
                rec("SKF_GetContainerType(temp)", rc, "created container");
                rc = SKF_CloseContainer(hCtn);
                rec("SKF_CloseContainer(temp)", rc, ctnname);
                rc = SKF_DeleteContainer(hCApp, (LPSTR)ctnname);
                rec("SKF_DeleteContainer(temp)", rc, ctnname);
            }
        } else {
            HCONTAINER hCtn = NULL;
            rc = SKF_CreateContainer(hCApp, (LPSTR)ctnname, &hCtn);
            rec("SKF_CreateContainer(KEDA)", rc, ctnname);
            if (rc == SAR_OK && hCtn) {
                ULONG ctype = 0;
                rc = SKF_GetContainerType(hCtn, &ctype);
                rec("SKF_GetContainerType(KEDA temp)", rc, ctnname);

                BYTE digest[32];
                for (int i = 0; i < 32; i++) digest[i] = (BYTE)i;
                ECCPUBLICKEYBLOB eccpub;
                memset(&eccpub, 0, sizeof(eccpub));
                rc = SKF_GenECCKeyPair(hCtn, SGD_SM2, &eccpub);
                if (rc != SAR_OK) {
                    ECCPUBLICKEYBLOB eccpub2;
                    memset(&eccpub2, 0, sizeof(eccpub2));
                    ULONG r2 = SKF_GenECCKeyPair(hCtn, SGD_SM2_1, &eccpub2);
                    if (r2 == SAR_OK) { eccpub = eccpub2; rc = r2; }
                    else rc = r2;
                }
                rec("SKF_GenECCKeyPair(KEDA temp)", rc, "tried SGD_SM2 and SGD_SM2_1");
                if (rc == SAR_OK) {
                    ECCSIGNATUREBLOB sig;
                    memset(&sig, 0, sizeof(sig));
                    ULONG sr = SKF_ECCSignData(hCtn, digest, sizeof(digest), &sig);
                    rec("SKF_ECCSignData(after GenECC)", sr, "temporary container");
                    if (sr == SAR_OK) {
                        ULONG vr = SKF_ECCVerify(hDev, &eccpub, digest, sizeof(digest), &sig);
                        rec("SKF_ECCVerify(after GenECC)", vr, "temporary container");
                    }
                }

                RSAPUBLICKEYBLOB rsapub;
                memset(&rsapub, 0, sizeof(rsapub));
                ULONG rr = SKF_GenRSAKeyPair(hCtn, 1024, &rsapub);
                rec("SKF_GenRSAKeyPair(KEDA temp)", rr, "1024-bit temporary key");
                if (rr == SAR_OK) {
                    BYTE sig[512];
                    ULONG siglen = sizeof(sig);
                    ULONG sr = SKF_RSASignData(hCtn, digest, sizeof(digest), sig, &siglen);
                    rec("SKF_RSASignData(after GenRSA)", sr, "temporary container");
                    if (sr == SAR_OK) {
                        ULONG vr = SKF_RSAVerify(hDev, &rsapub, digest, sizeof(digest), sig, siglen);
                        rec("SKF_RSAVerify(after GenRSA)", vr, "temporary container");
                    }
                    HANDLE hSess = NULL;
                    BYTE encdata[256];
                    ULONG enclen = sizeof(encdata);
                    ULONG xr = SKF_RSAExportSessionKey(hCtn, SGD_SM4_ECB, &rsapub,
                        encdata, &enclen, &hSess);
                    rec("SKF_RSAExportSessionKey(KEDA temp)", xr, "RSA-wrapped SM4 session key");
                    if (hSess) {
                        ULONG cr = SKF_CloseHandle(hSess);
                        rec("SKF_CloseHandle(RSA session)", cr, "cleanup");
                    }
                    BYTE in[128], out[512];
                    memset(in, 0x5a, sizeof(in));
                    ULONG outlen = sizeof(out);
                    ULONG pr = SKF_ExtRSAPubKeyOperation(hDev, &rsapub, in, sizeof(in), out, &outlen);
                    rec("SKF_ExtRSAPubKeyOperation(KEDA temp)", pr, "RSA public-key operation");
                }

                RSAPRIVATEKEYBLOB *ext = calloc(1, sizeof(*ext));
                if (ext) {
                    ULONG gr = SKF_GenExtRSAKey(hDev, 1024, ext);
                    rec("SKF_GenExtRSAKey(KEDA temp)", gr, "1024-bit external RSA key");
                    if (gr == SAR_OK) {
                        BYTE in[128], out[512];
                        ULONG outlen = sizeof(out);
                        memset(in, 0x33, sizeof(in));
                        ULONG pr = SKF_ExtRSAPriKeyOperation(hDev, ext, in, sizeof(in),
                                                             out, &outlen);
                        rec("SKF_ExtRSAPriKeyOperation(KEDA temp)", pr,
                            "RSA private-key operation");
                    }
                    free(ext);
                }

                rc = SKF_CloseContainer(hCtn);
                rec("SKF_CloseContainer(KEDA temp)", rc, ctnname);
                rc = SKF_DeleteContainer(hCApp, (LPSTR)ctnname);
                rec("SKF_DeleteContainer(KEDA temp)", rc, ctnname);
            }
        }
    } else {
        rec("SKF_CreateApplication/Container", SAR_FAIL, "no application handle; nothing created");
    }

    if (created_app) {
        if (hApp) {
            rc = SKF_CloseApplication(hApp);
            rec("SKF_CloseApplication(temp)", rc, appname);
            hApp = NULL;
        }
        rc = SKF_DeleteApplication(hDev, (LPSTR)appname);
        rec("SKF_DeleteApplication(temp)", rc, appname);
    }

    if (!created_app && hCApp) {
        rc = SKF_CloseApplication(hCApp);
        rec("SKF_CloseApplication(KEDA)", rc, "cleanup");
    }

    rc = SKF_DisConnectDev(hDev);
    rec("SKF_DisConnectDev", rc, "cleanup");

    fprintf(rep, "\n## Result\n\n");
    fprintf(rep, "- Failures: %d\n", failures);
    printf("\nFailures: %d\n", failures);
    if (created_app)
        printf("Temporary app: %s\n", appname);
    if (failures)
        printf("WARNING: some temporary objects may remain; inspect with skf_test_generic.\n");

    fclose(rep);
    free(names);
    free(apps);
    return failures ? 2 : 0;
}
