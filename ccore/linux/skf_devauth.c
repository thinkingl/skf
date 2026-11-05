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
    case SAR_FAIL: return "SAR_FAIL";
    case SAR_UNKNOWNERR: return "SAR_UNKNOWNERR";
    case SAR_INVALIDHANDLEERR: return "SAR_INVALIDHANDLEERR";
    case SAR_INVALIDPARAMERR: return "SAR_INVALIDPARAMERR";
    case SAR_USER_NOT_LOGGED_IN: return "SAR_USER_NOT_LOGGED_IN";
    case SAR_USER_ALREADY_LOGGED_IN: return "SAR_USER_ALREADY_LOGGED_IN";
    case SAR_PIN_INCORRECT: return "SAR_PIN_INCORRECT";
    case SAR_PIN_LOCKED: return "SAR_PIN_LOCKED";
    case SAR_FILE_NOT_EXIST: return "SAR_FILE_NOT_EXIST";
    case SAR_APPLICATION_EXISTS: return "SAR_APPLICATION_EXISTS";
    case SAR_APPLICATION_NOT_EXISTS: return "SAR_APPLICATION_NOT_EXISTS";
    case SAR_NO_ROOM: return "SAR_NO_ROOM";
    default: return "?";
    }
}

static void rec_status(const char *what, const char *status, ULONG rc,
                       const char *note) {
    if (strcmp(status, "FAIL") == 0) failures++;
    fprintf(rep, "| `%s` | %s | `0x%08lx` (%s) | %s |\n",
            what, status, (unsigned long)rc, errname(rc), note ? note : "");
    printf("[%s] %-38s rc=0x%08lx (%s) %s\n",
           status, what, (unsigned long)rc, errname(rc), note ? note : "");
}

static void rec(const char *what, ULONG rc, const char *note) {
    rec_status(what, rc == SAR_OK ? "PASS" : "FAIL", rc, note);
}

static void rec_expect(const char *what, ULONG rc, ULONG expected,
                       const char *note) {
    rec_status(what, rc == expected ? "PASS" : "FAIL", rc, note);
}

int main(int argc, char **argv) {
    if (argc < 2 || argv[1][0] == '\0') {
        fprintf(stderr, "usage: %s DEVICE_AUTH_KEY [APP_NAME]\n", argv[0]);
        return 1;
    }
    const char *key = argv[1];
    ULONG keylen = (ULONG)strlen(key);
    const char *apparg = argc > 2 ? argv[2] : NULL;

    rep = fopen("devauth-report.md", "w");
    if (!rep) { perror("devauth-report.md"); return 1; }
    fprintf(rep, "# SKF device authentication and temp app test\n\n");
    fprintf(rep, "Device auth key: user-provided %lu-byte value (not stored in this report).\n\n",
            (unsigned long)keylen);
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

    DEVINFO info;
    memset(&info, 0, sizeof(info));
    rc = SKF_GetDevInfo(hDev, &info);
    rec("SKF_GetDevInfo", rc, "read DevAuthAlgId");
    if (rc != SAR_OK) {
        SKF_DisConnectDev(hDev);
        fclose(rep);
        return 2;
    }

    ULONG alg = info.DevAuthAlgId;
    if (alg != SGD_SM1_ECB && alg != SGD_SM4_ECB)
        alg = SGD_SM4_ECB;
    if (keylen != 16) {
        fprintf(stderr, "device auth key must be 16 bytes, got %lu\n",
                (unsigned long)keylen);
        SKF_DisConnectDev(hDev);
        fclose(rep);
        return 1;
    }

    /* The vendor wrapper implements device auth as a challenge/response:
     * generate 8 random bytes, zero-pad to 16, encrypt with the device auth
     * key, then pass the 16-byte ciphertext to SKF_DevAuth. */
    BYTE challenge[16];
    memset(challenge, 0, sizeof(challenge));
    rc = SKF_GenRandom(hDev, challenge, 8);
    rec("SKF_GenRandom(8)", rc, "device auth challenge");

    HANDLE hAuthKey = NULL;
    if (rc == SAR_OK)
        rc = SKF_SetSymmKey(hDev, (BYTE *)key, alg, &hAuthKey);
    char algnote[80];
    snprintf(algnote, sizeof(algnote), "DevAuthAlgId=0x%lx, %s",
             (unsigned long)info.DevAuthAlgId,
             alg == SGD_SM1_ECB ? "SM1 ECB" : "SM4 ECB");
    rec("SKF_SetSymmKey(devauth)", rc, algnote);

    BYTE wrapped[32];
    ULONG wrappedlen = sizeof(wrapped);
    memset(wrapped, 0, sizeof(wrapped));
    if (rc == SAR_OK) {
        BLOCKCIPHERPARAM param;
        memset(&param, 0, sizeof(param));
        rc = SKF_EncryptInit(hAuthKey, param);
        rec("SKF_EncryptInit(devauth)", rc, "ECB, no padding");
    }
    if (rc == SAR_OK)
        rc = SKF_Encrypt(hAuthKey, challenge, sizeof(challenge),
                         wrapped, &wrappedlen);
    rec("SKF_Encrypt(devauth)", rc, "encrypt challenge");
    if (hAuthKey)
        SKF_CloseHandle(hAuthKey);

    if (rc == SAR_OK)
        rc = SKF_DevAuth(hDev, wrapped, wrappedlen);
    rec("SKF_DevAuth(wrapped challenge)", rc, "device authentication");
    if (rc != SAR_OK) {
        fprintf(rep, "\nDevice authentication failed; no application was created.\n");
        SKF_DisConnectDev(hDev);
        fclose(rep);
        return 2;
    }

    unsigned id = (unsigned)getpid() % 100000;
    char appname[32], ctnname[32], filename[32];
    if (apparg)
        snprintf(appname, sizeof(appname), "%s", apparg);
    else
        snprintf(appname, sizeof(appname), "SKFA%u", id);
    snprintf(ctnname, sizeof(ctnname), "SKFC%u", id);
    snprintf(filename, sizeof(filename), "SKFF%u.TMP", id);

    HAPPLICATION hApp = NULL;
    rc = SKF_CreateApplication(hDev, (LPSTR)appname, (LPSTR)"123456", 6,
                               (LPSTR)"123456", 6, SECURE_ANYONE_ACCOUNT, &hApp);
    rec("SKF_CreateApplication", rc, appname);
    int created = (rc == SAR_OK);

    if (created) {
        if (hApp) {
            rc = SKF_CloseApplication(hApp);
            rec("SKF_CloseApplication(after create)", rc, appname);
            hApp = NULL;
        }
        rc = SKF_OpenApplication(hDev, (LPSTR)appname, &hApp);
        rec("SKF_OpenApplication(temp)", rc, appname);
        if (rc == SAR_OK && hApp) {
            ULONG retry = 0;
            rc = SKF_VerifyPIN(hApp, USER_TYPE, (LPSTR)"123456", &retry);
            rec("SKF_VerifyPIN(temp 123456)", rc, "temp app user PIN");

            retry = 0;
            rc = SKF_ChangePIN(hApp, USER_TYPE, (LPSTR)"123456", (LPSTR)"654321", &retry);
            rec("SKF_ChangePIN(temp 123456->654321)", rc, "temp app only");
            if (rc == SAR_OK) {
                retry = 0;
                rc = SKF_VerifyPIN(hApp, USER_TYPE, (LPSTR)"654321", &retry);
                rec("SKF_VerifyPIN(temp 654321)", rc, "verify changed temp PIN");
                retry = 0;
                rc = SKF_ChangePIN(hApp, USER_TYPE, (LPSTR)"654321", (LPSTR)"123456", &retry);
                rec("SKF_ChangePIN(temp 654321->123456)", rc, "restore temp PIN");
            }

            /* Lock the temporary user PIN, then unblock it with the temporary
             * admin PIN.  This never touches KEDA or DEFAULT. */
            for (int i = 0; i < 6; i++) {
                retry = 0;
                rc = SKF_VerifyPIN(hApp, USER_TYPE, (LPSTR)"000000", &retry);
            }
            rec_expect("SKF_VerifyPIN(lock temp user PIN)", rc, SAR_PIN_LOCKED,
                "6 wrong attempts exhausted; PIN locked as expected");
            retry = 0;
            rc = SKF_UnblockPIN(hApp, (LPSTR)"123456", (LPSTR)"123456", &retry);
            rec("SKF_UnblockPIN(temp)", rc, "admin PIN 123456, new user PIN 123456");
            retry = 0;
            rc = SKF_VerifyPIN(hApp, USER_TYPE, (LPSTR)"123456", &retry);
            rec("SKF_VerifyPIN(after unblock)", rc, "temp user PIN restored");

            rc = SKF_CreateFile(hApp, (LPSTR)filename, 64,
                                SECURE_ANYONE_ACCOUNT, SECURE_ANYONE_ACCOUNT);
            rec("SKF_CreateFile(temp)", rc, filename);
            if (rc == SAR_OK) {
                BYTE data[] = "devauth-file";
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

            HCONTAINER hCtn = NULL;
            rc = SKF_CreateContainer(hApp, (LPSTR)ctnname, &hCtn);
            rec("SKF_CreateContainer(temp)", rc, ctnname);
            if (rc == SAR_OK && hCtn) {
                ULONG ctype = 0;
                rc = SKF_GetContainerType(hCtn, &ctype);
                rec("SKF_GetContainerType(temp)", rc, ctnname);
                rc = SKF_CloseContainer(hCtn);
                rec("SKF_CloseContainer(temp)", rc, ctnname);
                rc = SKF_DeleteContainer(hApp, (LPSTR)ctnname);
                rec("SKF_DeleteContainer(temp)", rc, ctnname);
            }

            rc = SKF_CloseApplication(hApp);
            rec("SKF_CloseApplication(temp)", rc, appname);
            hApp = NULL;
        }

        /* Reconnect and re-authenticate: deleting the application that was
         * current in this session otherwise returns SAR_FILE_NOT_EXIST. */
        rc = SKF_DisConnectDev(hDev);
        rec("SKF_DisConnectDev(before delete)", rc, "reset application state");
        hDev = NULL;
        rc = SKF_ConnectDev((LPSTR)names, &hDev);
        rec("SKF_ConnectDev(before delete)", rc, names);

        if (rc == SAR_OK && hDev) {
            BYTE ch[16];
            memset(ch, 0, sizeof(ch));
            ULONG ar = SKF_GenRandom(hDev, ch, 8);
            HANDLE hk = NULL;
            if (ar == SAR_OK)
                ar = SKF_SetSymmKey(hDev, (BYTE *)key, alg, &hk);
            BLOCKCIPHERPARAM p2;
            memset(&p2, 0, sizeof(p2));
            if (ar == SAR_OK)
                ar = SKF_EncryptInit(hk, p2);
            BYTE wr[32];
            ULONG wl = sizeof(wr);
            if (ar == SAR_OK)
                ar = SKF_Encrypt(hk, ch, sizeof(ch), wr, &wl);
            if (hk)
                SKF_CloseHandle(hk);
            if (ar == SAR_OK)
                ar = SKF_DevAuth(hDev, wr, wl);
            rec("SKF_DevAuth(before delete)", ar,
                "re-authenticate after reconnect");
            if (ar == SAR_OK) {
                rc = SKF_DeleteApplication(hDev, (LPSTR)appname);
                rec("SKF_DeleteApplication(temp)", rc, appname);
            }
        }
    }

    SKF_DisConnectDev(hDev);
    fprintf(rep, "\n## Result\n\n- Failures: %d\n", failures);
    printf("\nFailures: %d\n", failures);
    fclose(rep);
    free(names);
    return failures ? 2 : 0;
}
