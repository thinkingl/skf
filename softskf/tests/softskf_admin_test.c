#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "skf.h"
#include "softskf_init.h"

static int failures;
static void check(const char *what, ULONG rc, int ok)
{
    printf("[%s] %-40s rc=0x%08lx\n", ok ? "PASS" : "FAIL", what,
           (unsigned long)rc);
    if (!ok)
        failures++;
}

static void wrap_auth(DEVHANDLE dev, const unsigned char key[16], ULONG alg,
                      ULONG *out_rc)
{
    BYTE challenge[16] = {0};
    ULONG rc = SKF_GenRandom(dev, challenge, 8);
    HANDLE h = NULL;
    if (rc == SAR_OK)
        rc = SKF_SetSymmKey(dev, (BYTE *)key, alg, &h);
    BLOCKCIPHERPARAM p;
    memset(&p, 0, sizeof(p));
    if (rc == SAR_OK)
        rc = SKF_EncryptInit(h, p);
    BYTE out[32];
    ULONG outlen = sizeof(out);
    if (rc == SAR_OK)
        rc = SKF_Encrypt(h, challenge, sizeof(challenge), out, &outlen);
    if (h)
        SKF_CloseHandle(h);
    if (rc == SAR_OK)
        rc = SKF_DevAuth(dev, out, outlen);
    *out_rc = rc;
}

static void *cancel_thread(void *arg)
{
    (void)arg;
    usleep(200 * 1000);
    SKF_CancelWaitForDevEvent();
    return NULL;
}

int main(void)
{
    const char *home = "/tmp/softskf-admin-test";
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", home);
    if (system(cmd) != 0)
        return 1;
    setenv("SOFTSKF_HOME", home, 1);

    unsigned char keyA[16], keyB[16];
    for (int i = 0; i < 16; i++) {
        keyA[i] = (unsigned char)(0x10 + i);
        keyB[i] = (unsigned char)(0x80 + i);
    }
    int rc = softskf_init_token(home, "softskf0", keyA, 16, "INITIAL",
                                "ADMINAPP", "123456", "123456", 1);
    check("softskf_init_token", 0, rc == 0);

    ULONG len = 0;
    rc = SKF_EnumDev(TRUE, NULL, &len);
    char *names = calloc(1, len + 1);
    rc = SKF_EnumDev(TRUE, (LPSTR)names, &len);
    check("SKF_EnumDev", rc, rc == SAR_OK && names[0]);
    DEVHANDLE dev = NULL;
    rc = SKF_ConnectDev((LPSTR)names, &dev);
    check("SKF_ConnectDev", rc, rc == SAR_OK && dev);

    ULONG ar = SAR_FAIL;
    wrap_auth(dev, keyA, SGD_SM4_ECB, &ar);
    check("DevAuth with key A", ar, ar == SAR_OK);

    rc = SKF_ChangeDevAuthKey(dev, keyB, 16);
    check("SKF_ChangeDevAuthKey A->B", rc, rc == SAR_OK);
    SKF_DisConnectDev(dev);
    dev = NULL;
    rc = SKF_ConnectDev((LPSTR)names, &dev);
    check("reconnect", rc, rc == SAR_OK && dev);

    ar = SAR_OK;
    wrap_auth(dev, keyA, SGD_SM4_ECB, &ar);
    check("DevAuth with old key fails", ar, ar == SAR_PIN_INCORRECT ||
          ar == SAR_PIN_LOCKED);
    ar = SAR_FAIL;
    wrap_auth(dev, keyB, SGD_SM4_ECB, &ar);
    check("DevAuth with new key", ar, ar == SAR_OK);

    rc = SKF_SetLabel(dev, (LPSTR)"RENAMED");
    check("SKF_SetLabel", rc, rc == SAR_OK);
    DEVINFO info;
    memset(&info, 0, sizeof(info));
    rc = SKF_GetDevInfo(dev, &info);
    check("SKF_GetDevInfo label", rc,
          rc == SAR_OK && strcmp((char *)info.Label, "RENAMED") == 0);

    rc = SKF_LockDev(dev, 1000);
    check("SKF_LockDev", rc, rc == SAR_OK);
    rc = SKF_UnlockDev(dev);
    check("SKF_UnlockDev", rc, rc == SAR_OK);

    pthread_t th;
    pthread_create(&th, NULL, cancel_thread, NULL);
    char event_name[128];
    ULONG event_len = sizeof(event_name);
    ULONG event = 0;
    rc = SKF_WaitForDevEvent((LPSTR)event_name, &event_len, &event);
    pthread_join(th, NULL);
    check("SKF_WaitForDevEvent cancel", rc, rc == SAR_NOT_EVENTERR);

    rc = SKF_Transmit(dev, (BYTE *)"\x00\xA4\x00\x00", 4, NULL, NULL);
    check("SKF_Transmit unsupported", rc, rc == SAR_NOTSUPPORTYETERR);

    SKF_DisConnectDev(dev);
    free(names);
    printf("\nFailures: %d\n", failures);
    return failures ? 1 : 0;
}
