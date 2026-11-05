#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "skf.h"

static void mark(const char *s)
{
    const char *p = getenv("SG_TRACE"); if (!p || !*p) p = "/tmp/sg_trace.log";
    int fd = open(p, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) { dprintf(fd, "=== MARK %s ===\n", s); close(fd); }
}
static void pr(const char *w, ULONG rc) { printf("%-32s 0x%08lx\n", w, (unsigned long)rc); }

int main(void)
{
    ULONG len = 0; SKF_EnumDev(TRUE, NULL, &len);
    char *names = calloc(1, len + 1); SKF_EnumDev(TRUE, (LPSTR)names, &len);
    DEVHANDLE dev = NULL;
    if (SKF_ConnectDev((LPSTR)names, &dev) != SAR_OK) return 1;
    HAPPLICATION app = NULL;
    if (SKF_OpenApplication(dev, (LPSTR)"KEDA", &app) != SAR_OK) return 1;
    ULONG retry = 0;
    if (SKF_VerifyPIN(app, USER_TYPE, (LPSTR)"123456", &retry) != SAR_OK) return 1;
    HCONTAINER ctn = NULL;
    if (SKF_OpenContainer(app, (LPSTR)"K01231-85422873-3457921", &ctn) != SAR_OK) return 1;

    BYTE cert[8192]; ULONG clen = sizeof(cert);
    mark("ExportCertificate");
    ULONG rc = SKF_ExportCertificate(ctn, TRUE, cert, &clen); pr("ExportCertificate", rc);
    printf("  cert len=%lu\n", (unsigned long)clen);

    BYTE pub[2048]; ULONG plen = sizeof(pub);
    mark("ExportPublicKey");
    rc = SKF_ExportPublicKey(ctn, TRUE, pub, &plen); pr("ExportPublicKey", rc);
    printf("  pub len=%lu alg=0x%lx\n", (unsigned long)plen,
           plen >= 4 ? *(unsigned long *)pub : 0);

    BYTE digest[32]; for (int i = 0; i < 32; i++) digest[i] = (BYTE)i;
    ECCSIGNATUREBLOB sig; memset(&sig, 0, sizeof(sig));
    mark("ECCSignData");
    rc = SKF_ECCSignData(ctn, digest, sizeof(digest), &sig); pr("ECCSignData", rc);

    mark("ECCVerify");
    rc = SKF_ECCVerify(dev, (ECCPUBLICKEYBLOB *)pub, digest, sizeof(digest), &sig);
    pr("ECCVerify", rc);

    mark("ExtECCVerify");
    rc = SKF_ExtECCVerify(dev, (ECCPUBLICKEYBLOB *)pub, digest, sizeof(digest), &sig);
    pr("ExtECCVerify", rc);

    BYTE plain[16]; for (int i = 0; i < 16; i++) plain[i] = (BYTE)(0x40 + i);
    ECCCIPHERBLOB *cipher = calloc(1, sizeof(ECCCIPHERBLOB) + 256);
    mark("ExtECCEncrypt");
    rc = SKF_ExtECCEncrypt(dev, (ECCPUBLICKEYBLOB *)pub, plain, sizeof(plain), cipher);
    pr("ExtECCEncrypt", rc);

    HANDLE sess = NULL;
    mark("ECCExportSessionKey");
    rc = SKF_ECCExportSessionKey(ctn, SGD_SM4_ECB, (ECCPUBLICKEYBLOB *)pub, cipher, &sess);
    pr("ECCExportSessionKey", rc);

    if (sess) SKF_CloseHandle(sess);
    free(cipher);
    SKF_CloseContainer(ctn);
    SKF_CloseApplication(app);
    SKF_DisConnectDev(dev);
    free(names);
    return 0;
}
