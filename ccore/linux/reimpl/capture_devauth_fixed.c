#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skf.h"
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    ULONG len=0; SKF_EnumDev(TRUE,NULL,&len);
    char *n=calloc(1,len+1); SKF_EnumDev(TRUE,(LPSTR)n,&len);
    DEVHANDLE d=NULL; if (SKF_ConnectDev((LPSTR)n,&d)!=SAR_OK) return 1;
    DEVINFO i; memset(&i,0,sizeof(i)); SKF_GetDevInfo(d,&i);
    ULONG alg=i.DevAuthAlgId; if (alg!=SGD_SM1_ECB && alg!=SGD_SM4_ECB) alg=SGD_SM4_ECB;
    BYTE ch[16]; for (int k=0;k<8;k++) ch[k]=(BYTE)k; for(int k=8;k<16;k++) ch[k]=0;
    HANDLE h=NULL; ULONG rc=SKF_SetSymmKey(d,(BYTE*)argv[1],alg,&h); printf("Set 0x%lx\n",(unsigned long)rc);
    BLOCKCIPHERPARAM p; memset(&p,0,sizeof(p)); rc=SKF_EncryptInit(h,p); printf("Init 0x%lx\n",(unsigned long)rc);
    BYTE out[32]; ULONG ol=sizeof(out); rc=SKF_Encrypt(h,ch,16,out,&ol); printf("Enc 0x%lx len=%lu: ",(unsigned long)rc,(unsigned long)ol);
    for(ULONG k=0;k<ol;k++) printf("%02x",out[k]); printf("\n");
    SKF_CloseHandle(h);
    rc=SKF_DevAuth(d,out,ol); printf("DevAuth 0x%lx\n",(unsigned long)rc);
    SKF_DisConnectDev(d); free(n); return 0;
}
