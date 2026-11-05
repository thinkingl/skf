#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "skf.h"
int main(int argc,char**argv){if(argc<2)return 1;ULONG len=0;SKF_EnumDev(TRUE,NULL,&len);char*n=calloc(1,len+1);SKF_EnumDev(TRUE,(LPSTR)n,&len);DEVHANDLE d=NULL;if(SKF_ConnectDev((LPSTR)n,&d)!=SAR_OK)return 1;BYTE key[16];memcpy(key,argv[1],16);BYTE p[16];for(int i=0;i<16;i++)p[i]=(BYTE)i;HANDLE h=NULL;ULONG rc=SKF_SetSymmKey(d,key,SGD_SM1_ECB,&h);printf("Set 0x%lx\n",(unsigned long)rc);BLOCKCIPHERPARAM bp;memset(&bp,0,sizeof(bp));rc=SKF_EncryptInit(h,bp);printf("Init 0x%lx\n",(unsigned long)rc);BYTE o[32];ULONG ol=sizeof(o);rc=SKF_Encrypt(h,p,16,o,&ol);printf("Enc 0x%lx: ",(unsigned long)rc);for(ULONG i=0;i<ol;i++)printf("%02x",o[i]);printf("\n");SKF_CloseHandle(h);SKF_DisConnectDev(d);free(n);return 0;}
