#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "skf.h"
static void mark(const char *s){const char*p=getenv("SG_TRACE");if(!p||!*p)p="/tmp/sg_trace.log";int fd=open(p,O_WRONLY|O_CREAT|O_APPEND,0644);if(fd>=0){dprintf(fd,"=== MARK %s ===\n",s);close(fd);}}
static int devauth(DEVHANDLE dev,const char*key){DEVINFO i;memset(&i,0,sizeof(i));if(SKF_GetDevInfo(dev,&i)!=SAR_OK)return-1;ULONG alg=i.DevAuthAlgId;if(alg!=SGD_SM1_ECB&&alg!=SGD_SM4_ECB)alg=SGD_SM4_ECB;BYTE ch[16];memset(ch,0,sizeof(ch));if(SKF_GenRandom(dev,ch,8)!=SAR_OK)return-1;HANDLE h=NULL;if(SKF_SetSymmKey(dev,(BYTE*)key,alg,&h)!=SAR_OK)return-1;BLOCKCIPHERPARAM p;memset(&p,0,sizeof(p));if(SKF_EncryptInit(h,p)!=SAR_OK)return-1;BYTE o[32];ULONG ol=sizeof(o);if(SKF_Encrypt(h,ch,16,o,&ol)!=SAR_OK)return-1;SKF_CloseHandle(h);return SKF_DevAuth(dev,o,ol)==SAR_OK?0:-1;}
int main(int argc,char**argv){if(argc<2)return 1;ULONG len=0;SKF_EnumDev(TRUE,NULL,&len);char*n=calloc(1,len+1);SKF_EnumDev(TRUE,(LPSTR)n,&len);DEVHANDLE d=NULL;if(SKF_ConnectDev((LPSTR)n,&d)!=SAR_OK)return 1;printf("auth1=%d\n",devauth(d,argv[1]));mark("ChangeDevAuthKey");ULONG rc=SKF_ChangeDevAuthKey(d,(BYTE*)argv[1],(ULONG)strlen(argv[1]));printf("ChangeDevAuthKey 0x%lx\n",(unsigned long)rc);mark("auth2");printf("auth2=%d\n",devauth(d,argv[1]));SKF_DisConnectDev(d);free(n);return 0;}
