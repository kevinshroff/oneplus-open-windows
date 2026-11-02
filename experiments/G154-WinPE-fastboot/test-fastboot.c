// Actual production C with only the final non-returning reset boundary modeled.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#undef NULL
#include <Uefi.h>
static void TestVendorReset(void *,EFI_RESET_TYPE,EFI_STATUS,UINTN,void *);
#include "private/model-FastbootOnce.c"
static EFI_BOOT_SERVICES bs;
static EFI_RUNTIME_SERVICES rt;
static EFI_SYSTEM_TABLE st;
static EFI_LOADED_IMAGE_PROTOCOL own,resetImage;
static EFI_SIMPLE_FILE_SYSTEM_PROTOCOL fs;
typedef struct {EFI_FILE_PROTOCOL p;int kind;UINTN pos;} FILE_MODEL;
static FILE_MODEL rootModel,origModel,bootModel,receiptModel;
static unsigned char *original,*boot,*vendor;
static UINTN bootSize;
static unsigned char dp[46],fv[24],pmic[48],record[64];
static EFI_HANDLE resetHandles[2];
static int fault,resetCalls,chainCalls,writes,opens,allocations;
static int eq16(const CHAR16 *a,const CHAR16 *b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
static EFI_STATUS EFIAPI alloc(EFI_MEMORY_TYPE t,UINTN n,void **p){(void)t;*p=malloc(n);if(!*p)return EFI_OUT_OF_RESOURCES;allocations++;return 0;}
static EFI_STATUS EFIAPI release(void *p){free(p);allocations--;return 0;}
static EFI_STATUS EFIAPI closeF(EFI_FILE_PROTOCOL *p){FILE_MODEL *f=(void*)p;if(f->kind==2&&fault==10)return EFI_DEVICE_ERROR;return 0;}
static EFI_STATUS EFIAPI position(EFI_FILE_PROTOCOL *p,UINT64 o){((FILE_MODEL*)p)->pos=(UINTN)o;return o==0?0:EFI_UNSUPPORTED;}
static EFI_STATUS EFIAPI infoF(EFI_FILE_PROTOCOL *p,EFI_GUID *g,UINTN *n,void *out){(void)g;assert(*n>=128);FILE_MODEL*f=(void*)p;EFI_FILE_INFO*i=out;memset(out,0,*n);i->Size=128;i->FileSize=f->kind==1?ORIGINAL_BYTES:bootSize;return 0;}
static EFI_STATUS EFIAPI setInfoF(EFI_FILE_PROTOCOL *p,EFI_GUID*g,UINTN n,void *v){(void)p;(void)g;(void)n;if(fault==6)return EFI_DEVICE_ERROR;bootSize=((EFI_FILE_INFO*)v)->FileSize;return 0;}
static EFI_STATUS EFIAPI readF(EFI_FILE_PROTOCOL*p,UINTN*n,void*v){FILE_MODEL*f=(void*)p;assert(f->pos==0);if(f->kind==1){memcpy(v,original,*n);if(fault==2)((unsigned char*)v)[0]^=1;if(fault==3)(*n)--;}else{assert(f->kind==2);memcpy(v,boot,*n);if(fault==8)((unsigned char*)v)[0]^=1;}f->pos+=*n;return 0;}
static EFI_STATUS EFIAPI writeF(EFI_FILE_PROTOCOL*p,UINTN*n,void*v){FILE_MODEL*f=(void*)p;assert(f->pos==0);if(f->kind==3){assert(*n==64);memcpy(record,v,64);return 0;}assert(f->kind==2);writes++;if(fault==4)return EFI_DEVICE_ERROR;if(fault==5)(*n)--;memcpy(boot,v,*n);f->pos+=*n;return 0;}
static EFI_STATUS EFIAPI flushF(EFI_FILE_PROTOCOL*p){return ((FILE_MODEL*)p)->kind==2&&fault==7?EFI_DEVICE_ERROR:0;}
static EFI_STATUS EFIAPI openF(EFI_FILE_PROTOCOL*p,EFI_FILE_PROTOCOL**f,CHAR16*n,UINT64 mode,UINT64 attr){(void)p;(void)attr;opens++;FILE_MODEL*m=NULL;if(eq16(n,L"\\EFI\\BOOT\\G154.ORIG")){assert(mode==1);if(fault==20)return EFI_NOT_FOUND;m=&origModel;}else if(eq16(n,L"\\EFI\\BOOT\\BOOTAA64.EFI")){assert(mode==3);m=&bootModel;}else{assert(eq16(n,L"\\EFI\\BOOT\\G154.STATUS"));assert(mode==3);m=&receiptModel;}m->pos=0;*f=&m->p;return 0;}
static EFI_STATUS EFIAPI openVol(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL*p,EFI_FILE_PROTOCOL**f){(void)p;if(fault==19)return EFI_DEVICE_ERROR;*f=&rootModel.p;return 0;}
static EFI_STATUS EFIAPI hp(EFI_HANDLE h,EFI_GUID*g,void**p){if(!CompareMem(g,&LoadedGuid,16)){*p=h==(void*)1?(void*)&own:(void*)&resetImage;return 0;}assert(h==(void*)2);if(!CompareMem(g,&DpGuid,16)){*p=dp;return 0;}assert(!CompareMem(g,&FsGuid,16));*p=&fs;return 0;}
static EFI_STATUS EFIAPI handles(EFI_LOCATE_SEARCH_TYPE t,EFI_GUID*g,void*k,UINTN*n,EFI_HANDLE**p){(void)t;(void)g;(void)k;*n=fault==15?2:fault==18?257:1;if(fault==12)*n=0;*p=malloc((*n?*n:1)*sizeof(void*));allocations++;for(UINTN i=0;i<*n;i++)(*p)[i]=resetHandles[0];return 0;}
static EFI_STATUS EFIAPI locate(EFI_GUID*g,void*k,void**p){(void)k;assert(!CompareMem(g,&PmicGuid,16));if(fault==16)return EFI_NOT_FOUND;*p=pmic;return 0;}
static EFI_STATUS EFIAPI load(BOOLEAN pol,EFI_HANDLE h,EFI_DEVICE_PATH_PROTOCOL*d,void*b,UINTN n,EFI_HANDLE*out){assert(!pol&&h==(void*)1&&d&&n==ORIGINAL_BYTES);assert(!memcmp(b,original,n));chainCalls++;*out=(void*)3;return EFI_LOAD_ERROR;}
static void TestVendorReset(void*b,EFI_RESET_TYPE t,EFI_STATUS s,UINTN n,void*d){assert(b==vendor&&t==EfiResetCold&&s==EFI_INVALID_PARAMETER&&n==25);assert(!memcmp(d,L"RESET_PARAM",24)&&((UINT8*)d)[24]==2);assert(!memcmp(boot,original,ORIGINAL_BYTES)&&bootSize==ORIGINAL_BYTES);assert(((RECEIPT*)record)->Phase==4&&((RECEIPT*)record)->Status==0);assert(allocations==0);resetCalls++;}
static void setup(int f,const unsigned char *v){fault=f;resetCalls=chainCalls=writes=opens=allocations=0;memset(&bs,0,sizeof(bs));memset(&rt,0,sizeof(rt));memset(&st,0,sizeof(st));bs.AllocatePool=alloc;bs.FreePool=release;bs.HandleProtocol=hp;bs.LocateHandleBuffer=handles;bs.LocateProtocol=locate;bs.LoadImage=load;st.Hdr.Signature=EFI_SYSTEM_TABLE_SIGNATURE;st.BootServices=&bs;st.RuntimeServices=&rt;memset(&own,0,sizeof(own));own.DeviceHandle=(void*)2;
 HARDDRIVE_DEVICE_PATH hd;memset(&hd,0,sizeof(hd));hd.Header.Type=MEDIA_DEVICE_PATH;hd.Header.SubType=MEDIA_HARDDRIVE_DP;hd.Header.Length[0]=42;hd.PartitionNumber=14;hd.PartitionStart=0x4582ec;hd.PartitionSize=0x71bb90f;hd.MBRType=hd.SignatureType=2;memcpy(hd.Signature,&EspGuid,16);memcpy(dp,&hd,42);unsigned char end[4]={127,255,4,0};memcpy(dp+42,end,4);if(f==1)dp[24]^=1;
 memcpy(fv,(unsigned char[]){4,6,20,0},4);memcpy(fv+4,&ResetFileGuid,16);memcpy(fv+20,end,4);memset(&resetImage,0,sizeof(resetImage));resetImage.FilePath=(void*)fv;resetImage.ImageSize=RESET_IMAGE_BYTES;resetImage.ImageBase=vendor;memcpy(vendor,v,RESET_IMAGE_BYTES);for(UINTN j=0;j<sizeof(ResetTextRelocations)/2;j++){UINT64 a;memcpy(&a,vendor+0x1000+ResetTextRelocations[j],8);a+=(UINTN)vendor;memcpy(vendor+0x1000+ResetTextRelocations[j],&a,8);}UINTN p=(UINTN)&bs;memcpy(vendor+0x71b0,&p,8);vendor[0x71bc]=f==13?1:0;if(f==11)vendor[0x1800]^=1;if(f==14)vendor[0x71b0]^=1;memset(pmic,0,48);p=f==17?0:1;memcpy(pmic+40,&p,8);resetHandles[0]=(void*)4;
 FILE_MODEL*m[]={&rootModel,&origModel,&bootModel,&receiptModel};for(int i=0;i<4;i++){memset(m[i],0,sizeof(*m[i]));m[i]->kind=i;m[i]->p.Open=openF;m[i]->p.Close=closeF;m[i]->p.Read=readF;m[i]->p.Write=writeF;m[i]->p.GetInfo=infoF;m[i]->p.SetInfo=setInfoF;m[i]->p.SetPosition=position;m[i]->p.Flush=flushF;}fs.OpenVolume=openVol;bootSize=f==9?ORIGINAL_BYTES:8192;memset(boot,0,ORIGINAL_BYTES);memset(record,0,64);Root=NULL;}
int main(int argc,char**argv){assert(argc==3);original=malloc(ORIGINAL_BYTES);boot=malloc(ORIGINAL_BYTES);vendor=malloc(RESET_IMAGE_BYTES);unsigned char *v=malloc(RESET_IMAGE_BYTES);FILE*f=fopen(argv[1],"rb");assert(f&&fread(original,1,ORIGINAL_BYTES,f)==ORIGINAL_BYTES);fclose(f);f=fopen(argv[2],"rb");assert(f&&fread(v,1,RESET_IMAGE_BYTES,f)==RESET_IMAGE_BYTES);fclose(f);
 for(int i=0;i<=20;i++){setup(i,v);EFI_STATUS s=EfiMain((void*)1,&st);(void)s;if(i==0){assert(resetCalls==1&&writes==1&&chainCalls==0);}else{assert(resetCalls==0);if(i==1||i==2||i==3||i==19||i==20)assert(writes==0&&chainCalls==0);else assert(chainCalls==1);if(i>=11&&i<=18)assert(!memcmp(boot,original,ORIGINAL_BYTES));}if(allocations){/* ChainWindows returns EFI_LOAD_ERROR only in this model. */assert(chainCalls==1&&allocations==1);allocations=0;} }
 free(original);free(boot);free(vendor);free(v);puts("21 actual-C one-shot reset cases passed; firmware/FS/reset boundaries modeled.");return 0;}
