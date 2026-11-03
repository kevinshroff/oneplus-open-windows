/* Host behavioral harness; not EDK2 firmware/ABI qualification. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
typedef void VOID;typedef uint8_t UINT8;typedef uint32_t UINT32;typedef uint64_t UINT64;typedef size_t UINTN;typedef unsigned char BOOLEAN;typedef char CHAR8;typedef UINT64 EFI_STATUS;
#define CONST const
#define MAX_UINT32 UINT32_MAX
#define EFI_SUCCESS 0
#define EFI_UNSUPPORTED 3
#define EFI_NOT_READY 6
#define EFI_DEVICE_ERROR 7
#define STATIC_ASSERT _Static_assert
#define OFFSET_OF offsetof
#define ZeroMem(p,n) memset(p,0,n)
#define CopyMem memcpy
#pragma pack(push,1)
typedef struct {UINT32 Signature,Length;UINT8 Revision,Checksum;UINT8 OemId[6];UINT64 OemTableId;UINT32 OemRevision,CreatorId,CreatorRevision;}EFI_ACPI_DESCRIPTION_HEADER;
#pragma pack(pop)
typedef struct EFI_ACPI_TABLE_PROTOCOL {EFI_STATUS(*InstallAcpiTable)(struct EFI_ACPI_TABLE_PROTOCOL*,VOID*,UINTN,UINTN*);}EFI_ACPI_TABLE_PROTOCOL;
#include "../firmware/qtb_npa_abi.h"
#include "../firmware/qtb_tcu_vote.inc"
static int calls,mode;static int handle;
static EFI_STATUS avail(CONST CHAR8*n,UINT32*a){calls++;assert(!strcmp(n,"/icb/arbiter"));*a=0;return mode==1?7:0;}
static EFI_STATUS create(CONST CHAR8*r,CONST CHAR8*n,UINT32 t,UINT32 bytes,VOID*p,VOID**h){calls++;assert(!strcmp(r,"/icb/arbiter")&&!strcmp(n,"Open-QTB-gpu-tcu"));assert(t==0x400&&bytes==8&&((UINT32*)p)[0]==196&&((UINT32*)p)[1]==0);*h=&handle;return mode==2?7:0;}
static EFI_STATUS vector(VOID*h,UINT32 words,CONST UINT32*v){calls++;assert(h==&handle&&words==8&&v[0]==4&&v[1]==0&&v[2]==1000000&&v[3]==0&&v[4]==0&&v[5]==0&&v[6]==0&&v[7]==0);return mode==3?7:0;}
static EFI_STATUS install(EFI_ACPI_TABLE_PROTOCOL*a,VOID*p,UINTN n,UINTN*k){(void)a;calls++;assert(n==80);UINT8 sum=0;for(UINTN i=0;i<n;i++)sum+=((UINT8*)p)[i];assert(!sum&&!memcmp(p,"OWQT",4));QTB_VOTE_TABLE*t=p;assert(t->Version==1&&t->Master==196&&!t->Slave&&t->Type==4&&t->Ib==1000000&&!t->Ab&&t->FamilyInference==1&&!t->RequestStatus);*k=123;return 0;}
int main(int argc,char**argv){mode=argc>1?atoi(argv[1]):0;G289_NPA n;memset(&n,0,sizeof(n));n.Version=0x10003;n.Create=create;n.Available=avail;typedef EFI_STATUS(*V)(VOID*,UINT32,CONST UINT32*);V v=vector;memcpy((UINT8*)&n+144,&v,sizeof(v));EFI_ACPI_TABLE_PROTOCOL a={install};UINTN k=0;
#if !OPEN_QTB_WITNESS
 assert(QtbTcuKeepVote(&n,0)==EFI_UNSUPPORTED&&QtbPublishVote(&a,0,&k)==EFI_UNSUPPORTED&&!calls);puts("vote default-off zero calls");
#else
 assert(QtbTcuKeepVote(&n,1)==EFI_NOT_READY&&!calls);EFI_STATUS s=QtbTcuKeepVote(&n,0);assert(QtbTcuKeepVote(&n,0)==EFI_NOT_READY);if(mode){assert(s==7&&QtbPublishVote(&a,0,&k)==EFI_NOT_READY&&!k);if(mode>=2)assert(mQtbTcuClient==&handle);puts("vote partial failure retained/no publish/no retry");}else{assert(!s&&QtbPublishVote(&a,1,&k)==EFI_NOT_READY&&QtbPublishVote(&a,0,&k)==0&&k==123&&calls==4&&QtbPublishVote(&a,0,&k)==EFI_NOT_READY);puts("vote exact pair/bytes/words/raw request + OWQT receipt PASS");}
#endif
 return 0;}
