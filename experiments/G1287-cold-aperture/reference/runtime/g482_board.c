/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Concrete Open gen7-2-1 first-boot board programming, using actual assigned
 * Windows mappings. RSC/PDC setup is AFTER fresh FW-ready, before HFI init. */
#include <ntifs.h>
#include "g321_runtime.h"
#include "g482_board.h"
#include "g482_rsc_pin.h"
#include "gpu_owner.h"
#define CopyMem RtlCopyMemory
#define ZeroMem RtlZeroMemory
#define STATIC static
#define UINTN SIZE_T
#include "OpenSha256.h"
#undef CopyMem
#undef ZeroMem
#undef STATIC
#undef UINTN
static NTSTATUS Fail(G321_RUNTIME*r,NTSTATUS s){r->Board.Status=s;return s;}
static NTSTATUS Lease(G321_RUNTIME*r){return OgoGmuCurrent(r);}

static NTSTATUS Record(G321_RUNTIME*r,ULONG bank,ULONG off,ULONG value,ULONG op,NTSTATUS s){G482_BOARD_REPORT*t=&r->Board;if(t->Count>=RTL_NUMBER_OF(t->Access))return STATUS_BUFFER_OVERFLOW;t->Access[t->Count++]=(G482_BOARD_ACCESS){bank,off,value,op,s};return s;}
static NTSTATUS Read(G321_RUNTIME*r,ULONG bank,ULONG off,PULONG value){
 NTSTATUS s=Lease(r);ULONG v=0;if(s!=STATUS_SUCCESS)return s;
 s=bank==0?G482CoreRead(r->Io,off,&v):bank==1?G482CxRead(r->Io,off,&v):bank==2?G482RscRead(r->Io,off,&v):G482PdcRead(r->Io,off,&v);
 s=Record(r,bank,off,v,0,s);if(s==STATUS_SUCCESS)*value=v;return s;
}
static NTSTATUS Write(G321_RUNTIME*r,ULONG bank,ULONG off,ULONG value){
 NTSTATUS s=Lease(r);if(s!=STATUS_SUCCESS)return s;r->Board.Retained=TRUE;
 s=bank==0?G482CoreWrite(r->Io,off,value):bank==1?G482CxWrite(r->Io,off,value):bank==2?G482RscWrite(r->Io,off,value):G482PdcWrite(r->Io,off,value);
 return Record(r,bank,off,value,1,s);
}
static NTSTATUS Set(G321_RUNTIME*r,ULONG bank,ULONG off,ULONG value,ULONG mask){ULONG got=0;NTSTATUS s=Write(r,bank,off,value);if(s!=STATUS_SUCCESS)return s;s=Read(r,bank,off,&got);if(s!=STATUS_SUCCESS)return s;return(got&mask)==(value&mask)?STATUS_SUCCESS:STATUS_DEVICE_DATA_ERROR;}
NTSTATUS G482AdmitBoard(G321_RUNTIME*r,const G482_BOARD_INPUT*in){
 UCHAR digest[32];ULONG diff=0;
 /* Preserve g196_prepare's exact raw SMEM revision encoding (major2). */
 if(!r||!in||in->Generation!=r->Generation||in->SourceProfile!=0x70201||!in->RscCode||in->RscBytes!=20||r->Inputs.soc_id!=519||r->Inputs.revision!=0x20000||r->Inputs.source_sku!=2)return r?Fail(r,STATUS_NOT_SUPPORTED):STATUS_INVALID_PARAMETER;
 RtlCopyMemory(r->RscCode,in->RscCode,20);OpenShaAll(r->RscCode,20,digest);for(ULONG i=0;i<32;i++)diff|=digest[i]^G482RscSha[i];RtlSecureZeroMemory(digest,32);
 if(diff){RtlSecureZeroMemory(r->RscCode,20);return Fail(r,STATUS_INVALID_IMAGE_HASH);}r->BoardAdmitted=TRUE;return Fail(r,STATUS_SUCCESS);
}
#define TRY(x) do{s=(x);if(s!=STATUS_SUCCESS)goto done;}while(0)
NTSTATUS G482ColdPreflight(G321_RUNTIME*r){
 NTSTATUS s;ULONG v=0;if(!r||!r->BoardAdmitted||r->Board.Attempted)return STATUS_DEVICE_NOT_READY;
 r->Board.Attempted=TRUE;r->Board.Stage=1;
 TRY(Read(r,0,G190_CM3_RESET,&v));if(v!=1){s=STATUS_DEVICE_BUSY;goto done;}
 TRY(Read(r,0,G190_HFI_STATUS,&v));if(v&1){s=STATUS_DEVICE_BUSY;goto done;}
 TRY(Read(r,1,0xe4,&v));if(v){s=STATUS_NOT_SUPPORTED;goto done;}
 TRY(Read(r,2,0x404,&v));if(v){s=STATUS_DEVICE_BUSY;goto done;}
 s=STATUS_SUCCESS;
done:return Fail(r,s);
}
NTSTATUS G482ConfigureCore(G321_RUNTIME*r){
 NTSTATUS s;ULONG v=0,log,bytes;
 if(!r||!r->BoardAdmitted||r->Board.Stage!=1||r->Core.phase!=G190_LOADED)return STATUS_DEVICE_NOT_READY;
 r->Board.Stage=2;log=r->Plan.extent[r->Plan.log_index].iova;bytes=r->Plan.extent[r->Plan.log_index].bytes;
 if(bytes!=0x4000||(log&0xfff)){s=STATUS_DEVICE_CONFIGURATION_ERROR;goto done;}
 TRY(Read(r,0,G190_CM3_RESET,&v));if(v!=1){s=STATUS_DEVICE_BUSY;goto done;}
 /* Numeric facts from Open gen7_gmu_register_config/power_config. Core
  * namespace is (GPU-dword-0x1a800)*4. No reset release occurs here. */
 TRY(Set(r,0,0x143c4,1,MAXULONG));TRY(Set(r,0,0x143c0,1,MAXULONG));
 TRY(Set(r,1,0xe4,1,MAXULONG));
 TRY(Set(r,0,0x24c44,0x80c808a0,MAXULONG));TRY(Set(r,0,0x140b4,0x4052,MAXULONG));
 /* Preboot GBIF halt deassertion is source-defined here, not after GX/CP. */
 /* Source-defined position: the continuously exclusive native owner either
  * releases its legacy owned bit or performs the distinct cold-reset boot
  * whole-device unhalt. Stopped proof is consumed before the store. */
 TRY(OgoGmuHandoff(r));TRY(Lease(r));s=G482GpuRead(r->Io,0xf114,&v);TRY(Record(r,4,0xf114,v,0,s));if(v){s=STATUS_DEVICE_DATA_ERROR;goto done;}
 TRY(Set(r,0,0x14738,0,MAXULONG));TRY(Set(r,0,0x1473c,0x07020100,MAXULONG));
 TRY(Set(r,0,0x14734,(log&0xfffff000u)|((bytes/4096-1)&255),MAXULONG));
 TRY(Set(r,0,0x1303c,1,MAXULONG));TRY(Set(r,0,0x13000,1,MAXULONG));TRY(Set(r,0,0x13004,1,MAXULONG));
 TRY(Read(r,0,G190_CM3_RESET,&v));if(v!=1){s=STATUS_DEVICE_BUSY;goto done;}
 TRY(Read(r,0,G190_G2H_MASK,&v));if(v!=MAXULONG){s=STATUS_DEVICE_CONFIGURATION_ERROR;goto done;}
 TRY(Read(r,0,G190_AO_MASK,&v));if(v!=G190_AO_MASK_ALL){s=STATUS_DEVICE_CONFIGURATION_ERROR;goto done;}
 r->Board.CoreConfigured=TRUE;s=STATUS_SUCCESS;
done:return Fail(r,s);
}
/* Vendor PDC/RSC loader contract: exact posted writes, followed here by
 * observed read journaling. These registers have no source-established echo
 * requirement. Read mismatch is not RO/RAZ evidence or sleep/wake proof.
 * This helper is private to the bounded post-FW PDC/RSC list below. */
static NTSTATUS Post(G321_RUNTIME*r,ULONG bank,ULONG off,ULONG value){
 ULONG observed=0;NTSTATUS s=Write(r,bank,off,value);
 return s==STATUS_SUCCESS?Read(r,bank,off,&observed):s;
}
NTSTATUS G482ConfigureFirmwareReady(G321_RUNTIME*r){
 NTSTATUS s;ULONG v=0,mask,expected;
 if(!r||!r->Board.CoreConfigured||r->Board.FirmwareConfigured||r->Core.phase!=G190_FW_READY||!r->Core.reset_released)return STATUS_DEVICE_NOT_READY;
 r->Board.Stage=3;mask=r->Core.firmware_version<=0x20010004?MAXULONG:0x1ff;expected=mask==MAXULONG?0xbabeface:0x100;
 TRY(Read(r,0,G190_CM3_RESET,&v));if(v){s=STATUS_DEVICE_BUSY;goto done;}
 TRY(Read(r,0,G190_FW_RESULT,&v));if((v&mask)!=expected){s=STATUS_DEVICE_NOT_READY;goto done;}
 /* Vendor post-FW path does not require HFI ready to remain zero. Keep
  * the observation; actual INIT1 + posted ready-level poll still follows
  * PDC/RSC programming. This is not a fresh zero-to-one proof. */
 TRY(Read(r,0,G190_HFI_STATUS,&v));
 TRY(Read(r,2,0x404,&v));if(v){s=STATUS_DEVICE_BUSY;goto done;}
 /* Open first_boot order: load PDC, then RSC, AFTER device_start ready and
  * BEFORE HFI init. Never substitute NativeAdreno's earlier cold ordering. */
 TRY(Post(r,3,0x4520,0));TRY(Post(r,3,0x4500,0x80000001));
 TRY(Post(r,2,0x10,1u<<24));
 const ULONG pairs[][2]={{0x2c,1},{0x38,0},{0x34,0},{0x40,0},{0x3c,0},{0x48,0x80000021},{0x44,0},{0x400,0},{0x20,0x4520},{0x24,0x4510},{0x28,0x4514}};
 for(ULONG i=0;i<RTL_NUMBER_OF(pairs);i++)TRY(Post(r,2,pairs[i][0],pairs[i][1]));
 for(ULONG i=0;i<5;i++){const UCHAR*p=r->RscCode+4*i;ULONG word=(ULONG)p[0]|(ULONG)p[1]<<8|(ULONG)p[2]<<16|(ULONG)p[3]<<24;TRY(Post(r,2,0x550+4*i,word));}
 TRY(Read(r,0,G190_CM3_RESET,&v));if(v){s=STATUS_DEVICE_BUSY;goto done;}
 TRY(Read(r,0,G190_FW_RESULT,&v));if((v&mask)!=expected){s=STATUS_DEVICE_NOT_READY;goto done;}
 /* Sequence acceptance records posted vendor intent and observed reads,
  * not electrical echo agreement or qualified sleep/wake operation. */
 r->Board.FirmwareConfigured=TRUE;r->Board.Stage=4;r->Core.phase=G190_BOARD_READY;s=STATUS_SUCCESS;
done:return Fail(r,s);
}
