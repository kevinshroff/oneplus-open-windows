/* SPDX-License-Identifier: MIT
 * Temporary one-use original-loader diagnostic. Memory and stage-1 permission
 * admission are explicit; neither proves global DMA/stage-2 ownership. Underlying
 * secure calls can fail or never return. No shutdown or retry is issued.
 */
#include <Uefi.h>
#include <IndustryStandard/Acpi.h>
#include <Protocol/AcpiTable.h>
#include <Protocol/GraphicsOutput.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include "OpenGuardedAdsp.h"
#include "OpenPilMetadataProbe.h"

STATIC EFI_GUID mPilGuid={0x1f4f1da3,0x4d8d,0x4894,{0xba,0x2a,0x13,0xd3,0x20,0x7f,0x97,0x39}};
STATIC EFI_GUID mScmGuid={0x77ed108d,0x8524,0x4b8b,{0x9d,0x2e,0x34,0x98,0x7a,0xec,0xb9,0xc1}};
STATIC BOOLEAN mRan;
STATIC G134_REPORT mResult;
STATIC OP_OBSERVER mObserver;
STATIC OPEN_KERNEL_REPORT mLog;
STATIC UINT64 mOriginal;
CONST G134_REPORT *OpenGetGuardedAdspReport(VOID){return mRan?&mResult:NULL;}
STATIC UINT64 Q(CONST VOID *P){UINT64 v;CopyMem(&v,P,8);return v;}
STATIC VOID SetQ(VOID *P,UINT64 v){CopyMem(P,&v,8);}

#ifndef OPEN_GUARDED_ADSP_MODEL
STATIC UINT64 RawSip(VOID *self,UINT32 command,UINT32 param,OP_U64 *args,OP_U64 *results){
 return ((OP_SIP)(UINTN)mOriginal)(self,command,param,args,results);
}
STATIC UINT64 LoadCfg(UINTN method,VOID *cfg){return ((UINT64(EFIAPI *)(VOID *))method)(cfg);}
#else
UINT64 RawSip(VOID *,UINT32,UINT32,OP_U64 *,OP_U64 *);
UINT64 LoadCfg(UINTN,VOID *);
#endif
STATIC OP_U64 Forward(VOID *self,OP_U32 command,OP_U32 param,OP_U64 *args,OP_U64 *results){
 return RawSip(self,command,param,args,results);
}
STATIC OP_U64 EFIAPI Observe(VOID *self,OP_U32 command,OP_U32 param,OP_U64 *args,OP_U64 *results){
 if(!mObserver.Active)return RawSip(self,command,param,args,results);
 OP_U32 before=mObserver.Count;
 UINT64 id=args?args[0]:0,status;
 BOOLEAN tracked=(command==0x42000201||command==0x42000202||command==0x42000205||command==0x42000206)&&(id==36||id==1);
 if(tracked){mLog("G134_PAS_enter command=%x param=%x image=%lu\n",command,param,id);Print(L"G134 PAS %x image %lu: enter\n",command,id);}
 status=OpenPasCall(&mObserver,self,command,param,args,results);
 if(tracked&&mObserver.Count>before){
  OP_RECORD *r=&mObserver.Records[mObserver.Count-1];
  mLog("G134_PAS_return command=%x image=%u entered=%u returned=%u transport=%lx result0=%lx result1=%lx filtered=%lx refusal=%x\n",command,r->ImageId,r->Entered,r->Returned,r->OriginalStatus,r->Results[0],r->Results[1],r->ReturnedStatus,r->Refusal);
  Print(L"G134 PAS %x image %lu: return %lx, service %lx\n",command,id,status,r->Results[1]);
 }
 return status;
}
STATIC BOOLEAN Overlap(UINT64 base,UINT64 bytes){return bytes&&base<=MAX_UINT64-bytes&&base<0xae880000ULL&&base+bytes>0xa9f80000ULL;}
STATIC EFI_STATUS GopAdmission(VOID){
 EFI_HANDLE *handles=NULL;EFI_GRAPHICS_OUTPUT_PROTOCOL *gop;
 UINTN count=0;EFI_STATUS s=gBS->LocateHandleBuffer(ByProtocol,&gEfiGraphicsOutputProtocolGuid,NULL,&count,&handles);
 if(s!=EFI_SUCCESS||handles==NULL||count==0||count>8){if(handles!=NULL&&s==EFI_SUCCESS)FreePool(handles);return EFI_NOT_READY;}
 mResult.GopCount=(UINT32)count;
 for(UINTN i=0;i<count;i++){
  gop=NULL;s=gBS->HandleProtocol(handles[i],&gEfiGraphicsOutputProtocolGuid,(VOID **)&gop);
  if(s!=EFI_SUCCESS||gop==NULL||gop->Mode==NULL||gop->Mode->FrameBufferSize==0){s=EFI_NOT_READY;break;}
  UINT64 base=gop->Mode->FrameBufferBase,bytes=gop->Mode->FrameBufferSize;
  mLog("G134_GOP base=%lx bytes=%lx overlap=%u\n",base,bytes,Overlap(base,bytes));
  if(base>MAX_UINT64-bytes||Overlap(base,bytes)){s=EFI_ACCESS_DENIED;break;}
 }
 FreePool(handles);return s;
}
STATIC EFI_STATUS Publish(VOID){
 EFI_ACPI_TABLE_PROTOCOL *acpi;EFI_STATUS s;UINTN n=sizeof(EFI_ACPI_DESCRIPTION_HEADER)+sizeof(mResult),key;UINT8 sum=0;
 s=gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid,NULL,(VOID **)&acpi);if(s!=EFI_SUCCESS||acpi==NULL)return EFI_NOT_FOUND;
 EFI_ACPI_DESCRIPTION_HEADER *h=AllocateZeroPool(n);if(h==NULL)return EFI_OUT_OF_RESOURCES;
 h->Signature=SIGNATURE_32('O','A','D','P');h->Length=(UINT32)n;h->Revision=1;
 CopyMem(h->OemId,"OPEN  ",6);CopyMem(&h->OemTableId,"G134DSP1",8);h->OemRevision=134;
 h->CreatorId=SIGNATURE_32('O','P','E','N');h->CreatorRevision=1;CopyMem(h+1,&mResult,sizeof(mResult));
 for(UINTN i=0;i<n;i++)sum=(UINT8)(sum+((UINT8 *)h)[i]);h->Checksum=(UINT8)(0-sum);
 s=acpi->InstallAcpiTable(acpi,h,n,&key);FreePool(h);return s;
}

EFI_STATUS OpenRunGuardedAdsp(BOOLEAN ready,OPEN_KERNEL_REPORT log,BOOLEAN *mayContinue){
 CONST G128_REPORT *meta;VOID *pil=NULL,*scm=NULL;UINT64 el,method;
 UINT8 cfg[2][G128_CFG_BYTES];OPEN_CPU_ADMISSION cpu;
 EFI_TPL prior;EFI_STATUS s=EFI_NOT_READY,publication;
 if(mayContinue==NULL||log==NULL)return EFI_INVALID_PARAMETER;
 if(mRan){*mayContinue=!mResult.FatalRestore;return EFI_ALREADY_STARTED;}
 *mayContinue=TRUE;mRan=TRUE;mLog=log;
 ZeroMem(&mResult,sizeof(mResult));ZeroMem(&cpu,sizeof(cpu));
 mResult.Size=sizeof(mResult);mResult.Version=1;mResult.Magic=G134_MAGIC;
 for(UINTN i=0;i<8;i++)mResult.Status[i]=EFI_NOT_READY;
 if(ready)mResult.Flags|=1;
 if(OpenKernelWindowInventoryComplete())mResult.Flags|=2;
 meta=OpenGetPilMetadataReport();
 if(meta!=NULL&&meta->Size==sizeof(*meta)&&meta->Version==1&&meta->Magic==G128_MAGIC&&
    meta->Status[0]==EFI_SUCCESS&&(meta->Flags&0x7ff)==0x7ff&&meta->ScmABI==OP_ABI_ARMV8&&
    meta->ImagesAttempted==2&&meta->RequestedPasStages==0)mResult.Flags|=4;
 if((mResult.Flags&7)!=7)goto Done;
 mResult.Status[0]=EFI_SUCCESS;
 s=gBS->LocateProtocol(&mPilGuid,NULL,&pil);if(s!=EFI_SUCCESS||pil==NULL)goto Done;
 s=gBS->LocateProtocol(&mScmGuid,NULL,&scm);if(s!=EFI_SUCCESS||scm==NULL)goto Done;
 if(meta->ImageBase[0]>MAX_UINT64-0x42000||meta->ImageBase[1]>MAX_UINT64-0x42000||
    (UINTN)pil!=meta->ImageBase[0]+0x16188||Q(pil)!=0x10004||
    Q((UINT8 *)pil+16)!=meta->ImageBase[0]+0x172c||
    meta->ScmTableRva!=0xe140||meta->ScmFunctionRva!=0x3f94||
    (UINTN)scm!=meta->ImageBase[1]+0xe140||Q(scm)!=0x40001){s=EFI_COMPROMISED_DATA;goto Done;}
 mResult.ScmSlot=(UINTN)scm+56;mOriginal=Q((UINT8 *)scm+56);
 if(mOriginal!=meta->ImageBase[1]+0x3f94){s=EFI_COMPROMISED_DATA;goto Done;}
 mResult.OriginalMethod=mOriginal;mResult.WrapperMethod=(UINTN)Observe;
 mResult.Flags|=8;mResult.Status[1]=EFI_SUCCESS;method=Q((UINT8 *)pil+16);
 s=GopAdmission();mResult.Status[2]=s;if(s!=EFI_SUCCESS)goto Done;mResult.Flags|=16;
 el=OpenDspCurrentEl();mResult.CpuEl=el;
 if(el!=1&&el!=2){s=EFI_UNSUPPORTED;goto CpuDone;}
 if(!OpenCheckCpuRange(&cpu,OpenDspAt,&el,mResult.ScmSlot&~4095ULL,4096))
  OpenCheckCpuRange(&cpu,OpenDspAt,&el,0xa9f80000,0x4900000);
 s=cpu.Refusal?EFI_ACCESS_DENIED:EFI_SUCCESS;
CpuDone:
 mResult.CpuPages=cpu.Pages;mResult.CpuQueries=cpu.Queries;mResult.CpuFirstBad=cpu.FirstBad;
 mResult.CpuReadPar=cpu.ReadPar;mResult.CpuWritePar=cpu.WritePar;mResult.CpuRefusal=cpu.Refusal;
 mResult.Status[3]=s;mLog("G134_CPU el=%lu pages=%lu queries=%lu first_bad=%lx read_PAR=%lx write_PAR=%lx status=%r stage=1\n",el,cpu.Pages,cpu.Queries,cpu.FirstBad,cpu.ReadPar,cpu.WritePar,s);
 if(s!=EFI_SUCCESS)goto Done;mResult.Flags|=32;
 CopyMem(cfg,meta->Config,sizeof(cfg));
 for(UINTN i=0;i<2;i++){
  UINT32 id;CopyMem(&id,cfg[i]+0xec,4);
  if(Q(cfg[i])!=3||id!=(i?1U:36U)||cfg[i][0x101]!=0){s=EFI_COMPROMISED_DATA;goto Done;}
  /* No backup or post-image action is permitted after a failure. */
  for(UINTN n=0x114;n<0x174;n++)if(cfg[i][n]!=0){s=EFI_COMPROMISED_DATA;goto Done;}
  for(UINTN n=0x1b4;n<0x1f4;n++)if(cfg[i][n]!=0){s=EFI_COMPROMISED_DATA;goto Done;}
 }
 if(Q(cfg[0]+0xf0)!=0x9e980000||Q(cfg[0]+0xf8)!=0x80000||
    Q(cfg[1]+0xf0)!=0x9ea00000||Q(cfg[1]+0xf8)!=0x4880000){s=EFI_COMPROMISED_DATA;goto Done;}
 SetQ(cfg[0]+0xf0,0xa9f80000);cfg[0][0x102]=1;
 SetQ(cfg[1]+0xf0,0xaa000000);ZeroMem(cfg[1]+0x174,64);
 /* The public custom-config method copies into the existing retail record.
    Load DTB once, then main with its preimage field cleared to prevent a second
    DTB request. Original global records are temporary RAM state until reboot. */
 OpenPasInit(&mObserver,Forward,scm,OP_ABI_ARMV8);
 s=(EFI_STATUS)OpenPasArm(&mObserver);if(s!=EFI_SUCCESS)goto Done;
 prior=gBS->RaiseTPL(TPL_HIGH_LEVEL);
 if(Q((UINT8 *)scm+56)!=mOriginal){s=EFI_ACCESS_DENIED;}
 else{SetQ((UINT8 *)scm+56,(UINTN)Observe);MemoryFence();mResult.HookStores++;s=Q((UINT8 *)scm+56)==(UINTN)Observe?EFI_SUCCESS:EFI_DEVICE_ERROR;}
 gBS->RestoreTPL(prior);mResult.Status[4]=s;
 if(s==EFI_SUCCESS){
  VOID *current=NULL;
  EFI_STATUS verify=gBS->LocateProtocol(&mScmGuid,NULL,&current);
  if(verify!=EFI_SUCCESS||current!=scm||Q((UINT8 *)scm+56)!=(UINTN)Observe)s=EFI_ACCESS_DENIED;
  mResult.Status[4]=s;
 }
 if(s==EFI_SUCCESS){
  mResult.Flags|=64;mResult.PilRequests++;
  mResult.Status[5]=LoadCfg((UINTN)method,cfg[0]);
  if(mResult.Status[5]==EFI_SUCCESS&&mObserver.Fault==0&&mObserver.Phase[0]==3&&mObserver.AuthAcceptedMask==1){
   VOID *current=NULL;EFI_STATUS verify=gBS->LocateProtocol(&mScmGuid,NULL,&current);
   mResult.Flags|=256;
   if(verify==EFI_SUCCESS&&current==scm&&Q((UINT8 *)scm+56)==(UINTN)Observe){
    mResult.PilRequests++;mResult.Status[6]=LoadCfg((UINTN)method,cfg[1]);
   }else mResult.Status[6]=EFI_ACCESS_DENIED;
   if(mResult.Status[6]==EFI_SUCCESS&&mObserver.Fault==0&&mObserver.Phase[1]==3&&mObserver.AuthAcceptedMask==3)mResult.Flags|=512;
  }
 }
 OpenPasDisarm(&mObserver);
 /* Restore before cleanup or boot. If another owner replaced our slot, never
    overwrite it; refuse continuation with this code/context still retained. */
 prior=gBS->RaiseTPL(TPL_HIGH_LEVEL);
 if(Q((UINT8 *)scm+56)==(UINTN)Observe){SetQ((UINT8 *)scm+56,mOriginal);MemoryFence();mResult.HookStores++;}
 mResult.Status[7]=Q((UINT8 *)scm+56)==mOriginal?EFI_SUCCESS:EFI_DEVICE_ERROR;
 gBS->RestoreTPL(prior);
 { VOID *again=NULL;EFI_STATUS verify=gBS->LocateProtocol(&mScmGuid,NULL,&again);
   if(verify!=EFI_SUCCESS||again!=scm||Q((UINT8 *)scm+56)!=mOriginal)mResult.Status[7]=EFI_DEVICE_ERROR; }
 if(mResult.Status[7]==EFI_SUCCESS)mResult.Flags|=128;
 else{mResult.FatalRestore=1;*mayContinue=FALSE;}
 s=(mResult.Flags&(256|512|128))==(256|512|128)&&mObserver.Fault==0?EFI_SUCCESS:EFI_DEVICE_ERROR;
 if(s==EFI_SUCCESS)mResult.Flags|=1024;
Done:
 mResult.FinalStatus=s;
 mResult.Count=mObserver.Count;mResult.Fault=mObserver.Fault;
 CopyMem(mResult.Phase,mObserver.Phase,sizeof(mResult.Phase));
 mResult.AuthEnteredMask=mObserver.AuthEnteredMask;mResult.AuthAcceptedMask=mObserver.AuthAcceptedMask;
 CopyMem(mResult.Records,mObserver.Records,sizeof(mResult.Records));
 mLog("G134_FINAL status=%r flags=%x PIL_requests=%u PAS_records=%u fault=%x auth_entered=%x auth_accepted=%x restored=%u GLINK_ready=not_tested\n",s,mResult.Flags,mResult.PilRequests,mResult.Count,mResult.Fault,mResult.AuthEnteredMask,mResult.AuthAcceptedMask,(mResult.Flags&128)!=0);
 publication=Publish();mLog("G134_publication status=%r\n",publication);
 return s;
}
