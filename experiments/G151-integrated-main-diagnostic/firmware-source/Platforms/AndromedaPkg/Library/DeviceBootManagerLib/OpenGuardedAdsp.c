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
#include "OpenPilFootprint.h"

STATIC EFI_GUID mPilGuid={0x1f4f1da3,0x4d8d,0x4894,{0xba,0x2a,0x13,0xd3,0x20,0x7f,0x97,0x39}};
STATIC EFI_GUID mScmGuid={0x77ed108d,0x8524,0x4b8b,{0x9d,0x2e,0x34,0x98,0x7a,0xec,0xb9,0xc1}};
STATIC BOOLEAN mRan;
STATIC G151_REPORT mResult;
STATIC OP_OBSERVER mObserver;
STATIC OPEN_KERNEL_REPORT mLog;
STATIC UINT64 mOriginal;
STATIC OL_STATE mSerial;
STATIC OMP_CHECKER mPayload;
_Static_assert(sizeof(G151_REPORT)==9080,"fixed main diagnostic report ABI");
STATIC UINT64 mSerialSlot;
/* Observed SCM cache consumers use Write+10h, Poll+28h and Read+30h.
 * Only these modeled debug operations are available during the diagnostic.
 * The original serial object is neither read nor called; its pointer is saved
 * verbatim and restored before boot continuation. */
typedef struct {
 UINT64 Reserved0,Reserved1;
 UINTN(EFIAPI *Write)(CONST VOID *,UINTN);
 UINT64 Reserved3,Reserved4;
 BOOLEAN(EFIAPI *Poll)(VOID);
 UINTN(EFIAPI *Read)(VOID *,UINTN);
} G151_SERIAL_PROXY;
STATIC UINTN EFIAPI SerialWrite(CONST VOID *buffer,UINTN bytes){return (UINTN)OpenScmLogConsume(&mSerial,buffer,bytes);}
STATIC BOOLEAN EFIAPI SerialPoll(VOID){if(mSerial.Report.OtherCalls!=MAX_UINT32)mSerial.Report.OtherCalls++;return FALSE;}
STATIC UINTN EFIAPI SerialRead(VOID *buffer,UINTN bytes){(VOID)buffer;(VOID)bytes;if(mSerial.Report.OtherCalls!=MAX_UINT32)mSerial.Report.OtherCalls++;return 0;}
STATIC G151_SERIAL_PROXY mSerialProxy={0,0,SerialWrite,0,0,SerialPoll,SerialRead};
_Static_assert(sizeof(G151_SERIAL_PROXY)==56,"fixed observed serial proxy extent");
CONST G151_REPORT *OpenGetGuardedAdspReport(VOID){return mRan?&mResult:NULL;}
CONST OL_REPORT *OpenGetScmErrorReport(VOID){return mRan?&mSerial.Report:NULL;}
STATIC UINT64 Q(CONST VOID *P){UINT64 v;CopyMem(&v,P,8);return v;}
STATIC VOID SetQ(VOID *P,UINT64 v){CopyMem(P,&v,8);}
STATIC OP_U64 EFIAPI Observe(VOID *,OP_U32,OP_U32,OP_U64 *,OP_U64 *);
STATIC unsigned VerifyOwnership(VOID *self){
 VOID *current=NULL;EFI_STATUS s=gBS->LocateProtocol(&mScmGuid,NULL,&current);
 return s==EFI_SUCCESS&&current==self&&self==mObserver.ExpectedThis&&
        Q((VOID *)(UINTN)mResult.ScmSlot)==(UINTN)Observe&&
        Q((VOID *)(UINTN)mSerialSlot)==(UINTN)&mSerialProxy;
}
STATIC unsigned AuthorizeDtbCopy(VOID *self){
 return VerifyOwnership(self)&&
  OpenDtbAuthorizeCopy(OpenPilSetupFootprintReady(),mLog)==EFI_SUCCESS;
}
STATIC unsigned VerifyDtbPayload(VOID *self){
 return VerifyOwnership(self)&&
  OpenDtbVerifyPayload(OpenPilSetupFootprintReady(),mLog)==EFI_SUCCESS;
}

/* The verifier supplies fixed89 extents; the adapter independently refuses any
 * range outside them before the physical read boundary. */
#include "OpenMainPayloadPlan.h"
STATIC BOOLEAN MainReadRange(UINT64 at,UINTN n){
 if(!n||n>OMP_CHUNK||at>MAX_UINT64-n)return FALSE;
 for(UINTN i=0;i<OMP_EXTENTS;i++){
  CONST OMP_PLAN *p=&mMainPlan[i];
  if(at>=p->Base&&at<p->Base+p->Bytes&&n<=p->Base+p->Bytes-at)return TRUE;
 }
 return FALSE;
}
STATIC unsigned EFIAPI MainOwner(VOID *context){
 return context==&mObserver&&mObserver.Busy&&mObserver.DtbPublicComplete==1&&
        mObserver.Phase[1]==2&&mObserver.CopyAllowed[1]==1&&VerifyOwnership(mObserver.ExpectedThis);
}
STATIC unsigned EFIAPI RefreshMain(VOID *context){
 return MainOwner(context)&&OpenMainRefreshAdmission(OpenPilSetupFootprintReady(),mLog)==EFI_SUCCESS;
}
STATIC EFI_STATUS EFIAPI ReadMain(VOID *context,UINT64 at,UINTN *bytes,VOID *out){
 if(bytes==NULL)return EFI_INVALID_PARAMETER;
 UINTN n=*bytes;*bytes=0;
 CONST OPEN_MAIN_ADMISSION_REPORT *r=OpenGetMainAdmissionReport();
 if(!MainOwner(context)||out!=mPayload.Scratch||!MainReadRange(at,n)||r==NULL||
    r->CopyGranted!=1||r->AcceptedRefreshes!=1||r->Fault!=0)return EFI_ACCESS_DENIED;
 MemoryFence();
#ifndef OPEN_GUARDED_ADSP_MODEL
 CopyMem(out,(CONST VOID *)(UINTN)at,n);
#else
 extern EFI_STATUS MainModelRead(UINT64,UINTN,VOID *);
 EFI_STATUS s=MainModelRead(at,n,out);if(s!=EFI_SUCCESS)return s;
#endif
 MemoryFence();*bytes=n;return EFI_SUCCESS;
}
STATIC unsigned AuthorizeMainCopy(VOID *self){
 return VerifyOwnership(self)&&mObserver.DtbPublicComplete==1&&
  OpenMainAuthorizeCopy(OpenPilSetupFootprintReady(),mLog)==EFI_SUCCESS;
}
STATIC unsigned VerifyMainPayload(VOID *self){
 return VerifyOwnership(self)&&OpenMainPayloadVerify(&mPayload)==EFI_SUCCESS;
}

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
 volatile UINT8 anchor=0;
 unsigned begun=OpenScmLogBegin(&mSerial,command,args?args[0]:0,
                               mObserver.Count?mObserver.Count-1:16,(UINTN)&anchor);
 if(mSerial.Report.OriginalCalls!=MAX_UINT32)mSerial.Report.OriginalCalls++;
 UINT64 status=RawSip(self,command,param,args,results);
 if(begun)OpenScmLogEnd(&mSerial,status,results?results[0]:0);
 return status;
}
STATIC OP_U64 EFIAPI Observe(VOID *self,OP_U32 command,OP_U32 param,OP_U64 *args,OP_U64 *results){
 if(!mObserver.Active)return RawSip(self,command,param,args,results);
 OP_U32 before=mObserver.Count;
 UINT64 id=args?args[0]:0,status;
 BOOLEAN tracked=(command==0x42000201||command==0x42000202||command==0x42000205||command==0x42000206)&&(id==36||id==1);
 if(tracked){mLog("G151_PAS_enter command=%x param=%x image=%lu\n",command,param,id);Print(L"G151 PAS %x image %lu: enter\n",command,id);}
 status=OpenPasCall(&mObserver,self,command,param,args,results);
 if(tracked&&mObserver.Count>before){
  OP_RECORD *r=&mObserver.Records[mObserver.Count-1];
  mLog("G151_PAS_return command=%x image=%u entered=%u returned=%u transport=%lx result0=%lx result1=%lx filtered=%lx refusal=%x\n",command,r->ImageId,r->Entered,r->Returned,r->OriginalStatus,r->Results[0],r->Results[1],r->ReturnedStatus,r->Refusal);
  Print(L"G151 PAS %x image %lu: return %lx, service %lx\n",command,id,status,r->Results[1]);
 }
 return status;
}
STATIC BOOLEAN Overlap(UINT64 base,UINT64 bytes){return bytes&&base<=MAX_UINT64-bytes&&base<0xa3280000ULL&&base+bytes>0x9e980000ULL;}
STATIC EFI_STATUS GopAdmission(VOID){
 EFI_HANDLE *handles=NULL;EFI_GRAPHICS_OUTPUT_PROTOCOL *gop;
 UINTN count=0;EFI_STATUS s=gBS->LocateHandleBuffer(ByProtocol,&gEfiGraphicsOutputProtocolGuid,NULL,&count,&handles);
 if(s!=EFI_SUCCESS||handles==NULL||count==0||count>8){if(handles!=NULL&&s==EFI_SUCCESS)FreePool(handles);return EFI_NOT_READY;}
 mResult.GopCount=(UINT32)count;
 for(UINTN i=0;i<count;i++){
  gop=NULL;s=gBS->HandleProtocol(handles[i],&gEfiGraphicsOutputProtocolGuid,(VOID **)&gop);
  if(s!=EFI_SUCCESS||gop==NULL||gop->Mode==NULL||gop->Mode->FrameBufferSize==0){s=EFI_NOT_READY;break;}
  UINT64 base=gop->Mode->FrameBufferBase,bytes=gop->Mode->FrameBufferSize;
  mLog("G151_GOP base=%lx bytes=%lx overlap=%u\n",base,bytes,Overlap(base,bytes));
  if(base>MAX_UINT64-bytes||Overlap(base,bytes)){s=EFI_ACCESS_DENIED;break;}
 }
 FreePool(handles);return s;
}
STATIC EFI_STATUS Publish(CONST VOID *body,UINTN bytes,UINT32 signature,CONST CHAR8 *tableId){
 EFI_ACPI_TABLE_PROTOCOL *acpi;EFI_STATUS s;UINTN n=sizeof(EFI_ACPI_DESCRIPTION_HEADER)+bytes,key;UINT8 sum=0;
 s=gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid,NULL,(VOID **)&acpi);if(s!=EFI_SUCCESS||acpi==NULL)return EFI_NOT_FOUND;
 EFI_ACPI_DESCRIPTION_HEADER *h=AllocateZeroPool(n);if(h==NULL)return EFI_OUT_OF_RESOURCES;
 h->Signature=signature;h->Length=(UINT32)n;h->Revision=1;
 CopyMem(h->OemId,"OPEN  ",6);CopyMem(&h->OemTableId,tableId,8);h->OemRevision=151;
 h->CreatorId=SIGNATURE_32('O','P','E','N');h->CreatorRevision=1;CopyMem(h+1,body,bytes);
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
 ZeroMem(&mResult,sizeof(mResult));ZeroMem(&cpu,sizeof(cpu));OpenScmLogInit(&mSerial);
 mResult.Size=sizeof(mResult);mResult.Version=1;mResult.Magic=G151_MAGIC;
 mResult.MainEnabled=1;mResult.DtbMarkerStatus=EFI_NOT_READY;
 for(UINTN i=0;i<8;i++)mResult.Status[i]=EFI_NOT_READY;
 s=OpenDtbAdmissionInit();if(s!=EFI_SUCCESS)goto Done;
 s=OpenMainAdmissionInit();if(s!=EFI_SUCCESS)goto Done;
 s=OpenMainPayloadInit(&mPayload,ReadMain,RefreshMain,MainOwner,&mObserver);if(s!=EFI_SUCCESS)goto Done;
 s=EFI_NOT_READY;
 if(ready && OpenPilSetupFootprintReady())mResult.Flags|=1;
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
 mSerialSlot=meta->ImageBase[1]+0xe580;
 mSerial.Report.ImageBase=meta->ImageBase[1];mSerial.Report.CacheSlot=mSerialSlot;
 mSerial.Report.OriginalMethod=mOriginal;mSerial.Report.Proxy=(UINTN)&mSerialProxy;
 /* The previously bound whole SCM text includes the formatter, mask and
  * consumers; E580 is a private data cache in the same admitted page as E178. */
 if((mSerialSlot&~4095ULL)!=(mResult.ScmSlot&~4095ULL)){s=EFI_COMPROMISED_DATA;goto Done;}
 mResult.Flags|=8;mResult.Status[1]=EFI_SUCCESS;method=Q((UINT8 *)pil+16);
 s=GopAdmission();mResult.Status[2]=s;if(s!=EFI_SUCCESS)goto Done;mResult.Flags|=16;
 el=OpenDspCurrentEl();mResult.CpuEl=el;
 if(el!=1&&el!=2){s=EFI_UNSUPPORTED;goto CpuDone;}
 if(!OpenCheckCpuRange(&cpu,OpenDspAt,&el,mResult.ScmSlot&~4095ULL,4096))
  OpenCheckPilCpuRange(&cpu,OpenDspAt,&el);
 s=cpu.Refusal?EFI_ACCESS_DENIED:EFI_SUCCESS;
CpuDone:
 mResult.CpuPages=cpu.Pages;mResult.CpuQueries=cpu.Queries;mResult.CpuFirstBad=cpu.FirstBad;
 mResult.CpuReadPar=cpu.ReadPar;mResult.CpuWritePar=cpu.WritePar;mResult.CpuRefusal=cpu.Refusal;
 mResult.Status[3]=s;mLog("G151_CPU el=%lu pages=%lu queries=%lu first_bad=%lx read_PAR=%lx write_PAR=%lx status=%r stage=1\n",el,cpu.Pages,cpu.Queries,cpu.FirstBad,cpu.ReadPar,cpu.WritePar,s);
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
 /* Original reserved DTB placement, with a separate finite copy admission
  * after MEM_SETUP and an exact payload check before AUTH. No remapping. */
 SetQ(cfg[0]+0xf0,0x9e980000);cfg[0][0x102]=1;
 mLog("G151_DTB_request base=9E980000 bytes=80000 payload_bytes=8376 payload_AT_tag=44 hook_AT_tag=FF main=after_DTB_public_completion\n");
 /* The public custom-config method copies into the existing retail record.
    Load DTB once. Clear only the local main preimage after public completion.
    Original global records are temporary RAM state until reboot. */
 OpenPasInit(&mObserver,Forward,scm,OP_ABI_ARMV8);
 mObserver.Verify=VerifyOwnership;
 mObserver.AuthorizeDtbCopy=AuthorizeDtbCopy;
 mObserver.VerifyDtbPayload=VerifyDtbPayload;
 mObserver.AuthorizeMainCopy=AuthorizeMainCopy;
 mObserver.VerifyMainPayload=VerifyMainPayload;
 s=(EFI_STATUS)OpenPasArm(&mObserver);if(s!=EFI_SUCCESS)goto Done;
 mSerial.Report.SavedCache=Q((VOID *)(UINTN)mSerialSlot);
 if(mSerial.Report.SavedCache==(UINTN)&mSerialProxy){
  mSerial.Report.RestoreStatus=EFI_DEVICE_ERROR;mSerial.Report.FatalRestore=1;
  mResult.FatalRestore=1;*mayContinue=FALSE;s=EFI_COMPROMISED_DATA;
  OpenPasDisarm(&mObserver);goto Done;
 }
 prior=gBS->RaiseTPL(TPL_HIGH_LEVEL);
 if(Q((UINT8 *)scm+56)!=mOriginal||Q((VOID *)(UINTN)mSerialSlot)!=mSerial.Report.SavedCache){s=EFI_ACCESS_DENIED;}
 else{
  SetQ((VOID *)(UINTN)mSerialSlot,(UINTN)&mSerialProxy);MemoryFence();mSerial.Report.HookStores++;
  s=Q((VOID *)(UINTN)mSerialSlot)==(UINTN)&mSerialProxy?EFI_SUCCESS:EFI_DEVICE_ERROR;
  if(s==EFI_SUCCESS){
   mSerial.Report.Active=1;
   SetQ((UINT8 *)scm+56,(UINTN)Observe);MemoryFence();mResult.HookStores++;
   s=Q((UINT8 *)scm+56)==(UINTN)Observe?EFI_SUCCESS:EFI_DEVICE_ERROR;
  }
 }
 mSerial.Report.HookStatus=s;
 gBS->RestoreTPL(prior);mResult.Status[4]=s;
 if(s==EFI_SUCCESS){
  VOID *current=NULL;
  EFI_STATUS verify=gBS->LocateProtocol(&mScmGuid,NULL,&current);
  if(verify!=EFI_SUCCESS||current!=scm||Q((UINT8 *)scm+56)!=(UINTN)Observe||
     Q((VOID *)(UINTN)mSerialSlot)!=(UINTN)&mSerialProxy)s=EFI_ACCESS_DENIED;
  mResult.Status[4]=s;
  mSerial.Report.HookStatus=s;
 }
 if(s==EFI_SUCCESS){
  mResult.Flags|=64;mResult.PilRequests++;
  mResult.Status[5]=LoadCfg((UINTN)method,cfg[0]);
  mResult.DtbLoadReturned=1;
  mResult.DtbPublicSuccess=mResult.Status[5]==0&&mObserver.AuthAcceptedMask==1&&
   mObserver.Phase[0]==3&&mObserver.Phase[1]==0&&mObserver.Fault==0;
  /* Original POST/public failure is retained even after accepted DTB AUTH.
   * Incomplete earlier stages never acquire a public-completion marker. */
  if(mObserver.Count==3&&mObserver.Phase[0]==3&&mObserver.Phase[1]==0&&mObserver.Fault==0)
   mResult.DtbMarkerStatus=OpenPasFinishDtb(&mObserver,mResult.Status[5]);
  mResult.DtbPublicComplete=mObserver.DtbPublicComplete;
  if(mResult.DtbPublicSuccess&&mResult.DtbPublicComplete&&mResult.DtbMarkerStatus==EFI_SUCCESS){
   /* Only the local main config loses its automatic duplicate DTB preimage.
    * The pinned original metadata/config and secure arguments remain unchanged. */
   ZeroMem(cfg[1]+0x174,64);
   mResult.PilRequests++;
   mResult.Status[6]=LoadCfg((UINTN)method,cfg[1]);mResult.MainLoadReturned=1;
   mResult.MainPublicSuccess=mResult.Status[6]==0&&mObserver.Phase[0]==3&&
    mObserver.Phase[1]==3&&mObserver.AuthAcceptedMask==3&&mObserver.Fault==0;
  }
 }
 OpenPasDisarm(&mObserver);
 mSerial.Report.DiagnosticStop=mResult.MainPublicSuccess;
 mSerial.Report.Active=0;
 /* Restore before cleanup or boot. If another owner replaced our slot, never
    overwrite it; refuse continuation with this code/context still retained. */
 prior=gBS->RaiseTPL(TPL_HIGH_LEVEL);
 if(Q((UINT8 *)scm+56)==(UINTN)Observe){SetQ((UINT8 *)scm+56,mOriginal);MemoryFence();mResult.HookStores++;}
 mResult.Status[7]=Q((UINT8 *)scm+56)==mOriginal?EFI_SUCCESS:EFI_DEVICE_ERROR;
 if(Q((VOID *)(UINTN)mSerialSlot)==(UINTN)&mSerialProxy){
  SetQ((VOID *)(UINTN)mSerialSlot,mSerial.Report.SavedCache);MemoryFence();mSerial.Report.HookStores++;
 }
 mSerial.Report.RestoreStatus=Q((VOID *)(UINTN)mSerialSlot)==mSerial.Report.SavedCache?EFI_SUCCESS:EFI_DEVICE_ERROR;
 gBS->RestoreTPL(prior);
 { VOID *again=NULL;EFI_STATUS verify=gBS->LocateProtocol(&mScmGuid,NULL,&again);
   if(verify!=EFI_SUCCESS||again!=scm||Q((UINT8 *)scm+56)!=mOriginal)mResult.Status[7]=EFI_DEVICE_ERROR;
   if(verify!=EFI_SUCCESS||again!=scm||Q((VOID *)(UINTN)mSerialSlot)!=mSerial.Report.SavedCache)mSerial.Report.RestoreStatus=EFI_DEVICE_ERROR; }
 if(mSerial.Report.RestoreStatus!=EFI_SUCCESS)mSerial.Report.FatalRestore=1;
 if(mResult.Status[7]==EFI_SUCCESS&&mSerial.Report.RestoreStatus==EFI_SUCCESS)mResult.Flags|=128;
 else{mResult.FatalRestore=1;*mayContinue=FALSE;}
 s=mResult.MainPublicSuccess&&(mResult.Flags&128)?EFI_ABORTED:EFI_DEVICE_ERROR;
Done:
 mResult.FinalStatus=s;
 mResult.Count=mObserver.Count;mResult.Fault=mObserver.Fault;
 CopyMem(mResult.Phase,mObserver.Phase,sizeof(mResult.Phase));
 mResult.AuthEnteredMask=mObserver.AuthEnteredMask;mResult.AuthAcceptedMask=mObserver.AuthAcceptedMask;
 CopyMem(mResult.Records,mObserver.Records,sizeof(mResult.Records));
 {CONST OPEN_DTB_ADMISSION_REPORT *r=OpenGetDtbAdmissionReport();if(r)CopyMem(&mResult.Dtb,r,sizeof(mResult.Dtb));}
 {CONST OPEN_MAIN_ADMISSION_REPORT *r=OpenGetMainAdmissionReport();if(r)CopyMem(&mResult.Main,r,sizeof(mResult.Main));}
 CopyMem(&mResult.Payload,&mPayload.Report,sizeof(mResult.Payload));
 mLog("G151_public_returns DTB=%lx DTB_marker=%lx DTB_complete=%u main=%lx main_returned=%u main_success=%u PRE_POST_direct=not_observed\n",
  mResult.Status[5],mResult.DtbMarkerStatus,mResult.DtbPublicComplete,mResult.Status[6],mResult.MainLoadReturned,mResult.MainPublicSuccess);
 mLog("G151_FINAL status=%r flags=%x PIL_requests=%u PAS_records=%u fault=%x auth_entered=%x auth_accepted=%x restored=%u GLINK_ready=not_tested\n",s,mResult.Flags,mResult.PilRequests,mResult.Count,mResult.Fault,mResult.AuthEnteredMask,mResult.AuthAcceptedMask,(mResult.Flags&128)!=0);
 publication=Publish(&mResult,sizeof(mResult),SIGNATURE_32('O','A','D','P'),"G151DSP1");mLog("G151_publication status=%r\n",publication);
 publication=Publish(&mSerial.Report,sizeof(mSerial.Report),SIGNATURE_32('O','S','E','R'),"G151SIP1");
 mLog("G151_SCM_log_publication status=%r captured=%u rejected=%u restored=%r stop=%u\n",publication,mSerial.Report.Count,mSerial.Report.Rejected,mSerial.Report.RestoreStatus,mSerial.Report.DiagnosticStop);
 return s;
}
