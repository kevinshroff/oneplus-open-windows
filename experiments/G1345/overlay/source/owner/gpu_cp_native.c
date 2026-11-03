/* Native single-context SID0/CB0 CP init fence1. No HAL, PAS, secure exit or IOCTL. */
#include "gpu_owner.h"
#include "gpu_cp_native.h"
#include "g1341_cb0_policy.h"
#if !OGO_GPU_CB0_STALL_ON_FAULT
#error G1343 requires the matched G1341 CB0 stall profile
#endif
#include "gpu_va_layout.h"
#include "ogo_gpu_allocation.h"
#include "g433_sqe_pin.h"
#include <intrin.h>
#define UINTN SIZE_T
#define STATIC static
#define CopyMem RtlCopyMemory
#define ZeroMem RtlZeroMemory
#include "OpenSha256.h"
#undef UINTN
#undef STATIC
#undef CopyMem
#undef ZeroMem
#define GX_STATUS 0x14340u
/* Pinned gen7_reg.h GEN7_GMU_AHB_FENCE_STATUS word23b13, corebase1a800. */
#define AHB_STATUS ((0x23b13u-0x1a800u)*4u)
_Static_assert(AHB_STATUS==0x24c4c,"source AHB status rebase");
NTSTATUS OgoCpCurrent(OGO_CONTEXT*p){
 G982_CP*c=p->Cp;if(!c||!c->Scope||!p->CpInit||!p->Gmu||!p->Active||p->OperationThread!=PsGetCurrentThread()||p->Active->OperationThread!=PsGetCurrentThread()||p->Gmu->LastStatus!=STATUS_SUCCESS||p->Gmu->CoreStatus!=G190_OK||p->Gmu->Core.phase!=G190_STARTUP_COMPLETE||p->Gmu->Core.startup_acked!=15||!p->Gmu->Core.reset_released)return STATUS_DEVICE_NOT_READY;
 NTSTATUS s=OgoGmuCurrent(p->Gmu);if(s!=STATUS_SUCCESS)return s;return p->Bank.Api.CheckGpuUser(p->Bank.Api.Interface.Context,&p->Bank.Native,&p->GpuUser,&p->Active->Scope);
}
/* Private cold-first-use authority, never a generic warm stopped witness. */
static NTSTATUS FirstUseFrame(OGO_CONTEXT*p){
 G982_CP*c=p->Cp;if(!c||!c->Scope||!c->InitialOff||!c->Published||c->FirstUseConsumed||c->Run.MastersMayRun||c->Run.Poisoned||c->Run.Closed||c->Phase<3||c->Phase>4||!c->Run.Prepared||!c->Tables.ActivationQualified||c->Run.Generation!=p->Hold.Generation||c->Run.Generation!=p->Gmu->Generation||c->Run.StopSerial!=p->Hold.Serial||!p->Hold.BootCommitted)return STATUS_INVALID_DEVICE_STATE;
 g440_gpu_power*q=&c->Run.Power;
 if(!q->held||q->released||q->poisoned||!q->freq_acked||!q->oob_may_be_held||q->status!=G190_OK||q->backend!=&p->Gmu->Core||q->generation!=c->Run.Generation||q->epoch!=p->Gmu->Core.epoch||q->stop_serial!=c->Run.StopSerial)return STATUS_INVALID_DEVICE_STATE;
 return OgoCpCurrent(p);
}
#if OGO_GPU_PRE_RELEASE_WITNESS
#include "g1325_witness_native.inc"
#endif
/* Finite active init trace: never emits from stage5 fence polling. */
static BOOLEAN CpTraceInit(OGO_CONTEXT*p){return p&&p->Cp&&p->Cp->Run.RunAttempted&&p->Cp->Run.Core.stage>=1&&p->Cp->Run.Core.stage<=4&&KeGetCurrentIrql()==PASSIVE_LEVEL;}
static void CpIoBegin(OGO_CONTEXT*p,ULONG off,ULONG op,ULONG value){if(CpTraceInit(p))DbgPrintEx(DPFLTR_IHVVIDEO_ID,DPFLTR_INFO_LEVEL,"G1126 CP begin run%llx stage%u op%u off%x value%08x\n",p->RunId,p->Cp->Run.Core.stage,op,off,value);}
static NTSTATUS CpIoEnd(OGO_CONTEXT*p,ULONG off,ULONG op,ULONG value,NTSTATUS s,BOOLEAN attempted,BOOLEAN valid){if(CpTraceInit(p))DbgPrintEx(DPFLTR_IHVVIDEO_ID,DPFLTR_INFO_LEVEL,"G1126 CP end run%llx stage%u op%u off%x value%08x status%08x attempt%u valid%u\n",p->RunId,p->Cp->Run.Core.stage,op,off,value,s,attempted,valid);return s;}
static void CpPoint(OGO_CONTEXT*p,const char*name,NTSTATUS s){if(KeGetCurrentIrql()==PASSIVE_LEVEL)DbgPrintEx(DPFLTR_IHVVIDEO_ID,DPFLTR_INFO_LEVEL,"G1126 point run%llx %s phase%u stage%u status%08x issued%u completed%u first%u\n",p->RunId,name,p->Cp->Phase,p->Cp->Run.Core.stage,s,p->Cp->Run.Core.issued,p->Cp->Run.Core.completed,p->Cp->FirstUseConsumed);}
/* SQE release window only; no new read/write or checkpoint outside init. */
static void SqePoint(OGO_CONTEXT*p,const char*name,NTSTATUS s,ULONG ahb,BOOLEAN valid){if(CpTraceInit(p))DbgPrintEx(DPFLTR_IHVVIDEO_ID,DPFLTR_INFO_LEVEL,"G1148 SQE run%llx %s stage%u status%08x ahb%08x valid%u first%u\n",p->RunId,name,p->Cp->Run.Core.stage,s,ahb,valid,p->Cp->FirstUseConsumed);}
static NTSTATUS GpuRead(PVOID x,ULONG off,PULONG out){OGO_CONTEXT*p=x;G982_CP*c=p->Cp;CpIoBegin(p,off,0,0);NTSTATUS s=OgoCpCurrent(p);if(s!=STATUS_SUCCESS)return CpIoEnd(p,off,0,0,s,FALSE,FALSE);
 BOOLEAN disabled=(BOOLEAN)(off==0x808*4&&c->Phase==4&&!c->FirstUseConsumed);
 if(disabled){s=FirstUseFrame(p);if(s!=STATUS_SUCCESS)return CpIoEnd(p,off,0,0,s,FALSE,FALSE);}
 c->LastOffset=off;c->LastWrite=0;c->LastValid=0;c->Reads++;s=G482GpuRead(&p->Io,off,out);
 if(s==STATUS_SUCCESS){c->LastValue=*out;c->LastValid=1;if(disabled&&*out!=0)return CpIoEnd(p,off,0,*out,STATUS_DEVICE_BUSY,TRUE,TRUE); /* exact cold disabled, including MAX refusal */}return CpIoEnd(p,off,0,s==STATUS_SUCCESS?*out:0,s,TRUE,(BOOLEAN)(s==STATUS_SUCCESS));
}
static NTSTATUS Ahb(PVOID x,PULONG out){OGO_CONTEXT*p=x;NTSTATUS s=OgoCpCurrent(p);return s==STATUS_SUCCESS?G482CoreRead(&p->Io,AHB_STATUS,out):s;}
static NTSTATUS GpuWrite(PVOID x,ULONG off,ULONG value){OGO_CONTEXT*p=x;G982_CP*c=p->Cp;ULONG drop;NTSTATUS s;CpIoBegin(p,off,1,value);
 if(off==0x808*4){
  /* G1343: owned BASE/ring admission retained; sole SQE store is ZERO.
   * Cold-zero idempotence is UNKNOWN. Terminal control, never release1.
   * gen7 ordinary cold start: owned BASE/ring first, then CNTL1 release.
   * CNTL3 is a recovery operation for an already initialized engine. */
  if(value!=0||c->Phase!=4||!c->Run.RunAttempted||!c->Run.Core.attempted||c->Run.Core.stage!=3)return CpIoEnd(p,off,1,value,STATUS_INVALID_DEVICE_STATE,FALSE,FALSE);
  s=FirstUseFrame(p);if(s!=STATUS_SUCCESS)return CpIoEnd(p,off,1,value,s,FALSE,FALSE);
  const ULONG regs[]={0x808*4,0x830*4,0x831*4,0x800*4,0x801*4,0x802*4};
  const ULONG want[]={0,(ULONG)c->Run.Layout.Iova[2],(ULONG)(c->Run.Layout.Iova[2]>>32),(ULONG)c->Run.Layout.Iova[0],(ULONG)(c->Run.Layout.Iova[0]>>32),0x20c};
  if(c->Run.Core.sqe.iova!=c->Run.Layout.Iova[2]||c->Run.Core.ring.iova!=c->Run.Layout.Iova[0])return CpIoEnd(p,off,1,value,STATUS_INVALID_DEVICE_STATE,FALSE,FALSE);
  for(unsigned i=0;i<RTL_NUMBER_OF(regs);i++){ULONG got;s=GpuRead(p,regs[i],&got);if(s!=STATUS_SUCCESS)return CpIoEnd(p,off,1,value,s,FALSE,FALSE);if(got!=want[i])return CpIoEnd(p,off,1,value,STATUS_DEVICE_DATA_ERROR,FALSE,FALSE);}
#if OGO_GPU_PRE_RELEASE_WITNESS
  return CpIoEnd(p,off,1,value,G1325StopBeforeRelease(p),FALSE,FALSE);
#endif
 }
 if(off==0x2020)SqePoint(p,"PRE_AHB_CURRENT_BEGIN",STATUS_SUCCESS,0,FALSE);
 s=Ahb(p,&drop);if(off==0x2020)SqePoint(p,"PRE_AHB_CURRENT_END",s,s==STATUS_SUCCESS?drop:0,(BOOLEAN)(s==STATUS_SUCCESS));if(s!=STATUS_SUCCESS)return CpIoEnd(p,off,1,value,s,FALSE,FALSE);if(drop)return CpIoEnd(p,off,1,value,STATUS_DEVICE_NOT_READY,FALSE,FALSE);
 c->Retain=TRUE;c->LastOffset=off;c->LastValue=value;c->LastWrite=1;c->LastValid=0;c->Writes++;
 if(off==0x808*4){c->FirstUseConsumed=TRUE;c->Run.MastersMayRun=TRUE;} /* before uncertain actual store */
 if(off==0x2020)SqePoint(p,"STORE_CALL_BEGIN",STATUS_SUCCESS,0,FALSE);
 s=G482GpuWrite(&p->Io,off,value);
 if(off==0x2020)SqePoint(p,"STORE_CALL_RETURN",s,0,FALSE);
 if(s==STATUS_SUCCESS){c->LastValid=1;if(off==0x2020)SqePoint(p,"POST_AHB_CURRENT_BEGIN",STATUS_SUCCESS,0,FALSE);s=Ahb(p,&drop);if(off==0x2020)SqePoint(p,"POST_AHB_CURRENT_END",s,s==STATUS_SUCCESS?drop:0,(BOOLEAN)(s==STATUS_SUCCESS));if(s==STATUS_SUCCESS&&drop)s=STATUS_DEVICE_NOT_READY;}if(off==0x2020&&s==STATUS_SUCCESS){ULONG observed=MAXULONG;s=GpuRead(p,off,&observed);if(s==STATUS_SUCCESS&&observed!=0)s=STATUS_DEVICE_DATA_ERROR;if(CpTraceInit(p))DbgPrintEx(DPFLTR_IHVVIDEO_ID,DPFLTR_INFO_LEVEL,"G1343 ZERO_READBACK run%llx status%08x value%08x accepted%u terminal1\n",p->RunId,s,observed,(BOOLEAN)(s==STATUS_SUCCESS));}
 return CpIoEnd(p,off,1,value,s,TRUE,c->LastValid);
}
static int CpLease(void*x){OGO_CONTEXT*p=x;BOOLEAN point=CpTraceInit(p)&&p->Cp->Run.Core.stage==1&&!p->Cp->Run.Core.time_seen;if(point)CpPoint(p,"postConfigureLease begin",STATUS_SUCCESS);NTSTATUS s=OgoCpCurrent(x);if(point)CpPoint(p,"postConfigureLease end",s);return s!=STATUS_SUCCESS;}
static int CpRead(void*x,uint32_t o,uint32_t*v){return GpuRead(x,o,(PULONG)v)!=STATUS_SUCCESS;}
static int CpWrite(void*x,uint32_t o,uint32_t v){return GpuWrite(x,o,v)!=STATUS_SUCCESS;}
static int CpFence(void*x,uint32_t*v){return Ahb(x,(PULONG)v)!=STATUS_SUCCESS;}
static int Publish(void*x,const volatile uint32_t*v,size_t n){UNREFERENCED_PARAMETER(v);UNREFERENCED_PARAMETER(n);OGO_CONTEXT*p=x;BOOLEAN point=CpTraceInit(p);if(point)CpPoint(p,"Publish begin",STATUS_SUCCESS);if(CpLease(x)){if(point)CpPoint(p,"Publish end",STATUS_DEVICE_NOT_READY);return -1;}__dsb(_ARM64_BARRIER_OSHST);if(point)CpPoint(p,"Publish end",STATUS_SUCCESS);return 0;}
static int Acquire(void*x,volatile uint32_t*v,size_t n){UNREFERENCED_PARAMETER(v);UNREFERENCED_PARAMETER(n);if(CpLease(x))return -1;__dmb(_ARM64_BARRIER_OSHLD);return 0;}
static int Barrier(void*x){OGO_CONTEXT*p=x;BOOLEAN point=CpTraceInit(p);if(point)CpPoint(p,"Barrier begin",STATUS_SUCCESS);if(CpLease(x)){if(point)CpPoint(p,"Barrier end",STATUS_DEVICE_NOT_READY);return -1;}__dsb(_ARM64_BARRIER_OSH);if(point)CpPoint(p,"Barrier end",STATUS_SUCCESS);return 0;}
static int Now(void*x,uint64_t*v){if(CpLease(x))return -1;ULONGLONG cycles;*v=KeQueryInterruptTimePrecise(&cycles)/10;return 0;}
static int Wait(void*x,uint32_t us){if(CpLease(x)||!us||us>1000)return -1;LARGE_INTEGER t;t.QuadPart=-(LONGLONG)us*10;return KeDelayExecutionThread(KernelMode,FALSE,&t)!=STATUS_SUCCESS;}
static int Cancelled(void*x){OGO_CONTEXT*p=x;return InterlockedCompareExchange(&p->Revoked,0,0)||InterlockedCompareExchange(&p->Life.Inhibit,0,0);}
static NTSTATUS LoadSqe(G982_CP*c){UNICODE_STRING name;OBJECT_ATTRIBUTES oa;IO_STATUS_BLOCK io;HANDLE f=NULL;FILE_STANDARD_INFORMATION info;RtlInitUnicodeString(&name,L"\\SystemRoot\\System32\\drivers\\OpenGpuInputs\\sqe.bin");InitializeObjectAttributes(&oa,&name,OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE,NULL,NULL);
 NTSTATUS s=ZwCreateFile(&f,FILE_READ_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE,&oa,&io,NULL,FILE_ATTRIBUTE_NORMAL,FILE_SHARE_READ,FILE_OPEN,FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE,NULL,0);if(s!=STATUS_SUCCESS)return s;
 s=ZwQueryInformationFile(f,&io,&info,sizeof(info),FileStandardInformation);if(s==STATUS_SUCCESS&&(info.Directory||info.EndOfFile.QuadPart!=G433_SQE_FILE_BYTES))s=STATUS_INVALID_IMAGE_HASH;
 if(s==STATUS_SUCCESS){c->SqeInput=ExAllocatePool2(POOL_FLAG_NON_PAGED,G433_SQE_FILE_BYTES,OGO_TAG);if(!c->SqeInput)s=STATUS_INSUFFICIENT_RESOURCES;}
 if(s==STATUS_SUCCESS){LARGE_INTEGER zero={0};s=ZwReadFile(f,NULL,NULL,NULL,&io,c->SqeInput,G433_SQE_FILE_BYTES,&zero,NULL);if(s==STATUS_SUCCESS&&io.Information!=G433_SQE_FILE_BYTES)s=STATUS_END_OF_FILE;}ZwClose(f);return s;
}
static NTSTATUS Prepare(OGO_CONTEXT*p){G982_CP*c=p->Cp;G433_RUNTIME*r=&c->Run;NTSTATUS s=OgoCpCurrent(p);if(s!=STATUS_SUCCESS)return s;
 KeInitializeMutex(&r->Lock,0);r->Initialized=TRUE;r->Gmu=p->Gmu;r->Generation=p->Gmu->Generation;r->StopSerial=p->Hold.Serial;r->Attempted=TRUE;r->Gpu.ReadGpuRegister=GpuRead;r->Gpu.WriteGpuRegister=GpuWrite;r->Gpu.AhbFenceStatus=Ahb;
 r->Gpu.Board=(G456_FACTS){r->Generation,0x70201,p->CpDdrType,1,1};
 const ULONGLONG va[4]=OGO_CP_VA_INITIALIZER;const SIZE_T bytes[4]={0x8000,0x1000,0x13000,0x1000};OSMI_INPUT in[4];RtlZeroMemory(in,sizeof(in));OsmiInitialize(&c->Tables);
 s=LoadSqe(c);if(s!=STATUS_SUCCESS)return s;
 for(unsigned i=0;i<4;i++){if((s=OgoCpCurrent(p))!=STATUS_SUCCESS)return s;G321_BUFFER*b=&r->Buffer[i];PHYSICAL_ADDRESS low={0},high,skip={0};high.QuadPart=OGO_GPU_ALLOC_HIGH;r->Layout.Iova[i]=va[i];r->Layout.Bytes[i]=bytes[i];
  b->Mdl=MmAllocatePagesForMdlEx(low,high,skip,bytes[i],MmNonCached,MM_ALLOCATE_FULLY_REQUIRED);if(!b->Mdl)return STATUS_INSUFFICIENT_RESOURCES;
  if(!(b->Mdl->MdlFlags&MDL_PAGES_LOCKED)||MmGetMdlByteOffset(b->Mdl)||MmGetMdlByteCount(b->Mdl)!=bytes[i])return STATUS_DEVICE_CONFIGURATION_ERROR;
  PPFN_NUMBER pfns=MmGetMdlPfnArray(b->Mdl);for(SIZE_T j=0;j<bytes[i]/4096;j++)if((ULONGLONG)pfns[j]>=OGO_GPU_ALLOC_LIMIT/4096)return STATUS_CONFLICTING_ADDRESSES;
  b->Cpu=MmMapLockedPagesSpecifyCache(b->Mdl,KernelMode,MmNonCached,NULL,FALSE,NormalPagePriority|MdlMappingNoExecute);if(!b->Cpu)return STATUS_INSUFFICIENT_RESOURCES;
  for(SIZE_T j=0;j<bytes[i]/4096;j++)if((ULONGLONG)MmGetPhysicalAddress((PUCHAR)b->Cpu+j*4096).QuadPart!=(ULONGLONG)pfns[j]*4096)return STATUS_DATA_ERROR;
  RtlZeroMemory(b->Cpu,bytes[i]);if(i==2){UCHAR digest[32];RtlCopyMemory(b->Cpu,c->SqeInput,G433_SQE_FILE_BYTES);OpenShaAll(b->Cpu,G433_SQE_FILE_BYTES,digest);BOOLEAN match=RtlCompareMemory(digest,G433SqeSha,32)==32;RtlSecureZeroMemory(digest,32);if(!match)return STATUS_INVALID_IMAGE_HASH;RtlMoveMemory(b->Cpu,(PUCHAR)b->Cpu+4,G433_SQE_FILE_BYTES-4);RtlZeroMemory((PUCHAR)b->Cpu+G433_SQE_FILE_BYTES-4,bytes[i]-(G433_SQE_FILE_BYTES-4));}
  in[i]=(OSMI_INPUT){b->Mdl,va[i],bytes[i]};
 }
 s=OsmiBuildInactiveGpu(&c->Tables,in,4);if(s!=STATUS_SUCCESS)return s;return OgoCpCurrent(p);
}
/* This is a distinct first-use GPU authority, never a resumed CM3 stopped token.
 * GX was physically off with no CPU CP stores and SID0 fault/default. Exact
 * first-use ledger remains exclusive through actual OOB/GX-on and disabled SQE qualification. */
static NTSTATUS InitialOff(OGO_CONTEXT*p){G982_CP*c=p->Cp;NTSTATUS s=OgoCpCurrent(p);if(s!=STATUS_SUCCESS)return s;if(c->InitialOff||c->Writes||c->FirstUseConsumed||c->Run.Power.attempted)return STATUS_INVALID_DEVICE_STATE;
 s=G482CoreRead(&p->Io,GX_STATUS,&c->GxBefore);if(s!=STATUS_SUCCESS)return s;if(c->GxBefore==MAXULONG||!(c->GxBefore&1))return STATUS_DEVICE_BUSY;c->InitialOff=TRUE;c->Phase=1;return STATUS_SUCCESS;
}
static NTSTATUS QualifyColdDisabledGpu(OGO_CONTEXT*p){G982_CP*c=p->Cp;
 if(!c||c->Writes||c->Run.RunAttempted)return STATUS_INVALID_DEVICE_STATE;NTSTATUS s=FirstUseFrame(p);if(s!=STATUS_SUCCESS)return s;
 s=G482CoreRead(&p->Io,GX_STATUS,&c->GxAfter);if(s!=STATUS_SUCCESS)return s;if(c->GxAfter&3)return STATUS_DEVICE_POWER_FAILURE;
 /* Never enable an uninitialized SQE merely to request a warm halt. Two
  * actual zero reads qualify only this generation-bound exclusive first use. */
 s=GpuRead(p,0x808*4,&c->SqeBefore);if(s!=STATUS_SUCCESS)return s;if(c->SqeBefore!=0)return STATUS_DEVICE_BUSY;
 s=FirstUseFrame(p);if(s!=STATUS_SUCCESS)return s;s=GpuRead(p,0x808*4,&c->SqeAfter);if(s!=STATUS_SUCCESS)return s;if(c->SqeAfter!=0)return STATUS_DEVICE_BUSY;c->Phase=4;return STATUS_SUCCESS;
}
/* Actual owned same-phone SMEM603 DDR record, independently recovered by
 * DDRInfoDxe. Full input files are already hash-pinned by OgoLoadInputs.
 * Both snapshot prefixes must match before selecting source HBB16/type8. */
static NTSTATUS DdrFact(OGO_CONTEXT*p){
 static const UCHAR pin[32]={0xcd,0x9c,0x9f,0xd9,0x72,0x99,0x44,0x22,0x22,0x95,0x07,0x56,0x37,0x50,0x1d,0xe0,0xbc,0xd4,0xe3,0x79,0x56,0x42,0x98,0x27,0xfa,0x24,0xfc,0xdf,0x5e,0x83,0xd7,0x03};
 UCHAR digest[32];if(!p->Input[1]||!p->Input[2]||p->Inputs.global_smem_first.bytes!=720896||p->Inputs.global_smem_second.bytes!=720896||p->Inputs.global_smem_first.data!=p->Input[1]||p->Inputs.global_smem_second.data!=p->Input[2])return STATUS_INVALID_IMAGE_HASH;
 const UCHAR*a=(PUCHAR)p->Input[1]+0x48a8,*b=(PUCHAR)p->Input[2]+0x48a8;if(RtlCompareMemory(a,b,216)!=216||a[1]!=8)return STATUS_NOT_SUPPORTED;OpenShaAll(a,216,digest);BOOLEAN good=RtlCompareMemory(digest,pin,32)==32;RtlSecureZeroMemory(digest,32);if(!good)return STATUS_INVALID_IMAGE_HASH;p->CpDdrType=8;return STATUS_SUCCESS;
}
NTSTATUS OgoRunCpFence1(OGO_CONTEXT*p){
 if(!p||!p->CpInit||p->Cp||!p->Active||!p->GpuUser.Qualified||!p->GpuUser.Referenced||!p->Gmu)return STATUS_INVALID_DEVICE_STATE;
 NTSTATUS fact=DdrFact(p);if(fact!=STATUS_SUCCESS)return fact;
 p->Cp=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*p->Cp),OGO_TAG);if(!p->Cp)return STATUS_INSUFFICIENT_RESOURCES;RtlZeroMemory(p->Cp,sizeof(*p->Cp));G982_CP*c=p->Cp;c->Retain=TRUE;
 NTSTATUS s=OasEnterRunningScope(p->Active);if(s!=STATUS_SUCCESS)goto done;c->Scope=TRUE;
 s=InitialOff(p);if(s!=STATUS_SUCCESS)goto leave;s=Prepare(p);if(s!=STATUS_SUCCESS)goto leave;
 s=OgoActivateGpu0(p);if(s!=STATUS_SUCCESS)goto leave;c->Published=TRUE;c->Phase=2;c->Run.Prepared=TRUE;
 {g190_status ps=g440_gpu_acquire(&c->Run.Power,&p->Gmu->Core,&p->Gmu->Inputs.policy,p->Hold.Serial);if(ps!=G190_OK){s=ps==G190_TIMEOUT?STATUS_IO_TIMEOUT:STATUS_DEVICE_NOT_READY;goto leave;}}
 c->Phase=3;s=QualifyColdDisabledGpu(p);if(s!=STATUS_SUCCESS)goto leave;
#if OPEN_QTB_WITNESS
 {struct qtb_report report;RtlZeroMemory(&report,sizeof(report));
  /* Existing first-use qualification just observed SQE0 twice; immutable SQE
   * MDL/table and held OOB/power remain source-owned until terminal retention. */
  if(!p->Bank.Api.QtbOnce){s=STATUS_NOT_SUPPORTED;goto leave;}
  s=FirstUseFrame(p);if(s!=STATUS_SUCCESS)goto leave;
  NTSTATUS qs=p->Bank.Api.QtbOnce(p->Bank.Api.Interface.Context,&p->Bank.Native,&p->GpuUser,&p->Active->Scope,&c->Tables,c->Run.Buffer[2].Mdl,c->Run.Layout.Iova[2],&report);
  LogPrint("QTB terminal status%08x result%u raw%llx extracted%llx expected%llx cleanup%u uncertain%u; noSQEwrite noPackets retain1\n",qs,report.result,report.out,report.extracted,report.expected_mdl_pa,report.cleanup_restored,report.uncertain);
  s=qs==STATUS_SUCCESS?STATUS_DEVICE_HARDWARE_ERROR:qs;goto leave;
 }
#endif
 CpPoint(p,"Configure begin",STATUS_SUCCESS);s=G456ConfigureGpuStopped(&c->Run);CpPoint(p,"Configure end",s);if(s!=STATUS_SUCCESS)goto leave;
 {g433_memory memory[4];for(unsigned i=0;i<4;i++)memory[i]=(g433_memory){c->Run.Buffer[i].Cpu,c->Run.Layout.Iova[i],c->Run.Layout.Bytes[i]};g433_cp_ops ops={p,CpLease,CpRead,CpWrite,Publish,Acquire,Barrier,Now,Wait,Cancelled,CpFence};c->Run.RunAttempted=TRUE;
 CpPoint(p,"g433 begin",STATUS_SUCCESS);g433_status cs=g433_cp_run(&c->Run.Core,&ops,memory,500000);CpPoint(p,"g433 return",(NTSTATUS)cs);s=cs==G433_OK?STATUS_SUCCESS:cs==G433_TIMEOUT?STATUS_IO_TIMEOUT:STATUS_DEVICE_HARDWARE_ERROR;if(s==STATUS_SUCCESS&&(c->Run.Core.completed!=1||c->Run.Core.last_observed!=1||c->Run.Core.stage!=6||!c->FirstUseConsumed))s=STATUS_DEVICE_DATA_ERROR;
 }
 if(s==STATUS_SUCCESS)c->Phase=6;
leave:c->Status=s;c->Scope=FALSE;s=OasLeaveFirmwareScope(p->Active,s);
done:c->Status=s;c->Run.LastStatus=s;LogPrint("CP fence1 status%08x phase%u stage%u observed%u completed%u issued%u gxBefore%x gxAfter%x sqeBefore%x sqeAfter%x smmuW%u smmuR%u powerSt%u powerErr%u freqAck%u oob%u gmuPhase%u gmuErr%u; retain1 secureExit0 WDDM0\n",s,c->Phase,c->Run.Core.stage,c->Run.Core.last_observed,c->Run.Core.completed,c->Run.Core.issued,c->GxBefore,c->GxAfter,c->SqeBefore,c->SqeAfter,c->SmmuWrites,c->SmmuReads,c->Run.Power.stage,c->Run.Power.status,c->Run.Power.freq_acked,c->Run.Power.oob_may_be_held,p->Gmu->Core.phase,p->Gmu->Core.failure);return s;
}
