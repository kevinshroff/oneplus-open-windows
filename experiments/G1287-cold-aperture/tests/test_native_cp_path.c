/* Actual new provider/IRQ/native-translation/native-CP bodies; explicit host
 * WDM/firmware actors. No native ABI, power, DMA or hardware evidence. */
#include "cp_host.h"
#include "g456_tables.h"
#include <string.h>
static OGO_CONTEXT owner;static OSM_CONTEXT broker;static G321_RUNTIME gmu;static OAS_BOOTSTRAP active;static OSMA_TABLE_BINDING gmutables;static OSMA_NATIVE_IO native;
static ULONG smmu[0x40000/4],gpu[0x40000/4],gmureg[0x40000/4];static _Alignas(4096) uint32_t hfi[4096];
static uint64_t clock_us;static unsigned locked,connections,leasecalls,loseat,mmio_writes,failconnect;static int faultat,gxinitial,sqeafter,device_completes,foreign_commit,fail_store;static const char*sqefile;static unsigned notify,requests;static ULONG info;NTSTATUS G1046TestGpuWrite(OGO_CONTEXT*,ULONG,ULONG);
static unsigned hw_mode,hw_at,hw_seen,hw_pending,hw_bank,hw_off,hw_ahb,hw_reads,trace_begin,trace_end,unsupported_reads,trace_extra,trace_max;
ULONG DbgPrintEx(ULONG id,ULONG level,const char*fmt,...){assert(id==DPFLTR_IHVVIDEO_ID&&level==DPFLTR_INFO_LEVEL&&KeGetCurrentIrql()==0);if(strstr(fmt,"G1126 ")||strstr(fmt,"G1148 ")){if(strstr(fmt,"G1126 CP "))assert(owner.Cp&&owner.Cp->Run.RunAttempted&&owner.Cp->Run.Core.stage>=1&&owner.Cp->Run.Core.stage<=4);trace_extra++;if(trace_extra>trace_max)trace_max=trace_extra;assert(trace_extra<256);return 0;}if(strstr(fmt," begin "))trace_begin++;else{assert(strstr(fmt," end "));trace_end++;}assert(trace_begin+trace_end<400);return 0;}
static NTSTATUS hw_write(unsigned bank,unsigned off){
 if(!owner.Cp||!owner.Cp->Run.Hwinit.Attempted||owner.Cp->Run.Hwinit.Complete)return 0;
 hw_seen++;hw_pending=1;hw_bank=bank;hw_off=off;
 if(hw_at&&hw_seen!=hw_at)return 0;
 if(hw_mode==2)return STATUS_DEVICE_NOT_READY;
 if(hw_mode==5)(void)OfAckPolicy(&broker.Fault.Journal,2,0x402);
 if(hw_mode==6)hw_ahb=1;
 if(hw_mode==7)owner.Revoked=1;
 return 0;
}
static NTSTATUS hw_read(unsigned bank,unsigned off,PULONG v){
 if(!owner.Cp||!owner.Cp->Run.Hwinit.Attempted||owner.Cp->Run.Hwinit.Complete|| (bank==1&&(off==0x14340||off==0x24c4c)))return 0;
 hw_reads++;
 if(bank==0&&off==0x142c){if(getenv("G1095_EXPECT_OLD_READ")){unsupported_reads++;return STATUS_DEVICE_NOT_READY;}assert(getenv("G1064_EXPECT_ECHO"));*v=0x2f7fff;} /* predecessor-only extra read, never G1095 */
 if(hw_mode==3&&hw_reads==hw_at)return STATUS_DEVICE_NOT_READY;
 if(hw_mode==4&&hw_reads==hw_at)*v=UINT32_MAX;
 if(owner.Cp->Run.Hwinit.Stage==6&&hw_mode==8&&bank==0&&off==G456_RBBM_CLOCK_CNTL*4)*v=0x12345678;
 return 0;
}
static ULONG bv_fail_offset;static unsigned missing_bv;
static unsigned premature_rejects;static unsigned sqe_writes,sqe_reads,inject_contract,release_fail;static int sqe_change_after;static ULONG fsr_inject;static unsigned fsr_when,fsr_stores;
/* Architectural generated Format side effect, not CPU/DMA completion. */
void G1020ModelWrite32(uint32_t*p,uint32_t v){
 uintptr_t at=(uintptr_t)p,b=(uintptr_t)smmu;
 if(at>=b&&at<b+sizeof(smmu)){
  unsigned off=(unsigned)(at-b);assert(off!=0x20058); /* no FSR writes */
  *p=v;
  if(off==0x1800&&v==1){smmu[0x20058/4]=0x400u;if(fsr_when==1)smmu[0x20058/4]|=fsr_inject;if(fsr_when==4)smmu[0x20058/4]=0;}
  if(off==0x20000&&v==0xc00067&&fsr_when==2)smmu[0x20058/4]|=fsr_inject;
  if(off==0xc04&&v==0x300&&fsr_when==3)smmu[0x20058/4]|=fsr_inject;
 }else *p=v;
}
static struct{void*p;size_t n;uint64_t pa;}allocs[64];static unsigned nalloc;static uint64_t nextpa;
static void*tracked(size_t n,int align){void*p=NULL;if(align){assert(!posix_memalign(&p,4096,n));memset(p,0,n);}else p=calloc(1,n);assert(p);assert(nalloc<64);allocs[nalloc++]=(typeof(allocs[0])){p,n,nextpa};nextpa+=((n+4095)&~4095u)+0x1000;return p;}
ULONG KeGetCurrentIrql(void){return 0;}void*PsGetCurrentThread(void){return(void*)1;}
PVOID ExAllocatePool2(UINT64 f,SIZE_T n,ULONG tag){(void)f;(void)tag;return tracked(n,0);}void ExFreePoolWithTag(PVOID p,ULONG t){(void)p;(void)t;assert(!"production must retain all modeled objects until reset");}
PVOID MmAllocateContiguousMemorySpecifyCache(SIZE_T n,PHYSICAL_ADDRESS a,PHYSICAL_ADDRESS b,PHYSICAL_ADDRESS c,int d){assert(!a.QuadPart&&(uint64_t)b.QuadPart==((1ull<<36)-1)&&!c.QuadPart&&d==MmNonCached);return tracked(n,1);}
PHYSICAL_ADDRESS MmGetPhysicalAddress(PVOID p){for(unsigned i=0;i<nalloc;i++)if((uintptr_t)p>=(uintptr_t)allocs[i].p&&(uintptr_t)p<(uintptr_t)allocs[i].p+allocs[i].n)return(PHYSICAL_ADDRESS){allocs[i].pa+(uintptr_t)p-(uintptr_t)allocs[i].p};assert(0);return(PHYSICAL_ADDRESS){0};}
void MmFreeContiguousMemory(PVOID p){(void)p;assert(!"no production free after publication");}
PMDL MmAllocatePagesForMdlEx(PHYSICAL_ADDRESS a,PHYSICAL_ADDRESS b,PHYSICAL_ADDRESS c,SIZE_T n,int cache,ULONG flags){assert(!a.QuadPart&&(uint64_t)b.QuadPart==((1ull<<36)-1)&&!c.QuadPart&&cache==MmNonCached&&flags==MM_ALLOCATE_FULLY_REQUIRED);PMDL m=tracked(sizeof(*m)+n/4096*sizeof(PFN_NUMBER),0);m->ByteCount=n;m->MdlFlags=MDL_PAGES_LOCKED;return m;}
PVOID MmMapLockedPagesSpecifyCache(PMDL m,int mode,int cache,PVOID req,BOOLEAN bug,ULONG flags){assert(mode==KernelMode&&cache==MmNonCached&&!req&&!bug&&(flags&MdlMappingNoExecute));void*p=tracked(m->ByteCount,1);uint64_t pa=MmGetPhysicalAddress(p).QuadPart;for(unsigned i=0;i<m->ByteCount/4096;i++)MmGetMdlPfnArray(m)[i]=(pa/4096)+i;return p;}
void MmUnmapLockedPages(PVOID p,PMDL m){(void)p;(void)m;assert(0);}void MmFreePagesFromMdl(PMDL m){(void)m;assert(0);}void ExFreePool(PVOID p){(void)p;assert(0);}
void KeInitializeMutex(KMUTEX*m,ULONG n){(void)n;m->held=0;}NTSTATUS KeWaitForSingleObject(PVOID p,int a,int b,BOOLEAN c,LARGE_INTEGER*d){(void)a;(void)b;(void)c;(void)d;((KMUTEX*)p)->held=1;return 0;}void KeReleaseMutex(KMUTEX*p,BOOLEAN b){(void)b;p->held=0;}
ULONGLONG KeQueryInterruptTimePrecise(ULONGLONG*c){*c=0;return clock_us++*10;}NTSTATUS KeDelayExecutionThread(int m,BOOLEAN a,LARGE_INTEGER*t){(void)m;(void)a;clock_us+=(uint64_t)(-t->QuadPart)/10;return 0;}void KeStallExecutionProcessor(ULONG n){clock_us+=n;}
void ObReferenceObject(PVOID p){assert(p);}void ObDereferenceObject(PVOID p){assert(p);}
void LogPrint(const char*s,...){(void)s;}
NTSTATUS ZwCreateFile(HANDLE*h,ULONG a,OBJECT_ATTRIBUTES*b,IO_STATUS_BLOCK*c,void*d,ULONG e,ULONG f,ULONG g,ULONG i,void*j,ULONG k){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)i;(void)j;(void)k;*h=fopen(sqefile,"rb");return*h?0:STATUS_INVALID_IMAGE_HASH;}
NTSTATUS ZwQueryInformationFile(HANDLE h,IO_STATUS_BLOCK*i,void*out,ULONG n,ULONG cls){(void)i;(void)n;(void)cls;FILE*f=h;fseek(f,0,SEEK_END);((FILE_STANDARD_INFORMATION*)out)->Directory=0;((FILE_STANDARD_INFORMATION*)out)->EndOfFile.QuadPart=ftell(f);rewind(f);return 0;}
NTSTATUS ZwReadFile(HANDLE h,void*a,void*b,void*c,IO_STATUS_BLOCK*i,void*out,ULONG n,LARGE_INTEGER*o,void*x){(void)a;(void)b;(void)c;(void)o;(void)x;i->Information=fread(out,1,n,h);return 0;}NTSTATUS ZwClose(HANDLE h){fclose(h);return 0;}
void BrokerLock(OSM_CONTEXT*p){assert(p==&broker&&!locked);locked=1;}void BrokerUnlock(OSM_CONTEXT*p){assert(p==&broker&&locked);locked=0;}NTSTATUS IoAcquireRemoveLock(void*p,void*t){(void)p;assert(t);return 0;}void IoReleaseRemoveLock(void*p,void*t){(void)p;assert(t);}
NTSTATUS CghNativeRetainFailure(CGH_NATIVE*p,NTSTATUS s){(void)p;assert(s);return s;}
int LocalCurrent(void*x,uint64_t gen,uint64_t serial){OLB_NATIVE_IO*n=x;return n->P!=&broker||gen!=7||serial!=19||broker.NsRevoked||owner.Revoked||broker.Fault.Journal.Fatal;}
static int snapshot(void*x,OSH_SNAPSHOT*s){OLB_NATIVE_IO*n=x;return CaptureGlobals(n->P,s)!=0;}static int readcb(void*x,unsigned bank,uint32_t*v){(void)x;assert(bank==0||bank==2);*v=smmu[(0x20000+bank*0x1000)/4];return 0;}
OLB_IO LocalOps(OLB_NATIVE_IO*n){return(OLB_IO){n,LocalCurrent,snapshot,readcb};}NTSTATUS LocalStatus(enum olb_status s){return s==OLB_OK?0:s==OLB_BUSY?STATUS_DEVICE_BUSY:STATUS_DEVICE_CONFIGURATION_ERROR;}
NTSTATUS CaptureGlobals(OSM_CONTEXT*p,OSH_SNAPSHOT*s){assert(p==&broker);memset(s,0,sizeof(*s));s->Id0=smmu[0x20/4];s->Id1=smmu[0x24/4];s->Id2=smmu[0x28/4];s->Nscr0=smmu[0];s->Nsacr=smmu[0x10/4];for(unsigned i=0;i<24;i++){s->Smr[i]=smmu[(0x800+4*i)/4];s->S2cr[i]=smmu[(0xc00+4*i)/4];}if(foreign_commit&&broker.GpuUser.Programming)s->S2cr[5]^=1;return 0;}
static int FaultBinding(OSM_CONTEXT*p,OLB_NATIVE*b){return p==&broker&&b==&owner.Bank.Native&&p->BankClaims==1;}
static NTSTATUS FaultEnter(OSM_CONTEXT*p,void*t){(void)t;BrokerLock(p);return 0;}static void FaultLeave(OSM_CONTEXT*p,void*t){(void)t;BrokerUnlock(p);}static NTSTATUS FaultCurrentIort(void){return 0;}static void FaultRetainAndDisconnect(OSM_CONTEXT*p){p->NsRevoked=1;p->Fault.Retain=1;}
static BOOLEAN FaultIsr(PKINTERRUPT a,PVOID b){(void)a;(void)b;return 0;}void KeInitializeSpinLock(KSPIN_LOCK*p){*p=0;}void KeRaiseIrql(KIRQL i,KIRQL*p){(void)i;*p=0;}void KeAcquireSpinLockAtDpcLevel(KSPIN_LOCK*p){(void)p;}void KeReleaseSpinLockFromDpcLevel(KSPIN_LOCK*p){(void)p;}void KeLowerIrql(KIRQL i){(void)i;}void IoDisconnectInterrupt(PKINTERRUPT i){assert(i);}
NTSTATUS IoConnectInterrupt(PKINTERRUPT*out,void*isr,void*c,KSPIN_LOCK*l,ULONG v,KIRQL a,KIRQL b,int m,BOOLEAN shared,KAFFINITY affinity,BOOLEAN f){(void)isr;(void)l;(void)a;(void)b;(void)m;(void)f;OF_ISR_CONTEXT*ctx=c;const ULONG expected[]={705,711,709};assert(ctx->Index==connections&&v==expected[connections]&&!shared&&affinity);connections++;if(connections==failconnect)return STATUS_DEVICE_NOT_READY;*out=(void*)(uintptr_t)connections;return 0;}
PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS p,SIZE_T n,ULONG f){(void)f;assert(n==4096);if(p.QuadPart==0x03da0000)return smmu;if(p.QuadPart==0x03dc2000)return(PUCHAR)smmu+0x22000;if(p.QuadPart==0x03dc0000)return(PUCHAR)smmu+0x20000;assert(0);return 0;}void MmUnmapIoSpace(PVOID p,SIZE_T n){(void)p;(void)n;}
#include "fault_actual.inc"
#include "provider_actual.inc"
NTSTATUS OgoGmuCurrent(G321_RUNTIME*g){assert(g==&gmu);leasecalls++;if(loseat&&leasecalls>=loseat)owner.Revoked=broker.NsRevoked=1;if(faultat&&leasecalls>=(unsigned)faultat)broker.Fault.Journal.Fatal=1;return owner.Revoked||broker.NsRevoked||broker.Fault.Journal.Fatal?STATUS_DEVICE_NOT_READY:0;}
NTSTATUS OasEnterRunningScope(OAS_BOOTSTRAP*a){assert(a==&active&&!broker.NsToken&&gmu.Core.phase==G190_STARTUP_COMPLETE);a->OperationThread=PsGetCurrentThread();a->Scope.Token=broker.NsToken=1;a->Scope.ProviderGeneration=broker.NsGeneration=7;broker.NsThread=PsGetCurrentThread();broker.NsBank=&owner.Bank.Native;broker.NsTag=a;a->Scope.Grant.Count=1;a->Scope.Grant.List[0].PartialResourceList.Count=1;a->Scope.Grant.List[0].PartialResourceList.PartialDescriptors[0]=broker.NsGrant;return 0;}
NTSTATUS OasLeaveFirmwareScope(OAS_BOOTSTRAP*a,NTSTATUS s){assert(a==&active);a->OperationThread=NULL;broker.NsToken=0;return s;}
NTSTATUS G482CoreRead(G482_BINDING*b,ULONG off,PULONG v){assert(b==&owner.Io);if(off==0x14340)*v=gmureg[off/4];else if(off==0x24c4c)*v=hw_ahb;else *v=gmureg[off/4];return hw_read(1,off,v);}
NTSTATUS G482CoreWrite(G482_BINDING*b,ULONG off,ULONG v){assert(b==&owner.Io);NTSTATUS st=hw_write(1,off);if(st)return st;gmureg[off/4]=v;return 0;}
NTSTATUS G482GpuRead(G482_BINDING*b,ULONG off,PULONG v){assert(b==&owner.Io&&!(off&3));if(off==0x808*4){sqe_reads++;if(sqe_change_after&&sqe_reads>=(unsigned)sqe_change_after)gpu[off/4]=1;}*v=off==0x808*4&&sqeafter?UINT32_MAX:gpu[off/4];return hw_read(0,off,v);}
NTSTATUS G482GpuWrite(G482_BINDING*b,ULONG off,ULONG v){assert(b==&owner.Io&&!(off&3));mmio_writes++;if(off==bv_fail_offset&&bv_fail_offset)return STATUS_DEVICE_NOT_READY;NTSTATUS hs=hw_write(0,off);if(hs)return hs;
 if(off==0x808*4){sqe_writes++;
  if(v==1&&((ULONGLONG)gpu[0xa98]|((ULONGLONG)gpu[0xa99]<<32))!=owner.Cp->Run.Layout.Iova[1]+8){missing_bv++;return STATUS_DEVICE_DATA_ERROR;}
  if(v==1){assert(owner.Cp->Run.Layout.Bytes[1]==4096&&((volatile ULONG*)owner.Cp->Run.Buffer[1].Cpu)[2]==0);}

  if(v==3&&gpu[0x808]==0&&gpu[0x830]==0&&gpu[0x831]==0){/* Explicit device-fetch actor for the actual G1043 observation. */
   smmu[0x20058/4]=0x402;smmu[0x20060/4]=smmu[0x20064/4]=0;smmu[0x20068/4]=0x001f0041;
   ULONG ack=OfAckPolicy(&broker.Fault.Journal,2,smmu[0x20058/4]);smmu[0x20058/4]&=~ack;
  }
  if(v==1){assert(owner.Cp->FirstUseConsumed&&owner.Cp->Run.MastersMayRun);assert(gpu[0x830]==owner.Cp->Run.Layout.Iova[2]&&gpu[0x831]==0&&gpu[0x800]==owner.Cp->Run.Layout.Iova[0]&&gpu[0x801]==0&&gpu[0x802]==0x20c);if(release_fail)return STATUS_DEVICE_NOT_READY;}
 }
 if(fail_store)return STATUS_DEVICE_NOT_READY;gpu[off/4]=v;
 if(off==0x807*4&&v==17&&device_completes){/* MODELED DEVICE DMA, only after real actual driver WPTR. */assert(owner.Cp->Published&&broker.GpuUser.Active&&connections==3);assert(owner.Cp->Run.Buffer[1].Cpu);((volatile ULONG*)owner.Cp->Run.Buffer[1].Cpu)[1]=1;}return 0;}
static int lease(void*x,uint64_t gen){(void)x;return gen!=7||OgoGmuCurrent(&gmu)!=0;}static int stop(void*x,uint64_t s,uint64_t g){(void)x;return s!=19||g!=7;}
static int rd(void*x,uint32_t off,uint32_t*v){(void)x;switch(off){case G190_CM3_RESET:*v=0;break;case G190_HFI_STATUS:*v=1;break;case G190_AO_STATUS:*v=0;break;case G190_G2H_INFO:*v=info;break;case 0x14340:*v=gmureg[off/4];break;default:assert(0);}return 0;}
static int wr(void*x,uint32_t off,uint32_t v){(void)x;if(off==G190_G2H_CLEAR){assert(v==0x80000000u);info&=~v;return 0;}assert(off==G190_H2G_SET);if(v==0x40000000u){requests++;info|=0x80000000u;gmureg[0x14340/4]=0;
 if(!getenv("G1046_EXPECT_LEGACY")){for(unsigned n=1;n<=3;n++){unsigned before=mmio_writes;assert(G1046TestGpuWrite(&owner,0x808*4,n)!=0&&!owner.Cp->FirstUseConsumed&&mmio_writes==before);premature_rejects++;}}

 if(inject_contract==1)owner.Cp->Run.Generation++;
 if(inject_contract==2)owner.Cp->Run.StopSerial++;
 if(inject_contract==3)owner.Cp->FirstUseConsumed=1;
 if(inject_contract==4)owner.Cp->Writes=1;
 if(inject_contract==5)owner.Cp->InitialOff=0;
 if(inject_contract==6)owner.Revoked=1;
 return 0;}assert(v==1);notify++;uint32_t*cmd=hfi+6,*msg=hfi+18,*data=hfi+1024,*out=hfi+2048;uint32_t hdr=data[cmd[10]];assert((hdr&255)==30);cmd[10]=cmd[11];unsigned w=msg[11];out[w]=(1u<<16)|(3u<<8)|30;out[w+1]=hdr;out[w+2]=0;out[w+3]=0xfafafafa;msg[11]=(w+4)&1023;return 0;}
static int bar(void*x,g190_barrier b){(void)x;(void)b;if(hw_mode==9&&hw_seen==hw_at&&hw_seen&&owner.Cp&&owner.Cp->Run.Hwinit.Attempted&&!owner.Cp->Run.Hwinit.Complete)return -1;return 0;}static int now(void*x,uint64_t*v){(void)x;*v=clock_us++;return 0;}static int waitfn(void*x,uint32_t u){(void)x;clock_us+=u;return 0;}static int cancel(void*x){(void)x;return owner.Revoked||broker.Fault.Journal.Fatal;}static int hash(void*a,const uint8_t*b,size_t c,const uint8_t*d){(void)a;(void)b;(void)c;(void)d;return 0;}static int fw(void*a,uint32_t b,uint32_t c,uint32_t d){(void)a;(void)b;(void)c;(void)d;return 0;}static int fr(void*a,uint32_t b,uint32_t c,uint32_t*d){(void)a;(void)b;(void)c;*d=0;return 0;}static int cfg(void*a){(void)a;return 0;}
static unsigned char*readfile(const char*path,size_t*n){FILE*f=fopen(path,"rb");assert(f);fseek(f,0,SEEK_END);*n=ftell(f);rewind(f);void*p=malloc(*n);assert(p&&fread(p,1,*n,f)==*n);fclose(f);return p;}
static void init(const char*smem){memset(&owner,0,sizeof(owner));memset(&broker,0,sizeof(broker));memset(&gmu,0,sizeof(gmu));memset(&active,0,sizeof(active));memset(&gmutables,0,sizeof(gmutables));memset(smmu,0,sizeof(smmu));memset(gpu,0,sizeof(gpu));memset(gmureg,0,sizeof(gmureg));memset(hfi,0,sizeof(hfi));nextpa=0x200000;nalloc=locked=connections=leasecalls=loseat=mmio_writes=failconnect=notify=requests=0;faultat=gxinitial=sqeafter=foreign_commit=fail_store=0;device_completes=1;bv_fail_offset=0;missing_bv=0;info=0;clock_us=100;hw_mode=hw_at=hw_seen=hw_pending=hw_bank=hw_off=hw_ahb=hw_reads=trace_begin=trace_end=unsupported_reads=trace_extra=0;sqe_writes=sqe_reads=inject_contract=release_fail=premature_rejects=0;sqe_change_after=0;fsr_inject=fsr_when=fsr_stores=0;
 broker.Fdo=(void*)2;broker.Generation=7;broker.BankClaims=1;broker.Map[0]=smmu;owner.CpInit=1;owner.Gmu=&gmu;owner.Active=&active;owner.OperationThread=PsGetCurrentThread();owner.Hold=(CGH_NATIVE){19,7,0,&owner.Life};owner.Bank.Native=(OLB_NATIVE){broker.Fdo,&owner.Hold,1,7,19,1,0};broker.NsGrant.Type=CmResourceTypeMemory;broker.NsGrant.u.Memory.Start.QuadPart=0x03da0000;broker.NsGrant.u.Memory.Length=0x40000;owner.Bank.Api.Interface.Context=&broker;owner.Bank.Api.ReserveGpuUser=GpuUserReserveApi;owner.Bank.Api.CheckGpuUser=GpuUserCheckApi;owner.Bank.Api.ReleaseGpuUserUnpublished=GpuUserReleaseApi;owner.Bank.Api.PinGpuProgramming=GpuUserPinApi;owner.Bank.Api.CommitGpuProgramming=GpuUserCommitApi;
 smmu[0x20/4]=0x4c017e18;smmu[0x24/4]=0x40000016;smmu[0x28/4]=0x5511;smmu[0]=0x002f0406;smmu[0x10/4]=0x1c;for(unsigned i=0;i<24;i++)smmu[(0xc00+4*i)/4]=0x20000;
 OLB_NATIVE_IO ioctx={&broker,&owner.Hold};OLB_IO io=LocalOps(&ioctx);uint64_t id;assert(OlbReserve(&broker.Banks,&io,7,19,&id)==OLB_OK&&id==1&&OlbQualify(&broker.Banks,&io,id)==OLB_OK);assert(GpuUserReserveApi(&broker,&owner.Bank.Native,&owner.GpuUser)==0);broker.Fault.GrantsValid=1;const ULONG irq[]={705,711,709};for(unsigned i=0;i<3;i++)broker.Fault.Grant[i]=(OF_IRQ_GRANT){irq[i],3,255};void*fault;assert(FaultConnectApi(&broker,&owner.Bank.Native,&fault)==0&&connections==3&&broker.Fault.KnownMask==7);
 /* Prior real GMU-success boundary modeled after reserve/IRQ ownership. */
 owner.Hold.BootCommitted=1;owner.Bank.Native.ProgramPinned=1;broker.Banks.Claim[0].State=OLB_PROGRAM_PINNED;smmu[0]=0x00ef0406;smmu[0x800/4]=0x80000005;smmu[0xc00/4]=0x302;CaptureGlobals(&broker,&gmutables.Session.After);native=(OSMA_NATIVE_IO){smmu,&gmutables};broker.RunNative=&native;active.Native=native;active.Tables=&gmutables;gmureg[0x14340/4]=3;gmureg[0x24c38/4]=0x77;smmu[0x22000/4]=0xc00067;smmu[0x22010/4]=0x38071;smmu[0x22030/4]=0x803519;gpu[G456_RB_CMP_DBG_ECO_CNTL]=0x200;
 gmu.Generation=7;gmu.Owner.Cookie=&owner;gmu.Io=&owner.Io;gmu.CoreStatus=G190_OK;gmu.Inputs.soc_id=519;gmu.Inputs.revision=0x20000;gmu.Inputs.source_sku=2;gmu.Core.shared=hfi;gmu.Core.iova=0x60006000;gmu.Core.epoch=1;gmu.Core.generation=7;gmu.Core.phase=G190_STARTUP_COMPLETE;gmu.Core.stage=11;gmu.Core.startup_acked=15;gmu.Core.reset_released=1;gmu.Core.limits=(g190_limits){65536,10,5000000,500000,500000,3000000};gmu.Core.ops=(g190_ops){NULL,lease,stop,rd,wr,bar,now,waitfn,cancel,hash,fw,fr,cfg};gmu.Inputs.policy.gpu_count=gmu.Inputs.policy.bandwidth_count=10;gmu.Inputs.policy.gpu[1].hz=124800000;gmu.Inputs.policy.gpu[1].vote=3408385;gmu.Inputs.policy.ddr_count=3;gmu.Inputs.policy.ddr_data[1][0]=gmu.Inputs.policy.ddr_data[1][1]=0x600007f2;gmu.Inputs.policy.ddr_data[1][2]=0x60000008;hfi[1]=168;hfi[2]=6;hfi[3]=12;hfi[4]=hfi[5]=3;for(unsigned q=0;q<3;q++){uint32_t*h=hfi+6+12*q;h[0]=1;h[1]=gmu.Core.iova+(q+1)*4096;h[2]=0xa00|q;h[3]=1024;}
 size_t n;owner.Input[1]=readfile(smem,&n);owner.Input[2]=malloc(n);assert(owner.Input[2]);memcpy(owner.Input[2],owner.Input[1],n);owner.Inputs.global_smem_first=(g196_bytes){owner.Input[1],n};owner.Inputs.global_smem_second=(g196_bytes){owner.Input[2],n};}
static void reset_model(void){/* Explicit modeled full reset, not productioncleanup. */for(unsigned i=0;i<nalloc;i++)free(allocs[i].p);free(owner.Input[1]);free(owner.Input[2]);}
int main(int argc,char**argv){assert(argc==3);sqefile=argv[1];unsigned cases=0;
 if(getenv("G1148_EXPECT_OLD_BV")){init(argv[2]);assert(OgoRunCpFence1(&owner)!=0&&missing_bv==1&&owner.Cp->FirstUseConsumed&&owner.Cp->Run.Core.issued==0&&owner.Cp->Retain);reset_model();puts("PASS exact G1126 core omits required BV pointer before actualSQE1; device model refuses, no900E attribution");return 0;}
 if(getenv("G1095_EXPECT_OLD_READ")){init(argv[2]);assert(OgoRunCpFence1(&owner)!=0&&unsupported_reads==1&&owner.Cp->Run.Hwinit.Writes==7&&!owner.Cp->FirstUseConsumed);reset_model();puts("PASS exact G1064 predecessor requires forbidden post-write142c read; no crash-cause inference");return 0;}
 if(getenv("G1064_EXPECT_ECHO")){init(argv[2]);assert(OgoRunCpFence1(&owner)!=0&&owner.Cp->Phase==4&&owner.Cp->Run.Hwinit.Stage==2&&owner.Cp->Run.Hwinit.Writes==7&&!owner.Cp->FirstUseConsumed);G456_REPORT*t=&owner.Cp->Run.Hwinit;assert(t->Access[t->Count-1].ByteOffset==0x142c&&t->Access[t->Count-1].Value==0x2f7fff);reset_model();puts("PASS exact predecessor G456 actualFFFFFFFF/read002f7fff false-echo refusal");return 0;}
 if(getenv("G1046_EXPECT_LEGACY")){init(argv[2]);assert(OgoRunCpFence1(&owner)!=0&&broker.Fault.Journal.Fatal==1&&broker.Fault.Journal.Events==1&&broker.Fault.Journal.LastStatus[2]==0x402&&broker.Fault.Journal.AckWrites==1&&smmu[0x20058/4]==0x400&&owner.Cp->Writes==1&&!owner.Cp->FirstUseConsumed);reset_model();puts("PASS actual predecessor cold0→3 triggers modeled NULL instruction TF/journalFatal/retained failure");return 0;}
 init(argv[2]);assert(OgoRunCpFence1(&owner)==0);assert(owner.Cp->Phase==6&&owner.Cp->Run.Core.completed==1&&owner.Cp->Run.Core.last_observed==1&&owner.Cp->FirstUseConsumed&&owner.Cp->Run.Power.held&&connections==3&&requests==1&&notify==1&&owner.CpDdrType==8&&owner.Cp->Tables.ActivationQualified&&owner.Cp->Run.Buffer[1].MapAttempted&&smmu[0x22000/4]==0xc00067&&smmu[0x22010/4]==0x38071&&smmu[0x22030/4]==0x803519&&smmu[0x800/4]==0x80000005&&smmu[0xc00/4]==0x302);assert(sqe_writes==1&&gpu[0x808]==1&&!broker.Fault.Journal.Fatal&&premature_rejects==3);unsigned baseline=leasecalls;unsigned hw_max=hw_seen;assert(hw_max==140&&hw_reads==23&&owner.Cp->Run.Hwinit.Reads==23&&trace_begin==163&&trace_end==163&&trace_extra>=180&&trace_extra<256);reset_model();cases++;
 init(argv[2]);gmureg[0x14340/4]=UINT32_MAX;assert(OgoRunCpFence1(&owner)!=0&&!owner.Cp->SmmuWrites&&!mmio_writes);reset_model();cases++;
 init(argv[2]);gmureg[0x14340/4]=0;assert(OgoRunCpFence1(&owner)!=0&&!owner.Cp->SmmuWrites&&!mmio_writes);reset_model();cases++;
 init(argv[2]);foreign_commit=1;assert(OgoRunCpFence1(&owner)!=0&&!owner.Cp->Published&&owner.Cp->Retain&&owner.Cp->Run.Buffer[0].MapAttempted&&!owner.Cp->Run.Buffer[0].Mapped&&owner.Cp->Tables.State==OSMI_POISONED);reset_model();cases++;
 init(argv[2]);sqeafter=1;assert(OgoRunCpFence1(&owner)!=0&&!owner.Cp->FirstUseConsumed&&owner.Cp->Retain);reset_model();cases++;
 init(argv[2]);device_completes=0;assert(OgoRunCpFence1(&owner)!=0&&owner.Cp->FirstUseConsumed&&owner.Cp->Run.Core.completed==0&&owner.Cp->Retain);reset_model();cases++;
 for(unsigned n=1;n<baseline;n+=baseline/8){init(argv[2]);loseat=n;assert(OgoRunCpFence1(&owner)!=0&&owner.Cp->Retain);reset_model();cases++;}
 init(argv[2]);faultat=baseline/2;assert(OgoRunCpFence1(&owner)!=0&&owner.Cp->Retain);reset_model();cases++;
 /* All architectural fault classes and every non-Format unknown bit refuse
  * after the actual CBA2R-generated Format transition. No publish/power. */
 for(unsigned bit=0;bit<32;bit++){if(bit==10)continue;init(argv[2]);fsr_when=1;fsr_inject=1u<<bit;
  assert(OgoRunCpFence1(&owner)!=0&&!owner.Cp->Published&&owner.Cp->SmmuWrites==13&&!requests&&owner.Cp->Retain);reset_model();cases++;}
 init(argv[2]);fsr_when=4;assert(OgoRunCpFence1(&owner)!=0&&!owner.Cp->Published&&owner.Cp->SmmuWrites==13&&!requests);reset_model();cases++;
 for(unsigned phase=2;phase<=3;phase++){init(argv[2]);fsr_when=phase;fsr_inject=2;
  assert(OgoRunCpFence1(&owner)!=0&&!owner.Cp->Published&&!requests&&owner.Cp->Retain);reset_model();cases++;}

 for(unsigned v=1;v<=3;v++){init(argv[2]);gpu[0x808]=v;assert(OgoRunCpFence1(&owner)!=0&&!owner.Cp->Writes&&!owner.Cp->FirstUseConsumed);reset_model();cases++;}
 for(unsigned n=2;n<=3;n++){init(argv[2]);sqe_change_after=n;assert(OgoRunCpFence1(&owner)!=0&&!owner.Cp->Writes&&!owner.Cp->FirstUseConsumed);reset_model();cases++;}
 for(unsigned n=1;n<=6;n++){init(argv[2]);inject_contract=n;assert(OgoRunCpFence1(&owner)!=0&&!mmio_writes);reset_model();cases++;}
 init(argv[2]);release_fail=1;assert(OgoRunCpFence1(&owner)!=0&&owner.Cp->FirstUseConsumed&&owner.Cp->Retain&&owner.Cp->Run.Core.issued==0);reset_model();cases++;

 /* WRITE contract: no post-store diagnostic reads, all140 G1224 writes remain (including CP_AHB_CNTL=1). */
 for(unsigned mode=2;mode<=7;mode++){if(mode==3||mode==4)continue;for(unsigned n=1;n<=hw_max;n++){init(argv[2]);hw_mode=mode;hw_at=n;assert(OgoRunCpFence1(&owner)!=0&&!owner.Cp->FirstUseConsumed&&owner.Cp->Retain);assert(trace_begin==trace_end);reset_model();cases++;}}
 for(unsigned mode=3;mode<=4;mode++)for(unsigned n=1;n<=23;n++){init(argv[2]);hw_mode=mode;hw_at=n;assert(OgoRunCpFence1(&owner)!=0&&!owner.Cp->FirstUseConsumed&&owner.Cp->Retain);assert(trace_begin==trace_end);reset_model();cases++;}
 init(argv[2]);hw_mode=8;assert(OgoRunCpFence1(&owner)==0&&owner.Cp->Run.Hwinit.Complete&&hw_reads==23);reset_model();cases++;
 init(argv[2]);gpu[G456_RBBM_CLOCK_CNTL]=0x8aa8aa82;assert(OgoRunCpFence1(&owner)==0&&owner.Cp->Run.Hwinit.HwcgSkipped&&hw_seen==85&&hw_reads==23&&trace_begin+trace_end==216);reset_model();cases++;
 init(argv[2]);gpu[G456_RB_CMP_DBG_ECO_CNTL]=UINT32_MAX;assert(OgoRunCpFence1(&owner)!=0&&!owner.Cp->FirstUseConsumed);reset_model();cases++;
 for(unsigned n=1;n<=hw_max;n++){init(argv[2]);hw_mode=9;hw_at=n;assert(OgoRunCpFence1(&owner)!=0&&!owner.Cp->FirstUseConsumed&&owner.Cp->Retain&&trace_begin==trace_end);reset_model();cases++;}
 for(unsigned n=0;n<2;n++){init(argv[2]);bv_fail_offset=(0xa98+n)*4;assert(OgoRunCpFence1(&owner)!=0&&!owner.Cp->FirstUseConsumed&&owner.Cp->Run.Core.issued==0&&owner.Cp->Retain);reset_model();cases++;}
 printf("PASS %u actual native-glue/provider/IRQ3/table/G440/G456/CP actor paths; baselineleases%u; hostWDM/firmware/DMAmodel only; maxAdditionalTrace%u\n",cases,baseline,trace_max);return 0;}
