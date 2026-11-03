/* CPU MMIO/IRQL shim; generated actual ISR slice supplies production logic. */
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
static int32_t InterlockedCompareExchange(volatile int32_t*p,int32_t v,int32_t c){__atomic_compare_exchange_n(p,&c,v,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);return c;}
#include "fault_policy.h"
typedef uint32_t ULONG,*PULONG;typedef unsigned char* PUCHAR;typedef void*PVOID;typedef void*PKINTERRUPT;typedef int BOOLEAN;typedef void VOID;
#define FALSE 0
#define TRUE 1
#define UNREFERENCED_PARAMETER(x) ((void)(x))
#define RtlZeroMemory(p,n) memset(p,0,n)
#define DPFLTR_IHVVIDEO_ID 99
#define DPFLTR_ERROR_LEVEL 0
struct OF_OWNER;typedef struct OF_OWNER OF_OWNER;
typedef struct{OF_OWNER*Owner;ULONG Index;} OF_ISR_CONTEXT;
struct OF_OWNER {PVOID Map[3],Bank;uint64_t Generation;volatile int32_t Armed;unsigned KnownMask,UncertainMask;OF_JOURNAL Journal;
#if OGO_GPU_FIRST_FAULT_TUPLE
 PVOID TupleOwner;
#endif
};
typedef struct {uint64_t Generation;int Started,D0Ref,Removing;struct{int Qualified,Active,Retained;uint64_t Generation;}GpuUser;PVOID GpuUserGmu;uint64_t NsToken,NsGeneration;PVOID NsBank,NsFault;}OSM_CONTEXT;
typedef struct{char Kind;unsigned Region,Offset;uint32_t Value;} EVENT;
static uint32_t maps[3][1024];static EVENT trace[64];static unsigned count,logs;static OF_OWNER f;static OSM_CONTEXT p;static int bank;
static void event(char k,unsigned r,unsigned o,uint32_t v){assert(count<64);trace[count++]=(EVENT){k,r,o,v};}
static void where(PULONG a,unsigned*r,unsigned*o){for(unsigned i=0;i<3;i++)if((uintptr_t)a>=(uintptr_t)maps[i]&&(uintptr_t)a<(uintptr_t)(maps[i]+1024)){*r=i;*o=(unsigned)((uintptr_t)a-(uintptr_t)maps[i]);return;}assert(0);}
static uint32_t ReadFake(PULONG a){unsigned r=0,o=0;where(a,&r,&o);event('R',r,o,*a);return *a;}
static void WriteFake(PULONG a,uint32_t v){unsigned r=0,o=0;where(a,&r,&o);event('W',r,o,v);assert(f.Journal.Fatal);*a&=~v;}
#define READ_REGISTER_ULONG ReadFake
#define WRITE_REGISTER_ULONG WriteFake
#define KeMemoryBarrier() event('B',0,0,0)
#if OGO_GPU_FIRST_FAULT_TUPLE
static void DbgPrintEx(unsigned component,unsigned level,const char*fmt,...){(void)fmt;assert(component==DPFLTR_IHVVIDEO_ID&&level==0);assert(f.Journal.First.State==2);logs++;event('L',0,0,0);}
#endif
#include "actual_isr.inc"
static void clear_trace(void){count=0;memset(trace,0,sizeof(trace));}
static void fresh(void){memset(&f,0,sizeof(f));memset(&p,0,sizeof(p));memset(maps,0,sizeof(maps));logs=0;clear_trace();for(unsigned i=0;i<3;i++)f.Map[i]=maps[i];f.Bank=&bank;f.Generation=p.Generation=42;p.Started=p.D0Ref=1;p.GpuUser.Qualified=p.GpuUser.Active=1;p.GpuUser.Generation=42;p.GpuUserGmu=&bank;p.NsToken=1;p.NsGeneration=42;p.NsBank=&bank;p.NsFault=&f;
#if OGO_GPU_FIRST_FAULT_TUPLE
 FaultTuplePrepare(&f,&p);
#endif
 f.Armed=1;for(unsigned i=0x60;i<=0x6c;i+=4)maps[2][i/4]=0x1000+i;for(unsigned i=0x50;i<=0x58;i+=4)maps[0][i/4]=0x2000+i;
}
static int call(unsigned index,uint32_t value){OF_ISR_CONTEXT c={&f,index};maps[index][(index?0x58:0x48)/4]=value;return FaultIsr(NULL,&c);}
int main(void){unsigned cases=0;
 fresh();f.Armed=0;assert(!call(2,0x402)&&!count&&!f.Journal.Events);cases++;
 for(unsigned index=0;index<3;index++)for(unsigned bit=0;bit<32;bit++){
  fresh();uint32_t status=(1u<<bit)|(index?0x400:0),ack=index?(status&0x800001fe):status;
  call(index,status);assert(f.Journal.LastStatus[index]==status);
  assert(f.Journal.Fatal==(index&&status==0x400?0:1));
  unsigned writes=0;for(unsigned i=0;i<count;i++)if(trace[i].Kind=='W'){assert(trace[i].Value==ack);writes++;}
  assert(writes==(ack?1u:0u));cases++;
 }
 for(unsigned index=0;index<3;index++){fresh();assert(!call(index,0)&&count==1&&!f.Journal.Fatal&&!logs);cases++;}
 fresh();assert(!call(2,0x400)&&count==1&&!f.Journal.Fatal&&!logs);cases++;
 fresh();assert(call(2,UINT32_MAX)&&f.Journal.Fatal&&f.Journal.InvalidReads==1&&!f.Journal.AckWrites);
#if OGO_GPU_FIRST_FAULT_TUPLE
 /* Invalid status adds only one log, with no further MMIO/ACK. */
 assert(count==2&&trace[1].Kind=='L'&&f.Journal.First.Refused==4&&!f.Journal.First.ReadMask);
#endif

#if !OGO_GPU_FIRST_FAULT_TUPLE
 assert(count==1);_Static_assert(sizeof(OF_JOURNAL)==28,"default journal ABI unchanged");
#endif
 cases++;
#if OGO_GPU_FIRST_FAULT_TUPLE
 fresh();assert(call(2,0x402));assert(count==11&&logs==1&&f.Journal.First.ReadMask==0x7f&&f.Journal.First.Refused==0);
 const unsigned regions[]={2,2,2,2,2,0,0,0};const unsigned offsets[]={0x58,0x60,0x64,0x68,0x6c,0x50,0x54,0x58};
 for(unsigned i=0;i<8;i++)assert(trace[i].Kind=='R'&&trace[i].Region==regions[i]&&trace[i].Offset==offsets[i]);
 assert(trace[8].Kind=='L'&&trace[9].Kind=='W'&&trace[10].Kind=='B');
 assert(f.Journal.First.FarLo==0x1060&&f.Journal.First.FarHi==0x1064&&f.Journal.First.Fsynr0==0x1068&&f.Journal.First.Fsynr1==0x106c);cases++;
 OF_FIRST_FAULT saved=f.Journal.First;clear_trace();call(2,0x404);assert(logs==1&&count==3&&trace[0].Kind=='R'&&trace[1].Kind=='W'&&!memcmp(&saved,&f.Journal.First,sizeof(saved)));cases++;
 clear_trace();call(0,8);assert(logs==1&&count==3&&!memcmp(&saved,&f.Journal.First,sizeof(saved)));cases++;
 /* Claim already in progress cannot be stolen. */
 fresh();f.Journal.First.State=1;call(2,0x402);assert(count==3&&!logs&&f.Journal.First.State==1);cases++;
 for(unsigned index=0;index<2;index++){fresh();call(index,2);assert(f.Journal.First.ReadMask==0x70&&logs==1);for(unsigned i=1;i<4;i++)assert(trace[i].Region==0);cases++;}
 /* All-current predicates are deliberately falsified individually. */
 for(unsigned fail=0;fail<13;fail++){
  fresh();switch(fail){case 0:p.Generation++;break;case 1:p.Started=0;break;case 2:p.D0Ref=0;break;case 3:p.Removing=1;break;case 4:p.GpuUser.Qualified=0;break;case 5:p.GpuUser.Active=0;break;case 6:p.GpuUser.Retained=1;break;case 7:p.GpuUserGmu=NULL;break;case 8:p.GpuUser.Generation++;break;case 9:p.NsToken=0;break;case 10:p.NsGeneration++;break;case 11:p.NsBank=NULL;break;case 12:p.NsFault=NULL;break;}
  call(2,0x402);assert(logs==1&&f.Journal.First.Refused&&f.Journal.Fatal&&f.Journal.AckWrites==1);
  assert(!(f.Journal.First.ReadMask&15));cases++;
 }
 fresh();maps[2][0x68/4]=UINT32_MAX;call(2,0x402);assert(f.Journal.First.ReadMask==0x7f&&f.Journal.First.AllOnesMask==4&&f.Journal.AckWrites==1);cases++;
 fresh();call(2,0x402);saved=f.Journal.First;FaultTuplePrepare(&f,&p);assert(!memcmp(&saved,&f.Journal.First,sizeof(saved)));cases++;
 p.Generation++;FaultTuplePrepare(&f,&p);assert(!memcmp(&saved,&f.Journal.First,sizeof(saved)));cases++;
 f.Armed=0;f.KnownMask=1;FaultTuplePrepare(&f,&p);assert(!memcmp(&saved,&f.Journal.First,sizeof(saved)));cases++;
 f.KnownMask=0;f.UncertainMask=1;FaultTuplePrepare(&f,&p);assert(!memcmp(&saved,&f.Journal.First,sizeof(saved)));cases++;
 f.UncertainMask=0;FaultTuplePrepare(&f,&p);assert(f.Journal.First.Generation==43&&f.Journal.First.State==0&&!f.Journal.First.ReadMask&&f.Journal.Fatal);cases++;
#endif
 printf("PASS %u source-bound ISR/ACK/guard/reset cases option%d\n",cases,OGO_GPU_FIRST_FAULT_TUPLE);return 0;
}
