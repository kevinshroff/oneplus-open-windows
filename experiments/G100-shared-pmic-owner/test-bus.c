/* Actual gate + actual G98/G99 algorithms. One aliased observer MMIO model. */
#include "g100_bus.c"
#include "g98_observer.h"
#include "g99_core.h"
typedef struct{ULONG Held;unsigned Reads,Writes,Cancel,FailCompletion;uint64_t Clock;}Ctx;
static const uint32_t Apids[7]={0,559,560,583,117,145,695};
static const uint32_t Maps[7]={0x1000100,0x800,0x1001300,0x1018d00,0x1010100,0x101c100,0x1c400};
static const uint32_t Owner[7]={4,0,0,0,4,4,0};
static const uint8_t Ids[7][8]={{33,0,1,2,81,74,1,0},{0,2,0,1,1,8,0,0},{0,2,0,1,1,9,0,0},{0,3,0,1,16,19,0,0},{32,0,0,2,81,73,1,0},{0,4,1,1,4,172,0,0},{0,4,1,1,4,171,0,0}};
static uint32_t LastCommand,Data[2];static unsigned CompletionTarget;
static int Present(void*x){return !((Ctx*)x)->Cancel;}
static int Acquire(void*x){Ctx*c=x;return G100BusAcquire(&c->Held,Present,x);}
static void Release(void*x,int uncertain){Ctx*c=x;G100BusRelease(&c->Held,uncertain);}
static int Read(void*x,uint32_t at,uint32_t*out){Ctx*c=x;c->Reads++;
 if(at==0xc400000){*out=0x70000001;return 1;}if(at==0xc400004){*out=0x80040300;return 1;}
 for(unsigned i=0;i<7;i++){
  if(at==0xc402000+Apids[i]*4){*out=Maps[i];return 1;}
  if(at==0xc42d000+Apids[i]*4){*out=Owner[i];return 1;}
  uint32_t base=0xc440000+Apids[i]*32;
  if(at==base||at==base+8||at==base+24||at==base+28){
   assert(c->Held&&InterlockedCompareExchange(&Owners,0,0)==1);
   if(at==base)*out=LastCommand;
   else if(at==base+8){if(c->FailCompletion&&c->Writes){assert(i==CompletionTarget);return 0;}*out=1;}
   else *out=Data[(at-base-24)/4];return 1;
  }
 }
 assert(!"unexpected MMIO read");return 0;
}
static int Write(void*x,uint32_t at,uint32_t command){Ctx*c=x;assert(c->Held&&InterlockedCompareExchange(&Owners,0,0)==1);
 unsigned i;for(i=0;i<7;i++)if(at==0xc440000+Apids[i]*32)break;assert(i<7);c->Writes++;LastCommand=command;CompletionTarget=i;
 unsigned offset=(command>>4)&255;uint8_t bytes[8]={0};
 if(!offset)memcpy(bytes,Ids[i],8);
 else if(offset==0x40){if(i==3){const uint8_t cfg[8]={0,1,0,0,0,1,128,0};memcpy(bytes,cfg,8);}else{assert(i==6);const uint8_t cfg[8]={8,7,0,0,7,7,0,0};memcpy(bytes,cfg,8);}}
 else if(offset==8){assert(i==6);bytes[0]=0x43;}
 else{assert(offset==0x10&&i>0&&i<4);bytes[0]=i==3?1:0x10;}
 memcpy(Data,bytes,8);struct timespec ts={0,1000};nanosleep(&ts,NULL);return 1;
}
static void WaitUs(void*x){(void)x;}
static void WaitInterval(void*x){((Ctx*)x)->Clock+=20000;}
static uint64_t Now(void*x){return ((Ctx*)x)->Clock++;}
static void*Run(void*x){unsigned type=(unsigned)(uintptr_t)x;Ctx c={0};
 for(unsigned i=0;i<400;i++)if(type){G99_RESULT*r=calloc(1,sizeof(*r));G99_IO io={&c,Read,Write,WaitUs,WaitInterval,Present,Now,Acquire,Release};assert(r);G99Sample(&io,1,r);assert(!r->Code&&r->SampleCount==1);free(r);}else{G98_OBS_RESULT r={0};G98_OBS_IO io={&c,Read,Write,WaitUs,Acquire,Release};G98Observe(&io,&r);assert(!r.Code&&r.Commands==5);}
 assert(!c.Held);return NULL;
}
int main(void){unsigned cases=0;G100_BUS_STATUS s;Ctx a={0},b={0};
 assert(!Acquire(&a));cases++;G100BusInitialize();
 Irql=2;assert(!Acquire(&a));Irql=0;cases++;
 a.Cancel=1;assert(!Acquire(&a));a.Cancel=0;cases++;
 ForceTimeout=1;assert(!Acquire(&a));ForceTimeout=0;G100BusStatus(&s);assert(s.Timeouts==1&&!s.Owners);cases++;
 pthread_t t[4];for(unsigned i=0;i<4;i++)assert(!pthread_create(&t[i],NULL,Run,(void*)(uintptr_t)(i&1)));for(unsigned i=0;i<4;i++)assert(!pthread_join(t[i],NULL));
 G100BusStatus(&s);assert(s.Acquires==8000&&s.Releases==8000&&s.PeakOwners==1&&!s.Owners&&!s.Poisoned);cases+=1600;
 assert(Acquire(&a));assert(!Acquire(&a)&&a.Held);Release(&a,0);cases++;
 /* Actual sampler failure after an issued command poisons before unlock. */
 b.FailCompletion=1;G99_RESULT*r=calloc(1,sizeof(*r));assert(r);G99_IO io={&b,Read,Write,WaitUs,WaitInterval,Present,Now,Acquire,Release};G99Sample(&io,1,r);assert(r->Code==G99_IO_ERROR&&b.Writes==1&&!b.Held);free(r);cases++;
 G100BusStatus(&s);assert(s.Poisoned&&!s.Owners&&s.Acquires==s.Releases);
 a=(Ctx){0};G98_OBS_RESULT out={0};G98_OBS_IO obs={&a,Read,Write,WaitUs,Acquire,Release};G98Observe(&obs,&out);assert(out.Code==G98_OBS_GATE&&!a.Reads&&!a.Writes&&!a.Held);cases++;
 printf("{\"passed\":true,\"cases\":%u,\"actual_native_gate_and_both_clients\":true,\"four_pthreads\":true,\"aliased_MMIO_model\":true,\"uncertain_command_poisoned_before_unlock\":true,\"native_operations\":0}\n",cases);return 0;}
