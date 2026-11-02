"""Execute actual native adapter functions and the whole core with MMIO models."""
from pathlib import Path
import argparse,re,subprocess,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();o=a.output.resolve();assert not o.exists();o.mkdir(parents=True);w=Path(__file__).resolve().parent;s=(w/'g103_driver.c').read_text()
def fn(name):
 m=re.search(r'^static (?:PULONG|int) '+name+r'\(',s,re.M);assert m;i=s.index('{',m.end())+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
ctx=re.search(r'typedef struct \{PVOID Maps\[12\].*?\}G103_CONTEXT;',s).group()
pre=r'''
#define main original_core_model_main
#include "test-core.c"
#undef main
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef int32_t LONG;typedef void*PVOID;typedef uint32_t*PULONG;typedef uint8_t*PUCHAR;typedef void*WDFREQUEST;typedef struct{int64_t QuadPart;}PHYSICAL_ADDRESS;
#define PAGE_READONLY 2
#define PAGE_READWRITE 4
#define PAGE_NOCACHE 512
static volatile LONG G103Maps;
static LONG InterlockedIncrement(volatile LONG*p){return++*p;}
static Model M;static unsigned MapCalls,MapFailure,RegReads,RegWrites;
static void*MmMapIoSpaceEx(PHYSICAL_ADDRESS a,unsigned bytes,unsigned flags){assert(bytes==4096);for(unsigned i=0;i<12;i++)if(a.QuadPart==Pages[i]){assert(flags==(((i==8||i==10)?PAGE_READWRITE:PAGE_READONLY)|PAGE_NOCACHE));MapCalls++;return MapFailure==i+1?NULL:M.Memory[i];}assert(0);return NULL;}
static ULONG OffsetOf(PULONG p){for(unsigned i=0;i<12;i++)if(p>=M.Memory[i]&&p<M.Memory[i]+1024)return Pages[i]+(ULONG)((p-M.Memory[i])*4);assert(0);return 0;}
static uint32_t ReadReg(PULONG p){uint32_t v;RegReads++;assert(Read(&M,OffsetOf(p),&v));return v;}
static void WriteReg(PULONG p,uint32_t v){RegWrites++;assert(Write(&M,OffsetOf(p),v));}
#define READ_REGISTER_ULONG(p) ReadReg(p)
#define WRITE_REGISTER_ULONG(p,v) WriteReg(p,v)
'''
body=r'''
static G103_CONTEXT C;
static void ResetNative(void){Reset(&M);memset(&C,0,sizeof(C));MapCalls=RegReads=RegWrites=MapFailure=0;}
static int Av(void*x){assert(x==&C);return Available(&M);}
static uint64_t Time(void*x){assert(x==&C);return Now(&M);}
static void DelayNative(void*x,uint32_t us){assert(x==&C);Delay(&M,us);}
int main(void){unsigned cases=0;uint32_t v;
 for(unsigned p=0;p<12;p++)for(unsigned o=0;o<4096;o++){
  ResetNative();uint32_t at=Pages[p]+o;int expected=G103ReadAllowed(at)&&at!=0x880780&&at!=0x98c780;
  assert(NativeRead(&C,at,&v)==expected);if(!G103ReadAllowed(at))assert(!RegReads&&!MapCalls);cases++;
  ResetNative();expected=at==0x88080c||at==0x98c80c;assert(NativeWrite(&C,at,0)==expected);if(!expected)assert(!RegWrites);cases++;
 }
 for(unsigned i=0;i<2;i++)for(unsigned j=0;j<3;j++)for(unsigned bad=0;bad<4;bad++){
  ResetNative();const G102_CONTROLLER*k=G102Controllers+i;
  if(bad==0)*At(&M,k->Clocks[j].Vote)&=~k->Clocks[j].Mask;
  if(bad==1)*At(&M,k->Clocks[j].Cbcr)=0x80000000;
  if(bad==2)*At(&M,k->Root)=1;
  if(bad==3)*At(&M,0xf100000+k->Pins[0]*0x1000)^=4;
  assert(!NativeWrite(&C,k->Base+0x80c,0)&&!RegWrites&&C.Guard==2&&!C.Maps[i?10:8]);cases++;
 }
 ResetNative();C.Reads=200000;assert(!NativeRead(&C,0x152008,&v)&&!RegReads&&!MapCalls);cases++;
 ResetNative();MapFailure=9;assert(!NativeRead(&C,0x880068,&v)&&!C.Maps[8]);cases++;
 G103_RESULT*r=calloc(1,sizeof(*r));assert(r);ResetNative();G103_IO io={&C,NativeRead,NativeWrite,Av,Time,DelayNative};G103Identify(&io,r);
 assert(!r->Code&&!r->Uncertain&&r->Commands==18&&r->Completed==18&&r->QueryMask==63&&r->RestoredMask==3);
 assert(C.Policy.Commands==18&&C.Policy.Completed==18&&!C.Policy.Active&&!C.Policy.Held&&!C.Policy.Faulted&&RegWrites==108&&C.Writes==108);
 printf("{\"passed\":true,\"cases\":%u,\"actual_native_adapter_and_complete_core\":true,\"native_adapter_reads\":%u,\"native_adapter_writes\":%u,\"model_Maps\":%u,\"MMIO_WDF_time_explicitly_modeled\":true,\"native_operations\":0}\n",cases+1,C.Reads,C.Writes,MapCalls);free(r);return 0;}
'''
f=o/'model.c';f.write_text(pre+ctx+'\n'.join(fn(n)for n in ['WriteOffset','Address','SafeRead','NativeClocks','NativeRead','NativeWrite'])+body)
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(w),str(f),str(w/'g102_core.c'),str(w/'g103_core.c'),'-o',str(o/'test')],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(o/'test')],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);r=json.loads(q.stdout);r['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g103_driver.c','g103_policy.h','g103_core.h','g103_core.c','g102_core.c','g102_resources.h']};(o/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(q.stdout)
