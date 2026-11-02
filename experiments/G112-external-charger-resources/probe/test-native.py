"""Exercise actual native MMIO adapter with explicit mappings/clock models."""
from pathlib import Path
import argparse,re,subprocess,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();o=a.output.resolve();assert not o.exists();o.mkdir(parents=True);w=Path(__file__).resolve().parent;s=(w/'g112_driver.c').read_text()
def fn(name):
 m=re.search(r'^static (?:PULONG|int) '+name+r'\(',s,re.M);assert m;i=s.index('{',m.end())+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
pre=r'''#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "g112_core.h"
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef int32_t LONG;typedef void*PVOID;typedef uint32_t*PULONG;typedef uint8_t*PUCHAR;typedef void*WDFREQUEST;typedef struct{int64_t QuadPart;}PHYSICAL_ADDRESS;
#define NULL ((void*)0)
#define PAGE_READONLY 2
#define PAGE_NOCACHE 512
static volatile LONG G112Maps;
static LONG InterlockedIncrement(volatile LONG*p){return++*p;}
static int WdfRequestIsCanceled(WDFREQUEST r){return*(int*)r;}
static uint32_t Memory[12][1024];static unsigned Maps,Reads,FailMap;
static void*MmMapIoSpaceEx(PHYSICAL_ADDRESS a,unsigned bytes,unsigned flags);
static uint32_t ReadReg(PULONG p){Reads++;return*p;}
#define READ_REGISTER_ULONG(p) ReadReg(p)
'''
ctx=re.search(r'typedef struct \{PVOID Maps\[12\].*?\}G112_CONTEXT;',s).group();pages=re.search(r'static const ULONG Pages\[\].*?;',s).group()
body=r'''
static G112_CONTEXT C;static int Cancel;
static void*MmMapIoSpaceEx(PHYSICAL_ADDRESS a,unsigned bytes,unsigned flags){assert(bytes==4096&&flags==(PAGE_READONLY|PAGE_NOCACHE));for(unsigned i=0;i<12;i++)if(a.QuadPart==Pages[i]){Maps++;return FailMap==i+1?NULL:Memory[i];}assert(0);return NULL;}
static uint32_t*At(uint32_t at){for(unsigned i=0;i<12;i++)if(at>=Pages[i]&&at-Pages[i]<4096)return&Memory[i][(at-Pages[i])/4];assert(0);return NULL;}
static void Reset(void){memset(&C,0,sizeof(C));memset(Memory,0,sizeof(Memory));Cancel=Maps=Reads=FailMap=0;C.Request=&Cancel;for(unsigned i=0;i<2;i++)for(unsigned j=0;j<3;j++){const G112_CLOCK*k=G112Controllers[i].Clocks+j;*At(k->Vote)|=k->Mask;*At(k->Cbcr)=k->Hwcg?0x80000002:0;}}
int main(void){unsigned cases=0;uint32_t value;
 for(unsigned page=0;page<12;page++)for(unsigned off=0;off<4096;off++){
  Reset();uint32_t at=Pages[page]+off;int yes=G112ReadAllowed(at);assert(NativeRead(&C,at,&value)==yes);if(!yes)assert(!Reads&&!Maps);cases++;
 }
 for(unsigned i=0;i<2;i++)for(unsigned j=0;j<3;j++)for(unsigned field=0;field<3;field++){
  Reset();const G112_CLOCK*k=G112Controllers[i].Clocks+j;
  if(!field)*At(k->Vote)&=~k->Mask;else if(field==1)*At(k->Cbcr)=0x80000000;else*At(G112Controllers[i].Root)=1;
  assert(!NativeRead(&C,G112Controllers[i].Base+0x68,&value)&&C.Guard==2&&!C.Maps[8+2*i]&&!C.Maps[9+2*i]);cases++;
 }
 Reset();Cancel=1;assert(!NativeRead(&C,0x880068,&value)&&!Reads&&!Maps);cases++;
 Reset();C.Reads=2048;assert(!NativeRead(&C,0x152008,&value)&&!Reads&&!Maps);cases++;
 Reset();FailMap=9;assert(!NativeRead(&C,0x880068,&value)&&!C.Maps[8]);cases++;
 printf("{\"passed\":true,\"cases\":%u,\"actual_native_adapter\":true,\"native_clock_guard_before_peripheral_mapping\":true,\"all_mappings_read_only\":true,\"MMIO_and_WDF_are_models\":true,\"native_operations\":0}\n",cases);return 0;}
'''
f=o/'model.c';f.write_text(pre+ctx+pages+'\n'.join(fn(n)for n in ['Address','SafeRead','NativeClocks','NativeRead'])+body);exe=o/'test';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(w),str(f),'-o',str(exe)],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe)],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);r=json.loads(q.stdout);r['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g112_driver.c','g112_core.h','g112_resources.h']};(o/'tests.json').write_text(json.dumps(r,indent=2));print(json.dumps(r))
