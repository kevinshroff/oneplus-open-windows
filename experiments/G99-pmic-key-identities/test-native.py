from pathlib import Path
import argparse,re,subprocess,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);w=Path(__file__).resolve().parent;s=(w/'g99_driver.c').read_text()
def fn(name):
 m=re.search(r'^static (?:PULONG|int) '+name+r'\(',s,re.M);assert m;i=s.index('{',m.end())+1;d=1
 while d:d+=(s[i]=='{')-(s[i]=='}');i+=1
 return s[m.start():i]
prefix=r'''#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "g99_core.h"
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef void*PVOID;typedef uint32_t*PULONG;typedef uint8_t*PUCHAR;typedef void*WDFREQUEST;
#define C_ASSERT(x) _Static_assert(x,#x)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define CTL_CODE(d,f,m,a) (((d)<<16)|((a)<<14)|((f)<<2)|(m))
#define FILE_DEVICE_UNKNOWN 0x22
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#include "g99_protocol.h"
static unsigned ActualWrites;
#define READ_REGISTER_ULONG(p) (*(p))
#define WRITE_REGISTER_ULONG(p,v) (*(p)=(v),ActualWrites++)
static int WdfRequestIsCanceled(WDFREQUEST r){return*(int*)r;}
'''
ctx=re.search(r'typedef struct \{PVOID Maps\[5\].*?\}G99_CONTEXT;',s).group();pages=re.search(r'static const ULONG Pages\[5\].*?;',s).group()
main=r'''
static uint32_t Mem[5][1024];static int Cancel;static G99_CONTEXT C;
static uint32_t*At(uint32_t a){for(unsigned i=0;i<5;i++)if(a>=Pages[i]&&a-Pages[i]<4096)return&Mem[i][(a-Pages[i])/4];assert(0);return 0;}
static void Reset(void){memset(&C,0,sizeof(C));memset(Mem,0,sizeof(Mem));Cancel=0;ActualWrites=0;C.Request=&Cancel;for(unsigned i=0;i<5;i++)C.Maps[i]=Mem[i];for(unsigned i=0;i<4;i++){*At(0xc402000+G99Targets[i].Apid*4)=G99Targets[i].Map;*At(0xc42d000+G99Targets[i].Apid*4)=G99Targets[i].Owner;*At(G99Base(i)+8)=1;}}
int main(void){unsigned cases=0;uint32_t value;
 for(uint32_t at=0xc400000;at<0xc448000;at++)for(unsigned j=0;j<4;j++){
  uint32_t command=(uint32_t[]){0x08000007,0x08000100,0x08000407,0x00000100}[j];Reset();int allowed=G99WriteAllowed(at,command);assert(NativeWrite(&C,at,command)==allowed);assert(ActualWrites==(unsigned)allowed&&C.Writes==(unsigned)allowed);cases++;
 }
 for(unsigned i=0;i<4;i++){
  Reset();*At(0xc402000+G99Targets[i].Apid*4)^=0x100;assert(!NativeWrite(&C,G99Base(i),0x08000007)&&C.Guard==2&&!ActualWrites);cases++;
  Reset();*At(0xc42d000+G99Targets[i].Apid*4)^=1;assert(!NativeWrite(&C,G99Base(i),0x08000007)&&C.Guard==2&&!ActualWrites);cases++;
  Reset();*At(G99Base(i)+8)=0;*At(G99Base(i))=0x08000007;assert(!NativeWrite(&C,G99Base(i),0x08000007)&&C.Guard==3&&!ActualWrites);cases++;
  Reset();Cancel=1;assert(!NativeWrite(&C,G99Base(i),0x08000007)&&C.Guard==4&&!ActualWrites);cases++;
 }
 Reset();C.Reads=80000;assert(!NativeRead(&C,0xc400000,&value));C.Reads=0;assert(!NativeRead(&C,0xc7b7000,&value)&&!NativeRead(&C,0xc7b7008,&value)&&!NativeRead(&C,0xb000000,&value));cases++;
 Reset();C.Writes=G99_MAX_COMMANDS;assert(!NativeWrite(&C,G99Base(0),0x08000007)&&!ActualWrites);cases++;
 printf("{\"passed\":true,\"cases\":%u,\"capture_bytes\":%zu,\"result_offset\":%zu,\"sample_offset\":%zu,\"trace_offset\":%zu,\"actual_native_adapter_functions\":true,\"MMIO_and_WDF_modeled\":true,\"native_operations\":0}\n",cases,sizeof(G99_CAPTURE),offsetof(G99_CAPTURE,Result),offsetof(G99_RESULT,Samples),offsetof(G99_RESULT,Trace));return 0;}
'''
f=a.output/'model.c';f.write_text(prefix+ctx+pages+'\n'.join(fn(n)for n in ['Address','NativeRead','NativeWrite'])+main);exe=a.output/'test';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(w),str(f),'-o',str(exe)],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);v=json.loads(q.stdout);v['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g99_driver.c','g99_core.h','g99_protocol.h']};(a.output/'tests.json').write_text(json.dumps(v,indent=2));print(json.dumps(v))
