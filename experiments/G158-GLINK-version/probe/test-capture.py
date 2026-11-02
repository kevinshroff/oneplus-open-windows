"""Run actual kernel capture/guard/map/write functions with explicit OS/peer models."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
w = Path(__file__).resolve().parent
out = args.output.resolve()
out.mkdir(exist_ok=False, parents=True)
native = w.parents[1] / 'charging-G156/private'
raw = (native / 'native-capture.bin').read_bytes()
assert hashlib.sha256(raw).hexdigest() == '1257b31305f2a669e84633a71d78f6660dc6a91ee2e098c25082fb2232ca903d'
decoded = json.loads((native / 'decoded-native-r2.json').read_text())
for index, name in [(1, 'toc.bin'), (3, 'part.bin')]:
    row = decoded['regions'][index]
    start = 288 + row['offset']
    (out / name).write_bytes(raw[start:start + row['bytes']])
fdt = (w.parents[1] / 'charging-G108/private/inspection-r2/boot-data-0x4000.dtb').read_bytes()
assert hashlib.sha256(fdt).hexdigest() == 'f0854f17171351b60254538941044e68cae283f1f6c9243faa14b71badbc2e29'
(out / 'fdt.bin').write_bytes(fdt + bytes(0x10000 - len(fdt)))
source = (w / 'g158_driver.c').read_text()
body = source[source.index('static int ReservedRam'):source.index('VOID G158Control')]
pre = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
typedef uint32_t ULONG,UINT32;typedef uint64_t ULONGLONG,UINT64;
typedef uint8_t UCHAR,UINT8;typedef int64_t LONGLONG;typedef int32_t LONG,NTSTATUS;
typedef size_t SIZE_T,UINTN;typedef void*PVOID;typedef void*WDFREQUEST;
typedef struct{LONGLONG QuadPart;}PHYSICAL_ADDRESS,LARGE_INTEGER;
typedef struct{PHYSICAL_ADDRESS BaseAddress,NumberOfBytes;}PHYSICAL_MEMORY_RANGE,*PPHYSICAL_MEMORY_RANGE;
#define C_ASSERT(x) _Static_assert(x,#x)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define CTL_CODE(d,f,m,a) (((d)<<16)|((a)<<14)|((f)<<2)|(m))
#define FILE_DEVICE_UNKNOWN 0x22
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#define PAGE_READONLY 2
#define PAGE_READWRITE 4
#define PAGE_NOCACHE 512
#define PASSIVE_LEVEL 0
#define MAXULONGLONG UINT64_MAX
#define KernelMode 0
#define FALSE 0
#define NT_SUCCESS(s) ((s)>=0)
#define UNREFERENCED_PARAMETER(x) ((void)x)
#define VOID void
#define STATIC static
#define CONST const
#define CopyMem memcpy
#define ZeroMem(p,n) memset(p,0,n)
#include "OpenSha256.h"
#include "g158_core.h"
#include "g158_slots.h"
#include "g158_protocol.h"
#include "smem-select.h"
static volatile LONG G158Maps,G158Fault,G158Ready;
static UCHAR Fdt[0x10000],Toc[0x1000],Part[0x60000],OriginalFdt[0x10000],OriginalToc[0x1000],OriginalPart[0x60000];
static ULONG Irq[1024];static G158_SLOTS Locations;static G158_CAPTURE*Out;
static PHYSICAL_MEMORY_RANGE Ranges[4];
static ULONG MapCalls,Unmaps,FailMap,CancelAt,CancelChecks,FirmwareMatch,Processors,Build,Irql,NoRanges,FullOS;
static ULONG Doorbells,PeerMode,AckFirst,AppendOpen,DelayFail,Mutation,MutationDone,ForcedElapsed,Delays;
static ULONGLONG Time;
static LONG InterlockedIncrement(volatile LONG*p){return++*p;}
static LONG InterlockedExchange(volatile LONG*p,LONG v){LONG old=*p;*p=v;return old;}
static ULONGLONG KeQueryInterruptTime(void){return Time+=ForcedElapsed?30000000:10;}
static void Status(G158_STATUS*s){memset(s,0,sizeof(*s));s->Size=sizeof(*s);s->Version=1;s->Magic=G158_MAGIC;s->FirmwareBytes=576;s->FirmwareMatch=FirmwareMatch;s->KernelBuild=Build;s->Processors=Processors;s->Irql=Irql;s->MapCalls=G158Maps;s->Attempts=1;s->Ready=G158Ready;s->Fault=G158Fault;}
static int WinPE(void){return FullOS;}
static PPHYSICAL_MEMORY_RANGE MmGetPhysicalMemoryRangesEx2(PVOID p,ULONG flags){assert(!p&&!flags);if(NoRanges)return NULL;void*out=malloc(sizeof(Ranges));assert(out);memcpy(out,Ranges,sizeof(Ranges));return out;}
static void ExFreePool(PVOID p){free(p);}
static int WdfRequestIsCanceled(WDFREQUEST r){assert(r==(void*)1);return++CancelChecks==CancelAt;}
static PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS a,SIZE_T n,ULONG flags){
 MapCalls++;if(MapCalls==FailMap)return NULL;
 if((ULONGLONG)a.QuadPart==0x81a04000&&n==0x10000){assert(flags==PAGE_READONLY);return Fdt;}
 if((ULONGLONG)a.QuadPart==0x81eff000&&n==0x1000){assert(flags==(PAGE_READONLY|PAGE_NOCACHE));return Toc;}
 if((ULONGLONG)a.QuadPart==0x81e9f000&&n==0x60000){assert(flags==(PAGE_READWRITE|PAGE_NOCACHE));return Part;}
 assert((ULONGLONG)a.QuadPart==0x408000&&n==0x1000&&flags==(PAGE_READWRITE|PAGE_NOCACHE));return Irq;
}
static void MmUnmapIoSpace(PVOID p,SIZE_T n){assert(p&&n);Unmaps++;}
static SIZE_T RtlCompareMemory(const void*a,const void*b,SIZE_T n){const UCHAR*x=a,*y=b;SIZE_T i=0;for(;i<n&&x[i]==y[i];i++){}return i;}
static void put32(UCHAR*p,ULONG v){for(unsigned i=0;i<4;i++)p[i]=(UCHAR)(v>>(8*i));}
static ULONG get32(const UCHAR*p){return G158U32(p);}
static void remoteFrame(ULONG command,ULONG version,ULONG features){
 UCHAR b[8]={(UCHAR)command,0,(UCHAR)version,0,0,0,0,0};put32(b+4,features);
 UCHAR*d=Part+Locations.Descriptor;ULONG head=get32(d+12);
 for(unsigned i=0;i<8;i++)Part[Locations.Rx+((head+i)&G158_FIFO_MASK)]=b[i];
 put32(d+12,(head+8)&G158_FIFO_MASK);
}
static void KeMemoryBarrier(void){
 __sync_synchronize();
 if(Mutation&&!MutationDone&&MapCalls==3&&Out->Slots.Descriptor){MutationDone=1;Part[4]^=1;}
 if(Irq[3]){
  assert(Irq[3]==0x30000);Doorbells++;Irq[3]=0;
  if(PeerMode){
   UCHAR*d=Part+Locations.Descriptor;ULONG tail=get32(d),head=get32(d+4),version=0,ack=0;
   while(tail!=head){ULONG command=G158U16(Part+Locations.Tx+tail);assert(command<=1);version+=command==0;ack+=command==1;tail=(tail+8)&G158_FIFO_MASK;}
   put32(d,tail);
   if(version){if(!AckFirst)remoteFrame(0,1,0);remoteFrame(1,1,PeerMode==2?7:0);if(AckFirst)remoteFrame(0,1,0);}
   else if(ack&&AppendOpen)remoteFrame(2,7,12);
  }
 }
}
static NTSTATUS KeDelayExecutionThread(int mode,int alert,LARGE_INTEGER*d){assert(!mode&&!alert&&d->QuadPart==-50000);Time+=50000;Delays++;return DelayFail?-1:0;}
'''
main = r'''
static void Reset(void){
 memset(Out,0,sizeof(*Out));memcpy(Fdt,OriginalFdt,sizeof(Fdt));memcpy(Toc,OriginalToc,sizeof(Toc));memcpy(Part,OriginalPart,sizeof(Part));memset(Irq,0,sizeof(Irq));memset(Ranges,0,sizeof(Ranges));
 MapCalls=Unmaps=FailMap=CancelAt=CancelChecks=NoRanges=Doorbells=DelayFail=Mutation=MutationDone=ForcedElapsed=Delays=0;
 G158Maps=G158Fault=G158Ready=0;FullOS=FirmwareMatch=PeerMode=1;Processors=8;Build=26100;Irql=AckFirst=0;AppendOpen=1;Time=0;
 assert(G158FindSlots(Part,sizeof(Part),&Locations));
}
static void Check(ULONG code,ULONG maps){
 Capture(Out,(void*)1,0x1234);
 assert(Out->Code==code&&MapCalls==maps&&Unmaps==maps&&Out->Nonce==0x1234&&G158Ready);
 assert((G158Fault!=0)==(code!=0));if(code<2000&&code!=0)assert(!Doorbells&&!Out->State.CounterWriteAttempts&&!Out->State.TxWriteAttempts);
}
static void File(const char*path,void*b,size_t n){FILE*f=fopen(path,"rb");assert(f&&fread(b,1,n,f)==n&&fgetc(f)==EOF);fclose(f);}
static void Save(const char*folder,const char*name){char path[4096];int n=snprintf(path,sizeof(path),"%s/%s",folder,name);assert(n>0&&(size_t)n<sizeof(path));FILE*f=fopen(path,"wbx");assert(f&&fwrite(Out,1,sizeof(*Out),f)==sizeof(*Out));fclose(f);}
int main(int argc,char**argv){
 assert(argc==5);unsigned cases=0;Out=calloc(1,sizeof(*Out));assert(Out);
 File(argv[1],OriginalFdt,sizeof(OriginalFdt));File(argv[2],OriginalToc,sizeof(OriginalToc));File(argv[3],OriginalPart,sizeof(OriginalPart));
 for(unsigned order=0;order<2;order++){
  Reset();AckFirst=order;Check(0,4);assert(Out->State.Complete&&Out->State.LocalAckObserved&&Out->State.NextCommand==2&&Out->FinalDescriptor[2]==24&&Out->FinalDescriptor[3]==32&&Out->State.KickAttempts==Doorbells&&Doorbells==3);if(!order)Save(argv[4],"success-open.bin");cases++;
 }
 for(unsigned i=1;i<=4;i++){
  Reset();FailMap=i;Capture(Out,(void*)1,0x1234);assert(Out->Code&&MapCalls==i&&Unmaps==i-1&&G158Ready&&G158Fault&&!Doorbells&&!Out->State.TxWriteAttempts);cases++;
 }
 for(unsigned i=0;i<5;i++){
  Reset();if(i==0)FullOS=0;if(i==1)FirmwareMatch=0;if(i==2)Processors=1;if(i==3)Build=1;if(i==4)Irql=1;Check(1001,0);cases++;
 }
 for(unsigned i=0;i<6;i++){
  Reset();Ranges[0].BaseAddress.QuadPart=(LONGLONG[]){0x400000,0x407800,0x81a00000,0x81cfffff,0x81d00000,0x81eff800}[i];Ranges[0].NumberOfBytes.QuadPart=4096;Check(1002,0);cases++;
 }
 Reset();NoRanges=1;Check(1002,0);cases++;
 Reset();Fdt[0]^=1;Check(1004,1);Save(argv[4],"refused-FDT.bin");cases++;
 Reset();Toc[0]^=1;Check(1006,2);cases++;
 Reset();Part[32]^=1;Check(1008,3);cases++;
 Reset();Mutation=1;Check(1008,3);assert(MutationDone);cases++;
 Reset();CancelAt=1;Check(1010,4);assert(Out->Cancelled);cases++;
 Reset();CancelAt=2;Check(0,4);assert(CancelChecks==1&&Out->State.Complete);cases++;
 Reset();ForcedElapsed=1;Check(3001,4);assert(Out->TimedOut&&!Doorbells&&!Out->State.Started);cases++;
 Reset();PeerMode=0;Check(3001,4);assert(Out->TimedOut&&!Out->State.Complete&&Doorbells==1&&Out->State.TxFrames==2&&Out->State.RxFrames==1&&Delays>500);Save(argv[4],"timeout-after-write.bin");cases++;
 Reset();DelayFail=1;Capture(Out,(void*)1,0x1234);assert(Out->Code==1011&&MapCalls==4&&Unmaps==4&&!Out->State.Complete&&Out->State.Started&&Doorbells==1);cases++;
 Reset();PeerMode=2;Check(2006,4);assert(!Out->State.Complete&&Doorbells<=2);cases++;
 Reset();put32(Part+Locations.Descriptor+4,8);Check(2003,4);assert(!Doorbells&&!Out->State.Started&&!Out->State.TxWriteAttempts);cases++;
 printf("{\"passed\":true,\"cases\":%u,\"actual_capture_and_native_IO_callbacks\":true,\"native_operations\":0}\n",cases);free(Out);return 0;
}
'''
(out / 'model.c').write_text(pre + body + main)
argv = ['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1',
        '-fsanitize=address,undefined', '-I' + str(w), str(out / 'model.c'),
        str(w / 'g158_core.c'), '-o', str(out / 'test-capture')]
q = subprocess.run(argv, capture_output=True, text=True)
(out / 'compiler.txt').write_text(q.stdout + q.stderr)
assert q.returncode == 0, q.stdout + q.stderr
q = subprocess.run([str(out / 'test-capture'), str(out / 'fdt.bin'), str(out / 'toc.bin'),
                    str(out / 'part.bin'), str(out)], capture_output=True, text=True)
(out / 'run.txt').write_text(q.stdout + q.stderr)
assert q.returncode == 0, q.stdout + q.stderr
result = json.loads(q.stdout)
result.update(source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in w.iterdir()
                           if p.suffix in ['.c', '.h'] and not p.name.startswith('test-')},
              models=['WinPE/DSDT/processor status', 'OS RAM ranges', 'physical maps as local arrays',
                      'cancellation and time', 'DSP version peer on the modeled doorbell'],
              limitations=['No real MMIO or native GLINK exchange. Only selected OS/callback behavior is modeled.'])
(out / 'tests.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
