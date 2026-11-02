"""Execute production capture with modeled OS, time and seven readonly MMIO pages."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
w = Path(__file__).resolve().parent
s = (w / 'g125_driver.c').read_text()

def function(name):
    m = re.search(r'^static (?:int|ULONG|void) ' + name + r'\(', s, re.M)
    assert m, name
    i = s.index('{', m.end()) + 1
    depth = 1
    while depth:
        depth += (s[i] == '{') - (s[i] == '}')
        i += 1
    return s[m.start():i]

pre = r'''
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
typedef uint8_t UCHAR;typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef int32_t LONG;typedef void*PVOID;typedef void*WDFREQUEST;
typedef struct{int64_t QuadPart;}LARGE_INTEGER,PHYSICAL_ADDRESS;
typedef struct{PHYSICAL_ADDRESS BaseAddress;LARGE_INTEGER NumberOfBytes;}PHYSICAL_MEMORY_RANGE,*PPHYSICAL_MEMORY_RANGE;
#define C_ASSERT(x) _Static_assert(x,#x)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define MAXULONGLONG UINT64_MAX
#define PAGE_READONLY 2u
#define PAGE_NOCACHE 512u
#define PASSIVE_LEVEL 0u
#define KernelMode 0
#define FALSE 0
#include "g125_protocol.h"
#include "g125_plan.h"
static ULONG Pages[G125_PAGE_COUNT][1024],Original[G125_PAGE_COUNT][1024];
static PHYSICAL_MEMORY_RANGE Ranges[512];
static volatile LONG G125Maps,G125Fault,G125Ready;
static unsigned MapCalls,Unmaps,FailMapAt,CancelAt,CancelChecks,Mutation,NoRanges,Frees,FullOS,FirmwareMatch,Processors,Build,Irql,Cases;
static ULONGLONG Time;
static LONG InterlockedIncrement(volatile LONG*p){return ++*p;}
static LONG InterlockedExchange(volatile LONG*p,LONG v){LONG old=*p;*p=v;return old;}
static PPHYSICAL_MEMORY_RANGE MmGetPhysicalMemoryRangesEx2(void*p,ULONG f){assert(!p&&!f);return NoRanges?NULL:Ranges;}
static void ExFreePool(PVOID p){assert(p==Ranges);Frees++;}
static void KeMemoryBarrier(void){__sync_synchronize();}
static ULONGLONG KeQueryInterruptTime(void){return ++Time;}
static int WdfRequestIsCanceled(WDFREQUEST p){assert(p==(void*)1);return ++CancelChecks==CancelAt;}
static PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS a,size_t n,ULONG flags){unsigned i=MapCalls++;assert(i<G125_PAGE_COUNT&&a.QuadPart==(int64_t)G125Pages[i]&&n==4096&&flags==(PAGE_READONLY|PAGE_NOCACHE));return MapCalls==FailMapAt?NULL:Pages[i];}
static void MmUnmapIoSpace(PVOID p,size_t n){assert(n==4096);assert(Unmaps<MapCalls);unsigned i=MapCalls-1-Unmaps-(FailMapAt&&FailMapAt==MapCalls?1:0);assert(p==Pages[i]);Unmaps++;}
static int FullWindows(void){return FullOS;}
static void Status(G125_STATUS*p){memset(p,0,sizeof(*p));p->Size=80;p->Version=1;p->Magic=G125_MAGIC;p->KernelBuild=Build;p->Processors=Processors;p->Irql=Irql;p->FirmwareBytes=576;p->FirmwareMatch=FirmwareMatch;p->MapCalls=G125Maps;p->Attempts=1;p->Ready=G125Ready;p->Fault=G125Fault;}
static void KeDelayExecutionThread(int mode,int alert,LARGE_INTEGER*d){assert(!mode&&!alert&&d->QuadPart==-500000);Time+=500000;if(Mutation){unsigned i=Mutation-1;assert(i<G125_WORD_COUNT);Pages[G125Words[i].Page][G125Words[i].Offset/4]^=1;}}
'''

main = r'''
static G125_CAPTURE Out;
static void SetWord(unsigned i,ULONG value){assert(i<G125_WORD_COUNT);Pages[G125Words[i].Page][G125Words[i].Offset/4]=value;}
static void Reset(void){memset(&Out,0,sizeof(Out));memset(Pages,0,sizeof(Pages));memset(Ranges,0,sizeof(Ranges));MapCalls=Unmaps=FailMapAt=CancelAt=CancelChecks=Mutation=NoRanges=Frees=0;G125Maps=G125Fault=G125Ready=0;FullOS=FirmwareMatch=1;Processors=8;Build=26300;Irql=0;Time=0;SetWord(4,1u<<31);SetWord(5,1u<<16);SetWord(13,1u<<31);SetWord(14,1u<<16);SetWord(16,1);}
static void Run(void){memcpy(Original,Pages,sizeof(Pages));Capture(&Out,(void*)1,123);assert(Unmaps==MapCalls-(FailMapAt&&FailMapAt==MapCalls?1:0)&&G125Ready&&G125Fault==!!Out.Code&&Out.Status.Ready&&Out.Status.Fault==!!Out.Code);if(!Mutation)assert(!memcmp(Original,Pages,sizeof(Pages)));assert(Out.ReadBytes<=192);for(unsigned pass=0;pass<2;pass++)for(unsigned i=0;i<G125_WORD_COUNT;i++){if(!(Out.WordMasks[pass]&(1u<<i)))assert(Out.Samples[pass][i]==0);}Cases++;}
int main(int argc,char**argv){assert(sizeof(Out)==320&&G125_PAGE_COUNT==7&&G125_WORD_COUNT==24);
 Reset();Run();assert(!Out.Code&&Out.CompleteMask==3&&Out.WordMasks[0]==G125_FULL_WORD_MASK&&Out.WordMasks[1]==G125_FULL_WORD_MASK&&Out.ReadBytes==192&&MapCalls==7&&Unmaps==7&&Frees==1&&Out.Nonce==123);
 for(unsigned i=0;i<G125_WORD_COUNT;i++){assert(G125Words[i].Page<7&&G125Words[i].Offset<=4092&&G125Words[i].Offset%4==0);for(unsigned j=0;j<i;j++)assert(G125Words[i].Page!=G125Words[j].Page||G125Words[i].Offset!=G125Words[j].Offset);}
 for(unsigned bit=0;bit<32;bit++){Reset();SetWord(16,1u<<bit);Run();assert(Out.Code==((1u<<bit)&G125_UNSUITABLE_CONTROL?2001u:0u));}
 Reset();SetWord(17,1);Run();assert(Out.Code==2003&&Out.ReadBytes==192);
 for(unsigned i=0;i<5;i++){Reset();if(i==0)FullOS=0;if(i==1)FirmwareMatch=0;if(i==2)Processors=1;if(i==3)Build=1;if(i==4)Irql=1;Run();assert(Out.Code==1001&&!MapCalls&&!Frees&&!Out.ReadBytes);}
 Reset();NoRanges=1;Run();assert(Out.Code==1002&&!MapCalls&&!Frees);
 for(unsigned page=0;page<7;page++)for(unsigned edge=0;edge<3;edge++){Reset();Ranges[0].BaseAddress.QuadPart=(int64_t)G125Pages[page]+(edge==0?-1:edge==1?0:4095);Ranges[0].NumberOfBytes.QuadPart=4096;Run();assert(Out.Code==1002&&Frees==1&&!MapCalls);}
 Reset();Ranges[0].BaseAddress.QuadPart=-2;Ranges[0].NumberOfBytes.QuadPart=4;Run();assert(Out.Code==1002&&!MapCalls&&Frees==1);
 Reset();for(unsigned i=0;i<512;i++){Ranges[i].BaseAddress.QuadPart=0x10000000;Ranges[i].NumberOfBytes.QuadPart=4096;}Run();assert(Out.Code==1002&&!MapCalls&&Frees==1);
 for(unsigned i=1;i<=7;i++){Reset();FailMapAt=i;Run();assert(Out.Code==1005&&MapCalls==i&&Unmaps==i-1&&!Out.ReadBytes&&!Out.CompleteMask);}
 for(unsigned i=1;i<=55;i++){Reset();CancelAt=i;Run();assert(Out.Code==1004);unsigned reads=i<=7?0:i-8;assert(Out.ReadBytes==4*reads);assert(MapCalls==(i<=7?i-1:7));assert(Out.CompleteMask==(reads>=24?1u:0u));}
 for(unsigned i=1;i<=24;i++){Reset();Mutation=i;Run();assert(Out.Code==((i==17||i==18)?2002u:0u)&&Out.ReadBytes==192&&Out.CompleteMask==3);}
 if(argc==2){Reset();Run();FILE*f=fopen(argv[1],"wb");assert(f&&fwrite(&Out,1,sizeof(Out),f)==sizeof(Out));fclose(f);}
 printf("{\"passed\":true,\"cases\":%u,\"production_capture_functions\":true,\"OS_MMIO_time_modeled\":true,\"all_map_failure_and_cancel_boundaries\":true,\"readonly_maps_and_no_page_writes\":true,\"native_hardware_operations\":0}\n",Cases);
}
'''

source = a.output / 'model.c'
source.write_text(pre + '\n'.join(function(n) for n in ['NoManagedRam', 'Word', 'Capture']) + main)
command = ['clang', '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', '-I' + str(w), str(source), '-o', str(a.output / 'test')]
r = subprocess.run(command, capture_output=True, text=True)
assert r.returncode == 0, r.stderr
r = subprocess.run([str((a.output / 'test').resolve()), str((a.output / 'fixture.bin').resolve())], capture_output=True, text=True)
assert r.returncode == 0 and not r.stderr, (r.stdout, r.stderr)
result = json.loads(r.stdout)
result['source_sha256'] = {n: hashlib.sha256((w / n).read_bytes()).hexdigest() for n in ['g125_driver.c', 'g125_plan.h', 'g125_protocol.h']}
(a.output / 'tests.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result))
