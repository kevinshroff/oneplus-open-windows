"""Compare the Go decoder with C layouts from the original SDK header."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess,sys
p=argparse.ArgumentParser();p.add_argument('--header',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();W=Path(__file__).resolve().parent;assert not a.output.exists();assert hashlib.sha256(a.header.read_bytes()).hexdigest()=='5c7cec278e684cf89591331391622441f660c5b9852351312fd910ae5930ae22';a.output.mkdir(parents=True)
h=a.header.read_text();names=['Mem_Range_s','Mem_Des_s','Mem_Large_Range_s','Mem_Large_Des_s','IRQ_Range_s','IRQ_Des_64_s'];blocks=[]
for name in names:
 m=re.search(r'typedef struct '+name+r' \{.*?\} \w+, \*\w+;',h,re.S);assert m,name;blocks.append(m.group())
source='''typedef unsigned int DWORD,ULONG;typedef unsigned short USHORT;typedef unsigned long long DWORDLONG,ULONGLONG,ULONG64;
#define NT_PROCESSOR_GROUPS 1
#pragma pack(push,1)
'''+ '\n'.join(blocks)+'\n#pragma pack(pop)\n'+'''#define O(t,f) __builtin_offsetof(t,f)
_Static_assert(sizeof(MEM_RANGE)==36,"MEM_RANGE");
_Static_assert(sizeof(MEM_DES)==32,"MEM_DES");
_Static_assert(O(MEM_DES,MD_Alloc_Base)==8,"memory base");
_Static_assert(O(MEM_DES,MD_Alloc_End)==16,"memory end");
_Static_assert(O(MEM_DES,MD_Flags)==24,"memory flags");
_Static_assert(O(MEM_DES,MD_Reserved)==28,"memory reserved");
_Static_assert(sizeof(MEM_LARGE_RANGE)==40,"large range");
_Static_assert(sizeof(MEM_LARGE_DES)==32,"large header");
_Static_assert(O(MEM_LARGE_DES,MLD_Alloc_Base)==8,"large base");
_Static_assert(O(MEM_LARGE_DES,MLD_Alloc_End)==16,"large end");
_Static_assert(O(MEM_LARGE_DES,MLD_Flags)==24,"large flags");
_Static_assert(sizeof(IRQ_RANGE)==12,"IRQ range");
_Static_assert(sizeof(IRQ_DES_64)==24,"IRQ64");
_Static_assert(O(IRQ_DES_64,IRQD_Flags)==8,"IRQ flags");
_Static_assert(O(IRQ_DES_64,IRQD_Group)==10,"IRQ group");
_Static_assert(O(IRQ_DES_64,IRQD_Alloc_Num)==12,"IRQ number");
_Static_assert(O(IRQ_DES_64,IRQD_Affinity)==16,"IRQ affinity");
#ifdef HOST_FIXTURE
#include <stdio.h>
static void hex(const void*x,unsigned n){const unsigned char*p=x;for(unsigned i=0;i<n;i++)printf("%02x",p[i]);}
int main(void){MEM_DES m={0,sizeof(MEM_RANGE),0xa90000,0xa93fff,1,0};MEM_LARGE_DES l={0,sizeof(MEM_LARGE_RANGE),0x100000000ull,0x1ffffffffull,3,0};IRQ_DES_64 q={0,sizeof(IRQ_RANGE),1,2,389,0x8000000000000001ull};printf("{\\"memory\\":\\"");hex(&m,sizeof(m));printf("\\",\\"large\\":\\"");hex(&l,sizeof(l));printf("\\",\\"irq\\":\\"");hex(&q,sizeof(q));printf("\\"}\\n");return 0;}
#endif
'''
(a.output/'abi.c').write_text(source)
def run(args):
 q=subprocess.run(list(map(str,args)),capture_output=True,text=True);assert not q.returncode,(args,q.stdout,q.stderr);return q.stdout
run(['clang','-target','aarch64-pc-windows-msvc','-std=c11','-Wall','-Wextra','-Werror','-c',a.output/'abi.c','-o',a.output/'abi-arm64.obj'])
run(['clang','-std=c11','-Wall','-Wextra','-Werror','-DHOST_FIXTURE=1',a.output/'abi.c','-o',a.output/'fixture'])
f=run([a.output/'fixture']);json.loads(f);(a.output/'fixture.json').write_text(f)
s=run(['go','run',W/'resource.go',W/'test_cases.go','--',a.output/'fixture.json']);v=json.loads(s);assert v['passed'];v.update(original_SDK_header_sha256=hashlib.sha256(a.header.read_bytes()).hexdigest(),ARM64_C_ABI_static_assertions=17,C_generated_fixture_sha256=hashlib.sha256(f.encode()).hexdigest(),decoder_source_sha256=hashlib.sha256((W/'resource.go').read_bytes()).hexdigest(),native_hardware_operations=0);(a.output/'tests.json').write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
