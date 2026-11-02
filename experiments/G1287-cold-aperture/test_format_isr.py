from pathlib import Path
import subprocess,json,hashlib
w=Path(__file__).resolve().parent
s=(w/'source/fault_owner_native.inc').read_text();a=s.index('static BOOLEAN FaultIsr(');b=s.index('\nstatic NTSTATUS CaptureFaultGrants',a);body=s[a:b]
p=w/'build/test_format_isr.c';p.write_text('''#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include "fault_policy.h"
typedef int BOOLEAN;typedef uint32_t ULONG;typedef ULONG*PULONG;typedef void*PVOID;typedef unsigned char*PUCHAR;typedef void*PKINTERRUPT;
#define TRUE 1
#define FALSE 0
#define UNREFERENCED_PARAMETER(x) (void)(x)
typedef struct {int Armed;void*Map[3];OF_JOURNAL Journal;}OF_OWNER;
typedef struct {OF_OWNER*Owner;unsigned Index;}OF_ISR_CONTEXT;
static unsigned writes;static ULONG stored;
#define InterlockedCompareExchange(p,a,b) (*(p))
#define READ_REGISTER_ULONG(p) (*(p))
#define WRITE_REGISTER_ULONG(p,v) (writes++,stored=(v),*(p)=(v))
#define KeMemoryBarrier() ((void)0)
'''+body+'''
int main(void){unsigned cases=0;for(unsigned i=1;i<=2;i++)for(unsigned bit=0;bit<=32;bit++){
 ULONG mem[32]={0};OF_OWNER f={0};f.Armed=1;f.Map[i]=mem;OF_ISR_CONTEXT c={&f,i};writes=0;stored=0;ULONG v=0x400u;if(bit<32&&bit!=10)v|=1u<<bit;mem[0x58/4]=v;
 BOOLEAN claim=FaultIsr(0,&c);assert(f.Journal.LastStatus[i]==v);
 if(v==0x400){assert(!claim&&!writes&&!f.Journal.Fatal&&!f.Journal.Events);}else {assert(claim&&f.Journal.Fatal);assert(stored==(v&0x800001feu));assert(!(stored&0x40000600u));}cases++;
 }printf("PASS %u actual ISR generated-body context Format/fault/unknown cases\\n",cases);return 0;}
''')
a=['clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(w/'source'),str(p),str(w/'source/fault_policy.c'),'-o',str(w/'build/test_format_isr')];q=subprocess.run(a,capture_output=True,text=True);assert not q.returncode,q.stderr;q=subprocess.run([str(w/'build/test_format_isr')],capture_output=True,text=True);assert not q.returncode,q.stderr;print(q.stdout)
(w/'evidence/FORMAT-ISR-ACTOR.json').write_text(json.dumps({'result':q.stdout,'actual_ISR_body_sha256':hashlib.sha256(body.encode()).hexdigest(),'ASan_UBSan':True,'hardware_evidence':False},indent=2)+'\n')
