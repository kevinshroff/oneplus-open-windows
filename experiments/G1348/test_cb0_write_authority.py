#!/usr/bin/env python3
"""Host-only regression of the actual cleanup and SCTLR-write source functions."""
from pathlib import Path
import hashlib,json,re,subprocess,tempfile
W=Path(__file__).resolve().parent;m=json.loads((W/'BASE-AND-DELTA.json').read_text());s=(W/'overlay'/m['changed_source']).read_text()
assert hashlib.sha256(s.encode()).hexdigest()==m['variant_sha256']
def function(name):
 start=s.index('static int '+name+'(');end=s.index('\n}',start)+2;return s[start:end]
cleanup=function('QtbCleanup');write=function('QtbSctlrWrite')
assert 'Armed'not in cleanup and 'Interrupt['not in cleanup and 'Fault.Retain'not in cleanup and 'Journal.Fatal'not in cleanup
assert 'q->Cb0WriteMap+0' in write and 'q->SmmuMap'not in write
source=r'''
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
typedef uint64_t ULONGLONG;typedef uint32_t ULONG;typedef int BOOLEAN;typedef void*PVOID;typedef void*PETHREAD;typedef uint32_t*PULONG;typedef unsigned char*PUCHAR;
#define PASSIVE_LEVEL 0
#define MDL_PAGES_LOCKED 1
#define TRUE 1
struct qtb_report {int unused;};typedef struct OSM_CONTEXT OSM_CONTEXT;
typedef struct {struct{ULONGLONG Token;struct{struct{void*Context;}Interface;}Api;}Clock;} CGH_NATIVE;
typedef struct {int Referenced;void*Fdo;CGH_NATIVE*Hold;ULONGLONG Generation;}OLB_NATIVE;
typedef struct {int Referenced;ULONGLONG Id,Generation;}OGU_TOKEN;
typedef struct{int unused;}OPEN_NS_SCOPE;
typedef struct{ULONG PoolOrigin;struct{ULONGLONG root_physical;}Tables;void*Pool;int References;}OSMI_TABLES;
typedef struct{ULONG MdlFlags;ULONG ByteOffset;}MDL,*PMDL;
typedef struct{OSMI_TABLES*Tables;}OSMA_NATIVE_IO;
struct OSM_CONTEXT {int Started,Removing,StopPending,RemovePending,D0Ref;void*Qtb,*QtbMap,*Map[3];struct{void*Map[3];OLB_NATIVE*Bank;ULONGLONG Generation;int Retain,Fatal,Armed;}Fault;int QtbGranted;ULONGLONG Generation,NsGeneration;PETHREAD NsThread;void*NsTag;ULONGLONG NsToken;OLB_NATIVE*NsBank;OGU_TOKEN*GpuUserTag;OLB_NATIVE*GpuUserGmu;OSMI_TABLES*GpuTables;void*Fdo;OSMA_NATIVE_IO*RunNative;struct{ULONGLONG Id;}GpuUser;ULONG GmuClients;struct{ULONG refs;ULONGLONG generation;}Gmu;struct{ULONGLONG generation;ULONG refs;}Lease;ULONG Clients;};
static int thread;static int KeGetCurrentIrql(void){return 0;}static void*PsGetCurrentThread(void){return &thread;}static ULONG MmGetMdlByteOffset(PMDL p){return p->ByteOffset;}
'''+s[s.index('typedef struct {'):s.index('}QTB_NATIVE;')+len('}QTB_NATIVE;')]+r'''
static unsigned writes,current_refuse;static void*last_address;static ULONG last_value;
static void write_reg(PULONG p,ULONG v){writes++;last_address=p;last_value=v;}
#define WRITE_REGISTER_ULONG(p,v) write_reg(p,v)
#define KeMemoryBarrier() ((void)0)
'''+cleanup+r'''
static int QtbCurrent(void*x){return current_refuse||QtbCleanup(x);}
'''+write+r'''
int main(void){
 OSM_CONTEXT p={0};OLB_NATIVE b={0};OGU_TOKEN u={0};CGH_NATIVE h={0};OSMI_TABLES tables={0},running={0};MDL mdl={MDL_PAGES_LOCKED,0};OSMA_NATIVE_IO run={&running};QTB_NATIVE q={0};ULONG cb0=0,readonly=0;int tag,pool,fdo,map;
 q.P=&p;q.B=&b;q.User=&u;q.Tables=&tables;q.Mdl=&mdl;q.Thread=&thread;q.Tag=&tag;q.Map=&map;q.SmmuMap=&readonly;q.Cb0WriteMap=&cb0;q.Generation=7;q.Token=8;q.ClockToken=9;q.Root=0x123000;q.UserId=10;q.Pool=&pool;q.RunNative=&run;q.GmuRefs=1;q.LeaseRefs=2;q.Clients=1;q.Sctlr=0x1234ff;
 p.Started=p.D0Ref=p.QtbGranted=1;p.Qtb=&q;p.QtbMap=q.Map;p.Map[0]=q.SmmuMap;p.Fault.Map[2]=q.Cb0WriteMap;p.Fault.Bank=&b;p.Fault.Generation=7;p.Generation=p.NsGeneration=7;p.NsThread=&thread;p.NsTag=&tag;p.NsToken=8;p.NsBank=&b;p.GpuUserTag=&u;p.GpuUserGmu=&b;p.GpuTables=&tables;p.Fdo=&fdo;p.RunNative=&run;p.GpuUser.Id=10;p.GmuClients=p.Gmu.refs=1;p.Gmu.generation=p.Lease.generation=7;p.Lease.refs=2;p.Clients=1;
 b.Referenced=u.Referenced=1;b.Fdo=&fdo;b.Hold=&h;b.Generation=u.Generation=7;u.Id=10;h.Clock.Token=9;h.Clock.Api.Interface.Context=&p;tables.PoolOrigin=0x4e435047u;tables.Tables.root_physical=q.Root;tables.Pool=&pool;running.References=2;
 assert(!QtbCleanup(&q));assert(!QtbSctlrWrite(&q,q.Sctlr&~0xc0u));assert(writes==1&&last_address==&cb0&&last_address!=&readonly&&last_value==(q.Sctlr&~0xc0u));
 p.Fault.Retain=p.Fault.Fatal=1;p.Fault.Armed=0;current_refuse=1;assert(!QtbCleanup(&q));assert(!QtbSctlrWrite(&q,q.Sctlr));assert(writes==2&&last_address==&cb0&&last_value==q.Sctlr);
 p.Fault.Map[2]=&readonly;assert(QtbCleanup(&q));assert(QtbSctlrWrite(&q,q.Sctlr)&&writes==2);p.Fault.Map[2]=q.Cb0WriteMap;
 p.Fault.Bank=0;assert(QtbCleanup(&q));assert(QtbSctlrWrite(&q,q.Sctlr)&&writes==2);p.Fault.Bank=&b;
 p.Fault.Generation++;assert(QtbCleanup(&q));assert(QtbSctlrWrite(&q,q.Sctlr)&&writes==2);p.Fault.Generation=q.Generation;
 q.Cb0WriteMap=0;p.Fault.Map[2]=0;assert(QtbCleanup(&q));assert(QtbSctlrWrite(&q,q.Sctlr)&&writes==2);
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='cb0-authority-')as tmp:
 p=Path(tmp);(p/'test.c').write_text(source);subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p/'test.c'),'-o',str(p/'test')],check=True);subprocess.run([str(p/'test')],check=True)
print('PASS actual write callback uses only captured CB0 map; pointer/bank/generation loss refuses; poisoned retained cleanup remains possible. Host-only, no kernel/target call.')
