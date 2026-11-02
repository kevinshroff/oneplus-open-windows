from pathlib import Path
import subprocess,json,hashlib
p=Path(__file__).resolve().parents[1];s=(p/'source/local_bank_native.inc').read_text();body=s[s.index('static int LocalCurrent('):s.index('static int LocalSnapshot(')]
shim=r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#define CGH_HELD 2
#define CGH_RELEASED 3
#define CGH_RESET_QUIESCENT 6
#define CGH_BOOT_RELEASED 9
#define OSMA_ACTIVE 3
#define STATUS_SUCCESS 0
#define RTL_NUMBER_OF(x) (sizeof(x)/sizeof((x)[0]))
typedef struct H H;typedef struct N N;typedef struct B B;typedef struct P P;
struct H{struct{void*Pdo;}*Life;uint64_t Serial;struct{uint64_t serial;int state,reset_mode;}Hold;struct{struct{struct{void*Context;}Interface;}Api;uint64_t Token;}Clock;uint64_t Generation;int BootCommitted;};
struct B{H*Hold;int ProgramPinned;};struct N{struct{void*Context;B*Bank;}Proof;struct{struct{int Phase;}Session;int Poisoned,Disabled,References;}*Tables;};
struct P{uint64_t Generation;int Granted[1];void*Map[1];struct{uint64_t Id;struct{void*Context;void*Pdo;uint64_t Generation;}Client;}GmuSlots[1];B*RunBank;N*RunNative;void*RunTag;};
typedef P OSM_CONTEXT;typedef H CGH_NATIVE;typedef N OSMA_NATIVE_IO;
typedef struct{P*P;H*H;}OLB_NATIVE_IO;static const struct{uint64_t pa,bytes;}osm_required_ranges[]={{0x3da0000,0x40000}};static int running,cold;
static int GmuCurrent(void*p,uint64_t g){(void)p;(void)g;return 0;}static int CghNativeCheck(H*h){(void)h;cold++;return 0;}static int CghNativeRuntimeCheck(H*h){(void)h;running++;return 0;}
'''
main=r'''
int main(void){P p={0};H h={0};B b={&h,1};N n={0};struct{void*Pdo;}life={(void*)1};struct{struct{int Phase;}Session;int Poisoned,Disabled,References;}tables={{OSMA_ACTIVE},0,0,2};
 h.Life=(void*)&life;h.Serial=h.Hold.serial=8;h.Hold.state=CGH_RELEASED;h.Clock.Api.Interface.Context=&p;h.Clock.Token=1;h.Generation=9;p.Generation=2;p.Granted[0]=1;p.Map[0]=(void*)1;p.GmuSlots[0].Id=1;p.GmuSlots[0].Client.Context=&h;p.GmuSlots[0].Client.Pdo=life.Pdo;p.GmuSlots[0].Client.Generation=9;p.RunBank=&b;p.RunNative=&n;p.RunTag=(void*)3;n.Proof.Context=p.RunTag;n.Proof.Bank=&b;n.Tables=(void*)&tables;OLB_NATIVE_IO io={&p,&h};
 h.BootCommitted=1;assert(!LocalCurrent(&io,2,8)&&running==1&&!cold);
 h.BootCommitted=0;assert(LocalCurrent(&io,2,8)&&running==1&&!cold);
 h.Hold.reset_mode=1;h.Hold.state=CGH_RESET_QUIESCENT;assert(!LocalCurrent(&io,2,8)&&cold==1);
 h.Hold.state=CGH_BOOT_RELEASED;assert(LocalCurrent(&io,2,8)&&cold==1);
 h.BootCommitted=1;assert(!LocalCurrent(&io,2,8)&&running==2);
 h.Hold.state=CGH_RESET_QUIESCENT;assert(LocalCurrent(&io,2,8)&&running==2);
 puts("{\"cases\":6,\"result\":\"pass\",\"native\":false}");return 0;}
'''
(p/'build/test_runtime_phase.c').write_text(shim+body+main);args=['clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p/'build/test_runtime_phase.c'),'-o',str(p/'build/test_runtime_phase')];r=subprocess.run(args,capture_output=True,text=True);assert not r.returncode,r.stderr
r=subprocess.run([str(p/'build/test_runtime_phase')],capture_output=True,text=True);(p/'evidence/RUNTIME-PHASE-TESTS.json').write_text(json.dumps(dict(exit=r.returncode,stdout=r.stdout,stderr=r.stderr,production_body_sha256=hashlib.sha256(body.encode()).hexdigest(),scope='exact LocalCurrent body with modeled owner services: committed RELEASED reaches runtime checker; uncommitted RELEASED refuses. No native/ABI/current-hardware proof'),indent=2)+'\n');assert not r.returncode,r.stderr;print(r.stdout)
