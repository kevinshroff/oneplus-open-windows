from pathlib import Path
import subprocess,hashlib,json
p=Path(__file__).resolve().parents[1];src=(p/'source/native_bootstrap.c').read_text();a=src.index('NTSTATUS OasHandoffOwnedGbif(');b=src.index('NTSTATUS OasLeaveFirmwareScope(',a);body=src[a:b]
shim=r'''
#include <assert.h>
#include <stdio.h>
typedef int NTSTATUS;typedef int BOOLEAN;typedef void*PVOID;
#define STATUS_SUCCESS 0
#define STATUS_INVALID_DEVICE_STATE -1
#define TRUE 1
#define OAS_ACTIVE 3
typedef struct{int consumed,committed;struct{int before_halt,reset_mode;}Hold;}HOLD;
typedef struct{int Native;struct{struct{PVOID Context;}Interface;int(*PromoteRuntime)(PVOID,int*,PVOID,PVOID,void*,int*);}Api;}BANK;
typedef struct{int ColdConsumed,State,Native,Scope;HOLD*Hold;BANK*Bank;PVOID Fault;NTSTATUS Status;}OAS_BOOTSTRAP;
static int witnessStatus,promoteStatus,releaseStatus,commitStatus,currentStatus,step,witnesses,promotes,releases,commits;static OAS_BOOTSTRAP*active;
static NTSTATUS OasCurrentRuntime(OAS_BOOTSTRAP*a){assert(a==active);if(a->ColdConsumed){assert(a->Hold->committed);return currentStatus;}return 0;}
static NTSTATUS OsmaWitnessOwnedBindingHeld(int*n){assert(n==&active->Native);witnesses++;assert(step++==0);return witnessStatus;}
static NTSTATUS promote(PVOID x,int*b,PVOID f,PVOID tag,void*s,int*n){(void)x;(void)b;(void)f;(void)s;assert(tag==active&&n==&active->Native&&!active->ColdConsumed);promotes++;assert(step++==1);return promoteStatus;}
static NTSTATUS CghNativeReleaseToReset(HOLD*h){assert(h==active->Hold&&active->ColdConsumed);releases++;assert(step++==2);return releaseStatus;}
static NTSTATUS CghNativeUnhaltResetForBoot(HOLD*h,PVOID boot){assert(h==active->Hold&&boot==active&&active->ColdConsumed&&h->Hold.reset_mode);releases++;assert(step++==2);return releaseStatus;}
static NTSTATUS CghNativeCommitToBoot(HOLD*h){assert(h==active->Hold&&active->ColdConsumed);commits++;assert(step++==3);if(!commitStatus)h->committed=1;return commitStatus;}
'''
main=r'''
static OAS_BOOTSTRAP setup(HOLD*h,BANK*b){OAS_BOOTSTRAP a={0};a.State=OAS_ACTIVE;a.Hold=h;a.Bank=b;b->Api.PromoteRuntime=promote;step=0;return a;}
int main(void){HOLD h={0};BANK bank={0};OAS_BOOTSTRAP a=setup(&h,&bank);active=&a;
 witnessStatus=-2;assert(OasHandoffOwnedGbif(&a)==-2&&!a.ColdConsumed&&!promotes&&!releases);
 witnessStatus=0;step=0;releaseStatus=-3;assert(OasHandoffOwnedGbif(&a)==-3&&a.ColdConsumed&&releases==1&&!commits);assert(OasHandoffOwnedGbif(&a)==-1&&releases==1);
 a=setup(&h,&bank);active=&a;releaseStatus=0;commitStatus=-4;assert(OasHandoffOwnedGbif(&a)==-4&&a.ColdConsumed&&!h.committed&&commits==1);
 a=setup(&h,&bank);active=&a;commitStatus=0;assert(!OasHandoffOwnedGbif(&a)&&a.ColdConsumed&&h.committed&&step==4);assert(OasHandoffOwnedGbif(&a)==-1);
 a=setup(&h,&bank);active=&a;h.Hold.before_halt=8;h.Hold.reset_mode=1;h.committed=0;assert(!OasHandoffOwnedGbif(&a)&&a.ColdConsumed&&h.committed&&step==4);
 a=setup(&h,&bank);active=&a;h.Hold.reset_mode=0;assert(OasHandoffOwnedGbif(&a)==-1&&!a.ColdConsumed);
 puts("{\"cases\":6,\"result\":\"pass\",\"native\":false}");return 0;}
'''
(p/'build/test_handoff.c').write_text(shim+body+main);args=['clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-sanitize-recover=all',str(p/'build/test_handoff.c'),'-o',str(p/'build/test_handoff')]
r=subprocess.run(args,capture_output=True,text=True);assert not r.returncode,r.stderr
r=subprocess.run([str(p/'build/test_handoff')],capture_output=True,text=True);(p/'evidence/HANDOFF-TESTS.json').write_text(json.dumps(dict(argv=args,exit=r.returncode,stdout=r.stdout,stderr=r.stderr,production_body_sha256=hashlib.sha256(body.encode()).hexdigest(),scope='actual production owned-handoff body; modeled child failures only: witness refusal, uncertain release/retry refusal, commit failure, exact successful ordering. Not hardware/ABI/proof success'),indent=2)+'\n');assert not r.returncode,r.stderr;print(r.stdout)
