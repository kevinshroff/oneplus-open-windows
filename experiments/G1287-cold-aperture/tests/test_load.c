#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "load_host.h"
#define CopyMem RtlCopyMemory
#define ZeroMem RtlZeroMemory
#define STATIC static
#define UINTN SIZE_T
#include "OpenSha256.h"
#undef CopyMem
#undef ZeroMem
#undef STATIC
#undef UINTN
#include "native_load.inc"
#include "g191_stock_gmu_profile.h"
static BANK_CLIENT bank;static G321_RUNTIME r;static OGO_CONTEXT p;static OAS_BOOTSTRAP a;static TABLES tables;
static _Alignas(4096) uint32_t shared[4096];static uint32_t tcm[2][4096];static uint8_t cache[0x20000];static uint64_t sim_us;static unsigned fullcalls,reads,writes,wordops,inject,clocklost;static uint32_t ao;static int nsrevoked,fatal,armed;static unsigned regreads,reads_at_revoke;
static NTSTATUS FastNs(void*x,void*b,void*f,void*tag,const void*scope){(void)x;(void)b;(void)f;(void)tag;(void)scope;return nsrevoked||fatal||!armed?STATUS_DEVICE_NOT_READY:STATUS_SUCCESS;}
ULONGLONG KeQueryInterruptTimePrecise(ULONGLONG*v){*v=sim_us;return inject==10&&writes?0:sim_us*10;}
NTSTATUS OasCurrentRuntime(OAS_BOOTSTRAP*x){assert(x==&a);fullcalls++;sim_us+=1000;return clocklost||nsrevoked||fatal||!armed?STATUS_DEVICE_NOT_READY:STATUS_SUCCESS;}
NTSTATUS G482CoreRead(G482_BINDING*x,ULONG off,PULONG v){assert(x==&p.Io);regreads++;sim_us++;*v=off==G190_AO_STATUS?ao:off==G190_CM3_RESET?1:0;return STATUS_SUCCESS;}
NTSTATUS G482CoreWrite(G482_BINDING*x,ULONG off,ULONG v){(void)x;(void)off;(void)v;return STATUS_SUCCESS;}
NTSTATUS G482TcmRead(G482_BINDING*x,ULONG reg,ULONG off,PULONG v){assert(x==&p.Io&&(reg==1||reg==3)&&off<=0x3ffc);*v=tcm[reg==3][off/4];return STATUS_SUCCESS;}
NTSTATUS G482TcmWrite(G482_BINDING*x,ULONG reg,ULONG off,ULONG v){assert(x==&p.Io&&(reg==1||reg==3)&&off<=0x3ffc);tcm[reg==3][off/4]=v;return STATUS_SUCCESS;}
static int stopped(void*x,uint64_t s,uint64_t g){(void)x;return s!=1||g!=1;}static int waitfn(void*x,uint32_t us){(void)x;sim_us+=us;return 0;}static int board(void*x){(void)x;return 0;}
static int fw(void*x,uint32_t reg,uint32_t off,uint32_t v){int s=Firmware(x,reg,off,&v,TRUE);if(!s){writes++;wordops++;sim_us+=inject==11?1000000:1;if(writes==1){if(inject==1)p.Revoked=1;if(inject==2)p.Life.Inhibit=1;if(inject==3)p.Hold.Generation++;if(inject==4)clocklost=1;if(inject==5)ao=1;if(inject==7)nsrevoked=1;if(inject==8)fatal=1;if(inject==9)armed=0;reads_at_revoke=regreads;}}return s;}
static int fr(void*x,uint32_t reg,uint32_t off,uint32_t*v){int s=Firmware(x,reg,off,v,FALSE);if(!s){reads++;wordops++;sim_us++;if(inject==6&&reads==1)*v^=1;}return s;}
static void setup(void){memset(&r,0,sizeof(r));memset(&p,0,sizeof(p));memset(&a,0,sizeof(a));memset(&tables,0,sizeof(tables));memset(tcm,0,sizeof(tcm));memset(cache,0,sizeof(cache));sim_us=0;fullcalls=reads=writes=wordops=clocklost=0;ao=0;nsrevoked=fatal=0;armed=1;regreads=reads_at_revoke=0;
 p.Gmu=&r;p.Pdo=(void*)1;p.OperationThread=CurrentThread;p.Started=p.D0=1;p.Io.Pdo=p.Pdo;p.Io.Bound=1;p.Io.MappedMask=31;p.Active=&a;
 p.Hold.Life=&p.Life;p.Hold.Thread=CurrentThread;p.Hold.Generation=1;p.Hold.Serial=p.Hold.Hold.serial=1;p.Hold.ScopeHeld=1;p.Hold.Io=&p.Io;p.Hold.Clock.Bound=1;p.Hold.Clock.Token=7;p.Hold.Hold.reset_mode=1;p.Hold.Hold.state=CGH_RESET_QUIESCENT;p.Hold.Hold.before_halt=8;
 p.Life.Pdo=p.Pdo;p.Life.HeldThread=CurrentThread;p.Life.Generation=1;p.Life.StartObserved=p.Life.OsD0Candidate=1;p.Life.Io=&p.Io;
 bank.Bound=1;bank.Api.CheckNsFast=FastNs;a.Bank=&bank;a.ProviderGeneration=a.Scope.ProviderGeneration=1;a.AllocationGeneration=tables.Generation=1;a.State=OAS_ACTIVE;a.OperationThread=CurrentThread;a.Hold=&p.Hold;a.Scope.Token=8;a.Tables=&tables;a.Native.Tables=&tables;a.BankIndex=2;tables.References=2;tables.Session.Phase=OSMA_ACTIVE;tables.Tables.State=OSMI_BUILT;tables.Tables.PoolOrigin=0x4e435047;tables.Tables.Config.table_physical=0x100000;tables.Session.Image.ttbr0=((uint64_t)2<<48)+0x100000;
 r.Owner.Cookie=&p;r.Io=&p.Io;r.Generation=r.StopSerial=1;r.Prepared=r.Attempted=1;r.Plan.count=1;r.Plan.extent[0]=(g321_extent){0x4000,sizeof(cache),G321_CACHE};r.Buffer[0].Cpu=cache;r.Buffer[0].Mapped=1;
 g190_ops ops={&r,Lease,stopped,Read,Write,Barrier,Now,waitfn,Cancelled,Hash,fw,fr,board};g190_limits limits={65536,10,5000000,500000,500000,3000000};assert(g190_initialize(&r.Core,&ops,&limits,shared,sizeof(shared),0x60000000)==G190_OK);r.Core.epoch=r.Core.generation=r.Core.stop_serial=1;r.Core.phase=G190_STOPPED;
}
int main(int argc,char**argv){assert(argc==2);FILE*f=fopen(argv[1],"rb");assert(f);uint8_t*image=malloc(G191_STOCK_GMU_BYTES);assert(image&&fread(image,1,G191_STOCK_GMU_BYTES,f)==G191_STOCK_GMU_BYTES&&fgetc(f)==EOF);fclose(f);g190_image im={image,G191_STOCK_GMU_BYTES,G191_STOCK_GMU_BLOCKS,{0}};memcpy(im.sha256,G191_STOCK_GMU_SHA256,32);
 unsigned cases=0;inject=0;setup();assert(g190_load_image(&r.Core,1,&im)==G190_OK&&r.Core.phase==G190_LOADED&&writes==(66844-15*16)/4&&reads==writes&&r.Core.reset_released==0);assert(fullcalls<600&&sim_us<5000000);printf("actual image: writes%u reads%u fullchecks%u modeled_us%llu unchangedbudget5000000\n",writes,reads,fullcalls,(unsigned long long)sim_us);cases++;
 for(inject=1;inject<=9;inject++){setup();g190_status s=g190_load_image(&r.Core,1,&im);assert(s!=G190_OK&&r.Core.phase==G190_FAILED&&r.Core.resources_must_retain&&!r.Core.reset_released);if(inject<=3||inject==5||inject>=7)assert(writes==1);if(inject>=7)assert(regreads==reads_at_revoke);if(inject==4)assert(writes==64&&s==G190_LEASE_LOST);if(inject==6)assert(s==G190_FIRMWARE&&reads==1);cases++;}
 inject=0;setup();r.Core.stage=2;r.LoadWordsLeft=65;assert(Lease(&r,1)!=0&&r.LoadWordsLeft==0);cases++;
 setup();r.Core.stage=3;r.LoadWordsLeft=32;unsigned before=fullcalls;assert(Lease(&r,1)==0&&fullcalls==before+1&&r.LoadWordsLeft==0);cases++;
 inject=10;setup();assert(g190_load_image(&r.Core,1,&im)==G190_CLOCK&&writes==1&&!r.Core.reset_released);cases++;
 inject=11;setup();assert(g190_load_image(&r.Core,1,&im)==G190_TIMEOUT&&writes==5&&!r.Core.reset_released);cases++;
 inject=0;setup();r.Core.stage=2;uint32_t val=1;assert(Firmware(&r,1,0,&val,TRUE)==0&&r.LoadWordsLeft==63);before=fullcalls;assert(Firmware(&r,3,0,&val,TRUE)==0&&fullcalls==before+1&&r.LoadWordsLeft==63);cases++;
 before=fullcalls;assert(Firmware(&r,3,4,&val,FALSE)==0&&fullcalls==before+1);cases++;
 before=fullcalls;assert(Barrier(&r,G190_COMPLETE)==0&&fullcalls==before+1&&r.LoadWordsLeft==0);cases++;
 assert(Lease(&r,1)==0&&r.LoadWordsLeft==64);before=fullcalls;assert(Hash(&r,im.bytes,im.size,im.sha256)==0&&fullcalls==before+1&&r.LoadWordsLeft==0);cases++;
 printf("PASS %u actual-native-helper/backend host actor cases; no runtime/WindowsABI/performance claim\n",cases);free(image);return 0;}
