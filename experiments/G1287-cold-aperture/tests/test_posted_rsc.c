/* Actual board/backend bodies with host service actors, not hardware proof. */
#include <assert.h>
#include <stdio.h>
#include "g321_runtime_test.h"
static G321_RUNTIME r;static uint32_t mem[5][0x30000/4];static unsigned seq,pdcfirst,rsclast,hfiinit,barriers,leasefail,badwrite,configwrites,mismatchat,readfailat,writefailat,leaseafter;static uint64_t timeus;
static _Alignas(4096) uint32_t shared[G190_HFI_BYTES/4];
NTSTATUS OgoGmuCurrent(G321_RUNTIME*x){assert(x==&r);return leasefail||(leaseafter&&configwrites>=leaseafter)?STATUS_DEVICE_NOT_READY:STATUS_SUCCESS;}
NTSTATUS OgoGmuHandoff(G321_RUNTIME*x){assert(x==&r);return STATUS_SUCCESS;}
static NTSTATUS bread(unsigned b,ULONG o,PULONG v){assert(b<5&&o<sizeof(mem[0])&&!(o&3));if((b==2||b==3)&&configwrites){if(readfailat==configwrites)return STATUS_DEVICE_NOT_READY;*v=mem[b][o/4];if(mismatchat==configwrites)*v^=0x82204514u;return STATUS_SUCCESS;}*v=mem[b][o/4];return STATUS_SUCCESS;}
static NTSTATUS bwrite(unsigned b,ULONG o,ULONG v){assert(b<5&&o<sizeof(mem[0])&&!(o&3));seq++;if(b==2||b==3){configwrites++;if(writefailat==configwrites)return STATUS_DEVICE_NOT_READY;}if(b==3&&!pdcfirst)pdcfirst=seq;if(b==2)rsclast=seq;if(b==0&&o==G190_HFI_INIT){assert(v==1);hfiinit=seq;}mem[b][o/4]=badwrite?v^1:v;return STATUS_SUCCESS;}
#define BANK(n,b) NTSTATUS G482##n##Read(G482_BINDING*x,ULONG o,PULONG v){(void)x;return bread(b,o,v);}NTSTATUS G482##n##Write(G482_BINDING*x,ULONG o,ULONG v){(void)x;return bwrite(b,o,v);}
BANK(Core,0) BANK(Cx,1) BANK(Rsc,2) BANK(Pdc,3)
NTSTATUS G482GpuRead(G482_BINDING*x,ULONG o,PULONG v){(void)x;return bread(4,o,v);}
static int lease(void*x,uint64_t g){(void)x;return g!=1||leasefail;}static int stopped(void*x,uint64_t s,uint64_t g){(void)x;return s!=1||g!=1;}
static int rd(void*x,uint32_t o,uint32_t*v){(void)x;return bread(0,o,v)!=STATUS_SUCCESS;}static int wr(void*x,uint32_t o,uint32_t v){(void)x;return bwrite(0,o,v)!=STATUS_SUCCESS;}static int bar(void*x,g190_barrier k){(void)x;(void)k;barriers++;return 0;}static int now(void*x,uint64_t*v){(void)x;*v=++timeus;return 0;}static int waitfn(void*x,uint32_t u){(void)x;timeus+=u;return 0;}static int zero(void*x){(void)x;return 0;}static int hash(void*x,const uint8_t*d,size_t n,const uint8_t e[32]){(void)x;(void)d;(void)n;(void)e;return 0;}static int fw(void*x,uint32_t a,uint32_t o,uint32_t v){(void)x;(void)a;(void)o;(void)v;return 0;}static int fr(void*x,uint32_t a,uint32_t o,uint32_t*v){(void)x;(void)a;(void)o;*v=0;return 0;}
static void setup(unsigned ready){memset(&r,0,sizeof(r));memset(mem,0,sizeof(mem));memset(shared,0,sizeof(shared));seq=pdcfirst=rsclast=hfiinit=barriers=leasefail=badwrite=configwrites=mismatchat=readfailat=writefailat=leaseafter=0;timeus=0;r.Generation=1;g190_ops ops={0,lease,stopped,rd,wr,bar,now,waitfn,zero,hash,fw,fr,zero};g190_limits lim={100,10,5000000,500000,500000,3000000};assert(g190_initialize(&r.Core,&ops,&lim,shared,sizeof(shared),0x60000000)==G190_OK);r.Core.epoch=1;r.Core.generation=1;r.Core.phase=G190_FW_READY;r.Core.reset_released=1;r.Core.firmware_version=0x40010009;r.Core.stage=5;r.BoardAdmitted=TRUE;r.Board.CoreConfigured=TRUE;r.Board.Retained=TRUE;r.Board.Stage=2;mem[0][G190_FW_RESULT/4]=0x100;mem[0][G190_HFI_STATUS/4]=ready;}
static void failed(NTSTATUS expected){assert(G482ConfigureFirmwareReady(&r)==expected);assert(!r.Board.FirmwareConfigured&&r.Board.Retained&&r.Core.phase==G190_FW_READY&&!hfiinit);}
int main(void){unsigned cases=0;for(unsigned bit=0;bit<2;bit++){setup(bit);assert(G482ConfigureFirmwareReady(&r)==STATUS_SUCCESS);assert(r.Board.Stage==4&&r.Board.FirmwareConfigured&&r.Core.phase==G190_BOARD_READY);assert(pdcfirst&&rsclast>pdcfirst&&!hfiinit);assert(r.Board.Access[2].Offset==G190_HFI_STATUS&&r.Board.Access[2].Value==bit);if(!bit)mem[0][G190_HFI_STATUS/4]=1;assert(g190_start_hfi(&r.Core,1)==G190_OK&&r.Core.phase==G190_HFI_READY);assert(hfiinit>rsclast&&barriers);cases++;}
 setup(1);mem[2][0x404/4]=1;failed(STATUS_DEVICE_BUSY);assert(!pdcfirst);cases++;
 setup(1);mem[0][G190_CM3_RESET/4]=1;failed(STATUS_DEVICE_BUSY);assert(!pdcfirst);cases++;
 setup(1);mem[0][G190_FW_RESULT/4]=0;failed(STATUS_DEVICE_NOT_READY);assert(!pdcfirst);cases++;
 /* Every one of the19 bounded posted registers may return a differing
  * observed value: exact write intent + both records still mandatory. */
 for(unsigned n=1;n<=19;n++){setup(1);mismatchat=n;assert(G482ConfigureFirmwareReady(&r)==STATUS_SUCCESS&&r.Board.FirmwareConfigured&&configwrites==19);assert(r.Board.Retained&&!hfiinit);unsigned index=4+2*(n-1);assert(r.Board.Access[index].Operation==1&&r.Board.Access[index+1].Operation==0);assert(r.Board.Access[index+1].Value==(r.Board.Access[index].Value^0x82204514u));cases++;}
 for(unsigned n=1;n<=19;n++){setup(1);readfailat=n;failed(STATUS_DEVICE_NOT_READY);assert(configwrites==n&&r.Board.Access[r.Board.Count-1].Status==STATUS_DEVICE_NOT_READY);cases++;}
 for(unsigned n=1;n<=19;n++){setup(1);writefailat=n;failed(STATUS_DEVICE_NOT_READY);assert(configwrites==n&&r.Board.Access[r.Board.Count-1].Operation==1&&r.Board.Access[r.Board.Count-1].Status==STATUS_DEVICE_NOT_READY);cases++;}
 for(unsigned n=1;n<=19;n++){setup(1);leaseafter=n;failed(STATUS_DEVICE_NOT_READY);assert(configwrites==n&&r.Board.Access[r.Board.Count-1].Operation==1);cases++;}
 /* A readback mismatch in pre-reset core controls still fails Set(). */
 setup(0);r.Core.phase=G190_LOADED;r.Core.reset_released=0;r.Board.Stage=1;r.Board.CoreConfigured=FALSE;mem[0][G190_CM3_RESET/4]=1;r.Plan.log_index=0;r.Plan.extent[0].iova=0x60004000;r.Plan.extent[0].bytes=0x4000;badwrite=1;assert(G482ConfigureCore(&r)==STATUS_DEVICE_DATA_ERROR&&!r.Board.CoreConfigured&&r.Board.Retained&&!pdcfirst);cases++;
 setup(1);leasefail=1;failed(STATUS_DEVICE_NOT_READY);assert(!pdcfirst&&!r.Board.Count);cases++;
 setup(1);r.Board.Attempted=FALSE;r.Board.Stage=0;mem[0][G190_CM3_RESET/4]=1;assert(G482ColdPreflight(&r)==STATUS_DEVICE_BUSY&&r.Board.Stage==1);assert(r.Board.Access[1].Offset==G190_HFI_STATUS&&!pdcfirst);cases++;
 setup(0);assert(G482ConfigureFirmwareReady(&r)==STATUS_SUCCESS);assert(g190_start_hfi(&r.Core,1)==G190_TIMEOUT&&hfiinit>rsclast&&r.Core.phase==G190_FAILED);cases++;
 printf("PASS %u focused actual board/backend actor cases; each19 posted mismatches accepted+journaled, each19 read/write/lease failures retained, cold Set echo unchanged, real PDC-RSC-INIT1/poll1 order; host-only\n",cases);return 0;}
