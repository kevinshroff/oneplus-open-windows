/* SPDX-License-Identifier: MIT -- replay captured callbacks through actual source. */
#include "g74_protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
typedef struct{const void*Trace;unsigned Count,At,Waits;}Stream;
static int Take(Stream*s,unsigned kind,uint32_t at,uint32_t*value)
{
 G74_RSC_EVENT e;assert(s->At<s->Count);memcpy(&e,(const uint8_t*)s->Trace+s->At++*12,12);
 assert(e.Address==at&&(e.Kind==kind||(kind==1&&e.Kind==3)));
 if(kind==2)assert(e.Value==*value);else *value=e.Value;return e.Kind!=3;
}
static int Read(void*p,uint32_t at,uint32_t*v){return Take(p,1,at,v);}
static int Write(void*p,uint32_t at,uint32_t v){return Take(p,2,at,&v);}
static void Wait(void*p){((Stream*)p)->Waits++;}
static void Observer(const G74_OBS_RESULT*n)
{assert(n->TraceCount<=128);Stream stream={n->Trace,n->TraceCount,0,0};G74_OBS_RESULT r;memset(&r,0,sizeof(r));G74_OBS_IO io={&stream,Read,Write,Wait};G74Observe(&io,&r);assert(stream.At==stream.Count&&!memcmp(&r,n,sizeof(r)));}
typedef struct{const G74_OFF_RESULT*Native;Stream Rsc[12],Obs[3];unsigned Tx,Ob,Guards,Ms,Us;}Core;
static int CoreEvent(void*p,unsigned kind,uint32_t at,uint32_t*v)
{
 Core*c=p;const uint32_t pins[8]={0xf10a000,0xf10a004,0xf118000,0xf118004,0xf119000,0xf119004,0xf119008,0xf11900c};
 if(at>=0xf000000&&at<0x10000000){assert(kind==1&&c->Guards<16&&at==pins[c->Guards%8]);*v=c->Guards<8?c->Native->GuardBefore[c->Guards]:c->Native->GuardAfter[c->Guards-8];c->Guards++;return 1;}
 if(at>=0x17000000&&at<0x18000000){while(c->Tx<c->Native->TxnCount&&c->Rsc[c->Tx].At==c->Rsc[c->Tx].Count)c->Tx++;assert(c->Tx<c->Native->TxnCount);return Take(c->Rsc+c->Tx,kind,at,v);}
 while(c->Ob<c->Native->PmicCount&&c->Obs[c->Ob].At==c->Obs[c->Ob].Count)c->Ob++;assert(c->Ob<c->Native->PmicCount);return Take(c->Obs+c->Ob,kind,at,v);
}
static int CoreRead(void*p,uint32_t at,uint32_t*v){return CoreEvent(p,1,at,v);}
static int CoreWrite(void*p,uint32_t at,uint32_t v){return CoreEvent(p,2,at,&v);}
static void Millisecond(void*p){((Core*)p)->Ms++;}
static void Microsecond(void*p){((Core*)p)->Us++;}
static void Load(const char*path,void*p,size_t n)
{FILE*f=fopen(path,"rb");assert(f&&fread(p,1,n,f)==n&&fgetc(f)==EOF&&!fclose(f));}
int main(int argc,char**argv)
{
 assert(argc==5);G74_RUN*n=calloc(1,sizeof(*n));assert(n);Load(argv[1],n,sizeof(*n));assert(n->Off.TxnCount<=12&&n->Off.PmicCount<=3);unsigned cases=0,events=0,reads=0,writes=0,waits=0;
 for(unsigned i=0;i<n->Off.TxnCount;i++){
  const G74_RSC_RESULT*t=n->Off.Transactions+i;assert(t->TraceCount<=256);Stream stream={t->Trace,t->TraceCount,0,0};G74_RSC_RESULT r;memset(&r,0,sizeof(r));G74_RSC_IO io={&stream,Read,Write,Wait};int mode=t->MsgId==0x108?G74_READ:t->MsgId==0x10108?G74_OFF_ACK:t->MsgId==0x10008?G74_OFF_NO_ACK:-1;assert(mode>=0);
  G74Transfer(&io,&r,t->RequestAddress,t->RequestData,mode);assert(stream.At==stream.Count&&!memcmp(&r,t,sizeof(r)));events+=t->TraceCount;reads+=t->Reads;writes+=t->Writes;waits+=stream.Waits;cases++;
 }
 for(unsigned i=0;i<n->Off.PmicCount;i++){Observer(n->Off.Pmic+i);events+=n->Off.Pmic[i].TraceCount;reads+=n->Off.Pmic[i].Reads;writes+=n->Off.Pmic[i].Writes;cases++;}
 Core c;memset(&c,0,sizeof(c));c.Native=&n->Off;
 for(unsigned i=0;i<n->Off.TxnCount;i++)c.Rsc[i]=(Stream){n->Off.Transactions[i].Trace,n->Off.Transactions[i].TraceCount,0,0};
 for(unsigned i=0;i<n->Off.PmicCount;i++)c.Obs[i]=(Stream){n->Off.Pmic[i].Trace,n->Off.Pmic[i].TraceCount,0,0};
 G74_OFF_RESULT*r=calloc(1,sizeof(*r));assert(r);G74_OFF_IO io={{&c,CoreRead,CoreWrite,Millisecond},{&c,CoreRead,CoreWrite,Microsecond}};G74OffTrial(&io,r);
 for(unsigned i=0;i<n->Off.TxnCount;i++)assert(c.Rsc[i].At==c.Rsc[i].Count);for(unsigned i=0;i<n->Off.PmicCount;i++)assert(c.Obs[i].At==c.Obs[i].Count);
 assert(c.Guards==16&&c.Ms==waits&&c.Ms==n->Off.Waits1ms&&!memcmp(r,&n->Off,sizeof(*r)));cases++;
 for(unsigned i=2;i<=3;i++){G74_PMIC pm;Load(argv[i],&pm,sizeof(pm));Observer(&pm.Observer);cases++;}
 FILE*f=fopen(argv[4],"wbx");assert(f&&fwrite(r,1,sizeof(*r),f)==sizeof(*r)&&!fclose(f));
 printf("{\"passed\":true,\"cases\":%u,\"RSC_transactions\":%u,\"PMIC_observers\":%u,\"whole_core_bytes_identical\":44192,\"core_trace_events\":%u,\"core_reads_including_guards\":%u,\"core_writes\":%u,\"waits_1ms\":%u,\"waits_1us\":%u,\"original_code\":%u,\"original_restore_error\":%u,\"original_restored\":%u,\"native_replay_operations\":0}\n",cases,n->Off.TxnCount,n->Off.PmicCount+2,events,reads+16,writes,c.Ms,c.Us,n->Off.Code,n->Off.RestoreError,n->Off.Restored);free(r);free(n);return 0;
}
