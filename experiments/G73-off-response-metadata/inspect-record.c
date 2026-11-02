/* SPDX-License-Identifier: MIT -- offline packet inspection; no hardware. */
#include "g73_client_policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
static void Status(const G73_STATUS*s)
{
 printf("\"status\":{\"build\":%u,\"processors\":%u,\"irql\":%u,\"firmware_bytes\":%u,\"firmware_match\":%u,\"firmware_status\":%u,\"map_calls\":%u,\"run_attempts\":%u,\"observer_captures\":%u,\"observer_fault\":%u,\"off_verified\":%u,\"sequence\":%" PRIu64 "}",s->KernelBuild,s->Processors,s->CurrentIrql,s->FirmwareBytes,s->FirmwareMatch,s->FirmwareStatus,s->MapCalls,s->RunAttempts,s->ObserverCaptures,s->ObserverFault,s->OffPmicVerified,s->Sequence);
}
static void Words(const uint32_t*v,unsigned count)
{putchar('[');for(unsigned i=0;i<count;i++)printf("%s%u",i?",":"",v[i]);putchar(']');}
static void Bytes(const uint8_t*v,unsigned count)
{putchar('[');for(unsigned i=0;i<count;i++)printf("%s%u",i?",":"",v[i]);putchar(']');}
static void Observer(const G73_OBS_RESULT*p)
{
 printf("{\"code\":%u,\"stage\":%u,\"status\":%u,\"reads\":%u,\"writes\":%u,\"polls\":%u,\"commands\":%u,\"trace_count\":%u,\"configuration\":",p->Code,p->Stage,p->Status,p->Reads,p->Writes,p->Polls,p->Commands,p->TraceCount);Bytes(p->Configuration,8);printf(",\"completion\":");Words(p->Completion,5);putchar('}');
}
int main(int argc,char**argv)
{
 assert(argc==5);union{G73_STATUS Status;G73_SNAPSHOT Snapshot;G73_PMIC Pmic;G73_RUN Run;}r;memset(&r,0,sizeof(r));uint32_t expected[50];FILE*f=fopen(argv[3],"rb");assert(f&&fread(expected,4,50,f)==50&&fgetc(f)==EOF&&!fclose(f));
 assert(strlen(argv[4])==32);for(unsigned i=0;i<32;i++)assert((argv[4][i]>='0'&&argv[4][i]<='9')||(argv[4][i]>='a'&&argv[4][i]<='f'));uint64_t nonce=strtoull(argv[4]+16,NULL,16);assert(nonce);
 unsigned mode;for(mode=0;mode<5;mode++)if(!strcmp(argv[1],G73ClientMode(mode)))break;assert(mode<5);
 size_t n=mode==0?sizeof(G73_STATUS):mode==1?sizeof(G73_SNAPSHOT):mode==2?sizeof(G73_PMIC):sizeof(G73_RUN);
 f=fopen(argv[2],"rb");assert(f&&fread(&r,1,n,f)==n&&fgetc(f)==EOF&&!fclose(f));
 int qualified=mode==0?G73ClientStatus(&r.Status):mode==1?G73ClientSnapshot(&r.Snapshot,expected):mode==2?G73ClientPmic(&r.Pmic):G73ClientRun(&r.Run,expected,nonce);
 printf("{\"qualified\":%s,\"bytes\":%zu,",qualified?"true":"false",n);Status(&r.Status);
 if(mode==0)printf(",\"ready\":%s",G73ClientReady(&r.Status)?"true":"false");
 else if(mode==1){printf(",\"count\":%u,\"values\":",r.Snapshot.Count);Words(r.Snapshot.Values,50);}
 else if(mode==2){printf(",\"attempt\":%u,\"fixed_registers_unchanged\":%u,\"elapsed_ticks\":%" PRIu64 ",\"counter_frequency\":%" PRIu64 ",\"observer\":",r.Pmic.Attempt,r.Pmic.FixedRegistersUnchanged,r.Pmic.ElapsedTicks,r.Pmic.CounterFrequency);Observer(&r.Pmic.Observer);}
 else{
  const G73_RUN*p=&r.Run;const G73_OFF_RESULT*o=&p->Off;
  printf(",\"nonce\":\"%016" PRIx64 "\",\"baseline_valid\":%u,\"fixed_registers_unchanged\":%u,\"elapsed_ticks\":%" PRIu64 ",\"counter_frequency\":%" PRIu64 ",\"before\":",p->Nonce,p->BaselineValid,p->FixedRegistersUnchanged,p->ElapsedTicks,p->CounterFrequency);Words(p->Before,50);printf(",\"after\":");Words(p->After,50);
  printf(",\"off\":{\"code\":%u,\"restore_error\":%u,\"restored\":%u,\"stage\":%u,\"transactions\":%u,\"pmic_count\":%u,\"preflight_verified\":%u,\"flip_attempted\":%u,\"restore_attempted\":%u,\"flip_verified\":%u,\"original_verified\":%u,\"rsc_uncertain\":%u,\"observer_uncertain\":%u,\"off_verified\":%u,\"ack_raw\":%u,\"noack_raw\":%u,\"waits_1ms\":%u,\"last_off_write_transaction\":%u,\"last_off_observe_transaction\":%u,\"client_before\":",o->Code,o->RestoreError,o->Restored,o->Stage,o->TxnCount,o->PmicCount,o->PreflightVerified,o->FlipAttempted,o->RestoreAttempted,o->FlipVerified,o->OriginalVerified,o->RscUncertain,o->ObserverUncertain,o->OffVerified,o->AckRaw,o->NoAckRaw,o->Waits1ms,o->LastOffWriteTxn,o->LastOffObserveTxn);Words(o->ClientBefore,3);printf(",\"client_after\":");Words(o->ClientAfter,3);printf(",\"transaction_results\":[");
  for(unsigned i=0;i<o->TxnCount&&i<12;i++){const G73_RSC_RESULT*t=o->Transactions+i;printf("%s{\"code\":%u,\"restore_error\":%u,\"restored\":%u,\"stage\":%u,\"address\":%u,\"data\":%u,\"msgid\":%u,\"response\":%u,\"completion\":%u,\"reads\":%u,\"writes\":%u,\"trace_count\":%u,\"triggered\":%u}",i?",":"",t->Code,t->RestoreError,t->Restored,t->Stage,t->RequestAddress,t->RequestData,t->MsgId,t->Response,t->Completion,t->Reads,t->Writes,t->TraceCount,t->Triggered);}
  printf("],\"pmic_results\":[");for(unsigned i=0;i<o->PmicCount&&i<3;i++){if(i)putchar(',');Observer(o->Pmic+i);}printf("]}");
 }
 printf("}\n");return 0;
}
