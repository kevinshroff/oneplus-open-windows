"""Replay actual captured before/transaction/after operations through the core/policy."""
from pathlib import Path
import argparse,json,hashlib,subprocess
p=argparse.ArgumentParser();p.add_argument('--capture',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();o=a.output.resolve();o.mkdir(parents=True,exist_ok=False);w=Path(__file__).resolve().parent
s=r'''
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "g113_policy.h"
static G113_RESULT Saved,Result;static G113_EVENT Events[19000];static G113_POLICY Policy;static unsigned Count,Index;static uint64_t Time;
static int Read(void*x,uint32_t at,uint32_t*v){(void)x;assert(Index<Count);G113_EVENT e=Events[Index++];assert(e.Kind==1&&e.Address==at);int i=G113Controller(at);if(i>=0&&at-G102Controllers[i].Base==0x780)assert(G113ReceiveAllowed(&Policy,(unsigned)i));*v=e.Value;if(i>=0)G113Observed(&Policy,(unsigned)i,at-G102Controllers[i].Base,*v);return 1;}
static int Write(void*x,uint32_t at,uint32_t v){(void)x;assert(Index<Count);G113_EVENT e=Events[Index++];assert(e.Kind==2&&e.Address==at&&e.Value==v);int i=G113Controller(at);assert(i==0&&G113WriteAllowed(&Policy,0,at-G102Controllers[0].Base,v));return 1;}
static int Available(void*x){(void)x;return 1;}
static uint64_t Now(void*x){(void)x;return++Time;}
static void Delay(void*x,uint32_t us){(void)x;assert(us==20);Time+=us;}
static void ProbeEvents(const G102_RESULT*p){assert(p->TraceCount<=1024);for(unsigned i=0;i<p->TraceCount;i++)Events[Count++]=(G113_EVENT){1,p->Trace[i].Address,p->Trace[i].Value,0};}
int main(int argc,char**argv){assert(argc==2);FILE*f=fopen(argv[1],"rb");assert(f&&fseek(f,120,SEEK_SET)==0&&fread(&Saved,sizeof(Saved),1,f)==1&&!fclose(f));assert(!Saved.Code&&!Saved.Uncertain);ProbeEvents(&Saved.Before);for(unsigned i=0;i<Saved.TraceCount;i++)Events[Count++]=Saved.Trace[i];ProbeEvents(&Saved.After);G113_IO io={0,Read,Write,Available,Now,Delay};G113Identify(&io,&Result);assert(Index==Count);Saved.BeginUs=Result.BeginUs;Saved.EndUs=Result.EndUs;Saved.Before.BeginUs=Result.Before.BeginUs;Saved.Before.EndUs=Result.Before.EndUs;Saved.After.BeginUs=Result.After.BeginUs;Saved.After.EndUs=Result.After.EndUs;assert(!memcmp(&Saved,&Result,sizeof(Result)));assert(Policy.Commands==6&&Policy.Completed==6&&!Policy.Active&&!Policy.Held&&!Policy.Faulted);printf("{\"passed\":true,\"events_replayed\":%u,\"all_result_bytes_match_except_six_modeled_time_fields\":true,\"independent_transaction_policy_accepts_capture\":true,\"native_operations\":0}\n",Index);return 0;}
'''
f=o/'replay.c';f.write_text(s);exe=o/'replay';r=subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-O1','-fsanitize=address,undefined','-I',str(w/'probe'),str(f),str(w/'probe/g102_core.c'),str(w/'probe/g113_core.c'),'-o',str(exe)],capture_output=True,text=True);assert not r.returncode,r.stderr;r=subprocess.run([str(exe),str(a.capture.resolve())],capture_output=True,text=True);assert not r.returncode and not r.stderr,(r.stdout,r.stderr);x=json.loads(r.stdout);x['raw_sha256']=hashlib.sha256(a.capture.read_bytes()).hexdigest();(o/'report.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x))
