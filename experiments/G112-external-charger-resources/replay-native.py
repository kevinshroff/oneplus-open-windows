"""Replay the finite native core trace locally; no hardware is accessed."""
from pathlib import Path
import argparse,json,hashlib,subprocess
p=argparse.ArgumentParser();p.add_argument('--capture',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False);w=Path(__file__).resolve().parent
s=r'''
#include <stdint.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "g112_core.h"
static unsigned Index;static uint64_t Time;static G112_RESULT Saved,Result;
static int Read(void*x,uint32_t at,uint32_t*v){(void)x;assert(Index<Saved.TraceCount);assert(Saved.Trace[Index].Address==at);*v=Saved.Trace[Index++].Value;return 1;}
static int Available(void*x){(void)x;return 1;}
static uint64_t Now(void*x){(void)x;return++Time;}
int main(int argc,char**argv){assert(argc==2);FILE*f=fopen(argv[1],"rb");assert(f&&fseek(f,104,SEEK_SET)==0&&fread(&Saved,sizeof(Saved),1,f)==1&&!fclose(f));G112_IO io={0,Read,Available,Now};G112Probe(&io,&Result);assert(Index==Saved.TraceCount);Saved.BeginUs=Result.BeginUs;Saved.EndUs=Result.EndUs;assert(!memcmp(&Saved,&Result,sizeof(Result)));printf("{\"passed\":true,\"events_replayed\":%u,\"all_result_bytes_match_except_modeled_times\":true,\"native_operations\":0}\n",Index);return 0;}
'''
f=a.output/'replay.c';f.write_text(s);exe=a.output.resolve()/'replay';r=subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-O1','-fsanitize=address,undefined','-I',str(w/'probe'),str(f),str(w/'probe/g112_core.c'),'-o',str(exe)],capture_output=True,text=True);assert not r.returncode,r.stderr;r=subprocess.run([str(exe),str(a.capture.resolve())],capture_output=True,text=True);assert not r.returncode and not r.stderr,(r.stdout,r.stderr);x=json.loads(r.stdout);x['raw_sha256']=hashlib.sha256(a.capture.read_bytes()).hexdigest();(a.output/'report.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x))
