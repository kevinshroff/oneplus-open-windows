from pathlib import Path
import argparse,subprocess,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);w=Path(__file__).resolve().parent;O=a.output.resolve()
c=r'''
#define main sampler_model_main
#include "test-core.c"
#undef main
#include <stddef.h>
typedef uint32_t ULONG;typedef uint64_t ULONGLONG;
#define C_ASSERT(x) _Static_assert(x,#x)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define CTL_CODE(d,f,m,a) (((d)<<16)|((a)<<14)|((f)<<2)|(m))
#define FILE_DEVICE_UNKNOWN 0x22
#define METHOD_BUFFERED 0
#define FILE_READ_ACCESS 1
#define FILE_WRITE_ACCESS 2
#include "g99_protocol.h"
int main(int argc,char**argv){assert(argc==2);G99_CAPTURE*c=calloc(1,sizeof(*c));Model m={0};assert(c);Run(&m,4,&c->Result);assert(!c->Result.Code);c->Status.Size=80;c->Status.Version=1;c->Status.Magic=G99_MAGIC;c->Status.KernelBuild=26300;c->Status.Processors=8;c->Status.FirmwareBytes=576;c->Status.FirmwareMatch=1;c->Status.MapCalls=5;c->Status.Attempts=c->Status.Ready=1;c->Status.Frequency=19200000;c->Nonce=0x1020304050607080ULL;c->Requested=4;c->NativeReads=m.Reads+4*m.Writes;c->NativeWrites=m.Writes;FILE*f=fopen(argv[1],"wb");assert(f&&fwrite(c,sizeof(*c),1,f)==1&&!fclose(f));printf("{\"capture\":%zu,\"core\":%zu,\"core_offset\":%zu,\"sample_offset\":%zu,\"trace_offset\":%zu}\n",sizeof(*c),sizeof(c->Result),offsetof(G99_CAPTURE,Result),offsetof(G99_RESULT,Samples),offsetof(G99_RESULT,Trace));free(c);return 0;}
'''
f=O/'fixture.c';f.write_text(c);exe=O/'fixture';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-I',str(w),str(f),str(w/'g99_core.c'),'-o',str(exe)],capture_output=True,text=True);assert not q.returncode,q.stderr
fixture=O/'model-capture.bin';q=subprocess.run([str(exe),str(fixture)],capture_output=True,text=True);assert not q.returncode,q.stderr;layout=json.loads(q.stdout)
g=r'''package main
import("os";"fmt")
func main(){b,e:=os.ReadFile(os.Args[1]);if e!=nil{panic(e)};nonce:=uint64(0x1020304050607080);v,e:=decodeCapture(b,nonce);if e!=nil{panic(e)};if v["samples"]!=uint32(4)||len(v["raw_transitions"].([]map[string]any))!=4{panic("sample layout")};cases:=1
 for _,at:=range []int{0,4,8,16,20,24,28,32,36,40,44,48,52,80,88,92,96,100,104,104+12,104+16,104+20,104+28,104+32,104+44,168,181,189,196,208,16600,16604,16608,16612,16624}{c:=append([]byte(nil),b...);c[at]^=0xff;if _,e:=decodeCapture(c,nonce);e==nil{panic(fmt.Sprintf("malformed field accepted at%d",at))};cases++}
 for _,n:=range []int{0,1,79,80,104,captureBytes-1}{if _,e:=decodeCapture(b[:n],nonce);e==nil{panic("truncation")};cases++};if _,e:=decodeCapture(b,nonce+1);e==nil{panic("nonce")};cases++
 fmt.Printf("{\"passed\":true,\"cases\":%d,\"actual_C_layout_and_Go_decoder\":true,\"hardware_explicitly_modeled\":true,\"native_operations\":0}\n",cases)}
'''
f=O/'main.go';f.write_text(g);d=O/'g99_decode.go';d.write_bytes((w/'g99_decode.go').read_bytes());exe=O/'decoder';q=subprocess.run(['go','build','-o',str(exe),str(f),str(d)],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe),str(fixture)],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);v=json.loads(q.stdout);v.update(layout=layout,source_sha256={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g99_core.h','g99_core.c','g99_protocol.h','g99_decode.go','test-core.c']});(O/'tests.json').write_text(json.dumps(v,indent=2));print(json.dumps(v))
