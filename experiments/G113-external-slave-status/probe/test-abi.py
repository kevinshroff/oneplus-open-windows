from pathlib import Path
import argparse,subprocess,json,hashlib
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();o=a.output.resolve();assert not o.exists();o.mkdir(parents=True);w=Path(__file__).resolve().parent
c=r'''
#define main original_core_main
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
#include "g113_protocol.h"
int main(int argc,char**argv){assert(argc==2);Model*m=calloc(1,sizeof(*m));G113_CAPTURE*c=calloc(1,sizeof(*c));assert(m&&c);Reset(m);Run(m,&c->Result);assert(!c->Result.Code);c->Status.Size=80;c->Status.Version=1;c->Status.Magic=G113_MAGIC;c->Status.KernelBuild=26300;c->Status.Processors=8;c->Status.FirmwareBytes=576;c->Status.FirmwareMatch=1;c->Status.MapCalls=7;c->Status.Attempts=c->Status.Ready=1;c->Status.Frequency=19200000;c->Nonce=0x1020304050607080ULL;c->NativeReads=714+c->Result.Reads+10*(74+c->Result.Reads+c->Result.Writes);c->NativeWrites=c->Result.Writes;c->MapCalls=7;c->PolicyCommands=c->PolicyCompleted=6;FILE*f=fopen(argv[1],"wb");assert(f&&fwrite(c,sizeof(*c),1,f)==1&&!fclose(f));printf("{\"capture\":%zu,\"core\":%zu,\"result_offset\":%zu,\"trace_offset\":%zu}\n",sizeof(*c),sizeof(c->Result),offsetof(G113_CAPTURE,Result),offsetof(G113_CAPTURE,Result)+offsetof(G113_RESULT,Trace));free(m);free(c);}
'''
f=o/'fixture.c';f.write_text(c);exe=o/'fixture';q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-I',str(w),str(f),str(w/'g102_core.c'),str(w/'g113_core.c'),'-o',str(exe)],capture_output=True,text=True);assert not q.returncode,q.stderr
fixture=o/'fixture.bin';q=subprocess.run([str(exe),str(fixture)],capture_output=True,text=True);assert not q.returncode,q.stderr;layout=json.loads(q.stdout)
g=r'''package main
import("os";"fmt")
func main(){b,e:=os.ReadFile(os.Args[1]);if e!=nil{panic(e)};nonce:=uint64(0x1020304050607080);v,e:=decodeCapture(b,nonce);if e!=nil{panic(e)};if v["commands"]!=uint32(6)||v["query_mask"]!=uint32(7){panic("fixture")};cases:=1
for _,at:=range []int{0,4,8,16,20,24,28,32,36,40,44,48,52,80,88,92,96,100,104,108,112,116,120,124,128,132,136,140,144,148,152,156,160,164,168,172,176,180,202,280,284,300,9008,17736,17740}{c:=append([]byte(nil),b...);c[at]^=0xff;if _,e:=decodeCapture(c,nonce);e==nil{panic(fmt.Sprintf("mutation accepted at%d",at))};cases++}
for _,n:=range []int{0,1,79,80,120,captureBytes-1}{if _,e:=decodeCapture(b[:n],nonce);e==nil{panic("truncation")};cases++};if _,e:=decodeCapture(b,nonce+1);e==nil{panic("nonce")};cases++
failed:=append([]byte(nil),b...);le.PutUint32(failed[124:],8);le.PutUint32(failed[176:],1);le.PutUint32(failed[52:],1);for i:=9008;i<17736;i++{failed[i]=0};if _,e:=decodeCapture(failed,nonce);e!=nil{panic(e)};cases++
row:=v["external_charger"].(map[string]any);if row["telemetry_usable"]!=true||row["charge_enable_bit7"]!=false{panic("external charger semantics")};cases++
partial,e:=decodeCapture(failed,nonce);if e!=nil{panic(e)};failedRow:=partial["external_charger"].(map[string]any);if failedRow["telemetry_usable"]!=false{panic("failed telemetry")};if _,ok:=failedRow["charge_enable_bit7"];ok{panic("failed charge flag leaked")};cases++
fmt.Printf("{\"passed\":true,\"cases\":%d,\"actual_C_layout_and_Go_decoder\":true,\"hardware_explicitly_modeled\":true,\"native_operations\":0}\n",cases)}
'''
f=o/'main.go';f.write_text(g);d=o/'g113_decode.go';d.write_bytes((w/'g113_decode.go').read_bytes());exe=o/'decoder';q=subprocess.run(['go','build','-o',str(exe),str(f),str(d)],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe),str(fixture)],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.stdout,q.stderr);r=json.loads(q.stdout);r['layout']=layout;r['source_sha256']={n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['g113_protocol.h','g113_core.h','g113_decode.go']};(o/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
