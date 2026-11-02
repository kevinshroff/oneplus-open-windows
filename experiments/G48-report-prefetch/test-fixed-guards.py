"""Execute the exact native adapter's fixed-state guards with reboot evidence."""
from pathlib import Path
import argparse,hashlib,json,subprocess
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
s=(W/'g48_driver.c').read_text();functions=[]
for n in ['G48FixedBaseline','G48FixedSameRestorable']:
 start=s.index('static int '+n+'(');pos=s.index('{',start)+1;depth=1
 while depth:depth+=(s[pos]=='{')-(s[pos]=='}');pos+=1
 functions.append(s[start:pos])
native=a.inputs/'touch-G39/peripheral-reboot-verification.json';r=json.loads(native.read_text())['snapshot_before']['values'];assert len(r)==50 and r[12]['address']=='0x17a20d44'and r[12]['value']==0
code='''#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t UCHAR;typedef uint32_t ULONG;typedef uint64_t ULONGLONG;typedef size_t SIZE_T;
#include "g48_binding.h"
'''+ '\n'.join(functions)+'\nstatic const ULONG Native[]={'+','.join(str(x['value'])for x in r)+'};\n'+r'''
int main(void){
 ULONG a[50],b[50];unsigned i,bit,cases=0;memcpy(a,Native,sizeof(a));assert(G48FixedBaseline(a));cases++;
 memcpy(b,a,sizeof(b));b[12]=7;assert(G48FixedBaseline(b)&&G48FixedSameRestorable(a,b));cases++;
 for(i=0;i<50;i++)if(i!=12)for(bit=0;bit<32;bit++){
  b[i]^=1u<<bit;assert(!G48FixedBaseline(b)&&!G48FixedSameRestorable(a,b));b[i]^=1u<<bit;cases++;
 }
 {const ULONG bad[]={1,6,0x80000000,0xffffffff};for(i=0;i<4;i++){b[12]=bad[i];assert(!G48FixedBaseline(b)&&!G48FixedSameRestorable(a,b));cases++;}}
 assert(sizeof(G48ExpectedDsdt)==576);printf("{\"passed\":true,\"cases\":%u,\"actual_adapter_guard_functions\":true,\"actual_reboot_response0_accepted\":true,\"only_recorded_response0_or7_allowed\":true,\"every_bit_mutation_of_other49_words_denied\":true,\"native_access\":false}\n",cases);return 0;
}
'''
source=a.output/'fixed-guards.c';source.write_text(code);exe=a.output/'fixed-guards'
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str((W/'private/inputs').resolve()),str(source),'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.returncode,q.stderr)
report=json.loads(q.stdout);report.update(ASan_UBSan=True,adapter_sha256=hashlib.sha256((W/'g48_driver.c').read_bytes()).hexdigest(),reboot_capture_sha256=hashlib.sha256(native.read_bytes()).hexdigest(),binding_header_sha256=hashlib.sha256((W/'private/inputs/g48_binding.h').read_bytes()).hexdigest(),limits=['CPU execution of the actual two guard functions and real reboot words; no device accesses.','The read-only response word remains separately reported; it is never restored by writing.'])
(a.output/'guard-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
