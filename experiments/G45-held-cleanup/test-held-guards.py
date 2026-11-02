"""Execute the actual native held-state matcher, including all one-bit faults."""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
p=argparse.ArgumentParser();p.add_argument('--binding',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent;s=(W/'g45_driver.c').read_text()
m=re.search(r'^static int G45HeldMatches\(',s,re.M);assert m;i=s.index('{',m.end())+1;depth=1
while depth:depth+=(s[i]=='{')-(s[i]=='}');i+=1
function=s[m.start():i]
body='''#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
typedef uint32_t ULONG;typedef uint8_t UCHAR;typedef uint64_t ULONGLONG;typedef size_t SIZE_T;
#include "g45_binding.h"
#include "g45_recovery_binding.h"
'''+function+'''
int main(void){ULONG v[50];unsigned i,bit,a,b,cases=0;
 for(a=0;a<2;a++)for(b=0;b<2;b++){memcpy(v,G45HeldValues,sizeof(v));v[47]=(v[47]&~1u)|a;v[49]=(v[49]&~1u)|b;assert(G45HeldMatches(v));cases++;}
 for(i=0;i<50;i++)for(bit=0;bit<32;bit++){
  memcpy(v,G45HeldValues,sizeof(v));v[i]^=1u<<bit;
  assert(G45HeldMatches(v)==((i==47||i==49)&&bit==0));cases++;
 }
 assert(!G45HeldMatches(G45ExpectedValues));cases++;
 printf("{\\"passed\\":true,\\"cases\\":%u}\\n",cases);return 0;
}
'''
source=a.output/'guards.c';source.write_text(body);exe=a.output/'guards'
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(a.binding.resolve()),str(source),'-o',str(exe.resolve())],capture_output=True,text=True);assert not q.returncode,q.stderr
q=subprocess.run([str(exe.resolve())],capture_output=True,text=True);assert not q.returncode and not q.stderr,(q.returncode,q.stdout,q.stderr)
r=json.loads(q.stdout);r.update(actual_native_function_executed_unchanged=True,ASan_UBSan=True,only_IRQ25_input_and_owned_pending_bit0_may_vary=True,ownership_output_configuration_and_other48_words_exact=True,adapter_sha256=hashlib.sha256((W/'g45_driver.c').read_bytes()).hexdigest(),binding_sha256=hashlib.sha256((a.binding/'g45_recovery_binding.h').read_bytes()).hexdigest(),native_access=False)
(a.output/'tests.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
