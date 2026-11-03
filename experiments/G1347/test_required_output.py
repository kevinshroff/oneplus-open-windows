#!/usr/bin/env python3
"""Host-only required-output regression using the actual two source functions."""
from pathlib import Path
import hashlib,json,re,subprocess,tempfile
W=Path(__file__).resolve().parent;m=json.loads((W/'BASE-AND-DELTA.json').read_text());new=(W/'overlay'/m['changed_source']).read_text();old=(W.parent/'G1345/overlay'/m['changed_source']).read_text()
assert hashlib.sha256(old.encode()).hexdigest()==m['base_sha256'] and hashlib.sha256(new.encode()).hexdigest()==m['variant_sha256']
assert old.count(m['exact_old'])==1 and new==old.replace(m['exact_old'],m['exact_new'])
source='''#include <stdint.h>
#include <stddef.h>
#include <assert.h>
typedef unsigned long long ULONGLONG;
#define UNREFERENCED_PARAMETER(x) (void)(x)
static unsigned valid,invalid;
static uint64_t KeQueryInterruptTimePrecise(ULONGLONG *out){if(!out){invalid++;return 0;}*out=0xabcdef;valid++;return 1234560;}
'''+m['exact_old'].replace('QtbNow','OldQtbNow')+'\n'+m['exact_new']+'''
int main(void){assert(OldQtbNow(NULL)==0&&invalid==1&&valid==0);assert(QtbNow(NULL)==123456&&valid==1&&invalid==1);return 0;}
'''
with tempfile.TemporaryDirectory(prefix='qtb-output-')as tmp:
 p=Path(tmp);(p/'test.c').write_text(source);subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p/'test.c'),'-o',str(p/'test')],check=True);subprocess.run([str(p/'test')],check=True)
print('PASS: old null argument detected; fixed function supplies writable output and preserves100ns/10. No kernel/target call.')
