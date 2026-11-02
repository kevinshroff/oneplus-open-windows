"""Validate the static claims against saved REA assembly, not pseudocode alone.

This is an evidence consistency check, not native CPU or firmware execution.
"""
from pathlib import Path
import hashlib,json,re
w=Path(__file__).resolve().parent;p=w/'private';load=lambda n:json.loads((p/n).read_text());sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
digest='669bdfd46da11481ba7de43bc7e3ab49202d8e3f2ac7beb61fdb91c0a34d9518'
assert sha(p/'view/BatteryStatusConsumers.elf')==digest
def ev(n,addr):
 v=load(n);assert v['subject']['digest']['sha256']==digest and v['parameters']['procedure']==addr
 return v
ping=ev('REA-assembly-check-0.json','0x6009abb0');noop=ev('REA-assembly-check-1.json','0x600b8410');wrapper=ev('REA-recovery-enable-wrapper.json','0x6009ab40')
a=ping['normalized_result']['assembly'];b=noop['normalized_result']['assembly']
at=lambda lines,address:next(x.split(': ',1)[1]for x in lines if x.startswith(address+':'))
want={'0x6009ac1c':'memb R2, (FP+#-0x1c)', '0x6009ac20':'cmp.eq P0, R2, #0x7', '0x6009ac34':'cmp.eq P0, R2, #0x0', '0x6009ac44':'assign R1, #0x0', '0x6009ac48':'call 0x6009ab40', '0x6009ac54':'assign R1, #0x1', '0x6009ac58':'call 0x6009ab40'}
for address,text in want.items():assert at(a,address).startswith(text),(address,at(a,address))
assert at(b,'0x600b8430').startswith('memub R2, (FP+#-0x3)')
assert at(b,'0x600b8434').startswith('cmp.gt P0, R2, #0xa')
assert at(b,'0x600b8588').startswith('memh (R2), #0x0')
calls=[int(re.search(r'call (0x[0-9a-f]+)',s)[1],16)for s in b if re.search(r'call (0x[0-9a-f]+)',s)]
assert set(calls)=={0x60005bc8,0x60007c38}and len(calls)==4
assert any('call 0x600b8410'in s for s in wrapper['normalized_result']['assembly'])
assert not any('callr'in s or 'jumpr'in s for s in b)
result={'campaign':'G176','view_sha256':digest,'checks_passed':True,'checks':{'status7_and_nonzero_enable_branch':'Original scalar comparisons and branch sites verified; see retained REA assembly.','recovery_arguments':'Immediate R1=0 and R1=1 before two calls to6009ab40.','recovery_wrapper':'6009ab40 calls600b8410.','internal_setter':'Unsigned chip argument checked against10; valid branch returns0; only four direct logging calls at two targets; no callback dispatch.'},'evidence':{n:load(n)['evidence_id']for n in ['REA-assembly-check-0.json','REA-assembly-check-1.json','REA-recovery-enable-wrapper.json','REA-platform4-hw-ping.json','REA-platform4-get.json','REA-platform-selector.json','REA-read-array-helper.json','REA-DAL-read-adapter.json']},'limits':['Static compiled observations; actual live platform/state/callback selection remains unobserved.','No native firmware function invocation or instruction emulation is performed by this checker.','An AP0->1 test is motivated by this evidence, not proof that it will start charging.','The two original internal recovery calls have no5s gap or90s timer. Those are bounded experiment safeguards, not reconstructed original behavior.'],'native_operations':0}
(p/'compiled-contract-validation.json').write_text(json.dumps(result,indent=2)+'\n');print({'checks_passed':True,'direct_noop_callees':len(calls),'native_operations':0})
