"""Check whether the original SCM formatter conflates the two error identities.

Secure responses, TPL, time, TZ diagnostics and serial callbacks are explicit
model boundaries. Original SCM and formatter instructions remain unchanged.
"""
from pathlib import Path
import argparse,ast,base64,hashlib,json,struct
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_BLOCK
from unicorn.arm64_const import *

w=Path(__file__).resolve().parent
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',required=True,type=Path)
p.add_argument('--runner',type=Path,default=w.parent/'charging-G136/emulate-scm-log.py')
p.add_argument('--scm',type=Path,default=w.parent/'charging-G127/private/ScmDxe-G80.efi')
a=p.parse_args();assert not a.output.exists()
source=a.runner
source_sha=hashlib.sha256(source.read_bytes()).hexdigest()
assert source_sha=='b28cf76794a50bc808e3c40739ce24eba3a79e67f23ef766683309d5920ff497'
raw=a.scm.read_bytes()
digest=hashlib.sha256(raw).hexdigest()
assert digest=='847b3a4cf2a8e46956a081e95d2303a65f47568094c72005db907b544f5a56ab'
SCM,ARENA,STOP=0x51000000,0x30000000,0x10000000
pe=pefile.PE(data=raw);pe.relocate_image(SCM);image=pe.get_memory_mapped_image();mask=(1<<64)-1
regs=[globals()['UC_ARM64_REG_X'+str(i)]for i in range(8)]
saved=[globals()['UC_ARM64_REG_X'+str(i)]for i in range(19,30)]
nodes=[n for n in ast.parse(source.read_text()).body
       if isinstance(n,(ast.ClassDef,ast.FunctionDef))and n.name in ['BudgetStop','run']]
assert len(nodes)==2
env=dict(globals());exec(compile(ast.Module(body=nodes,type_ignores=[]),str(source),'exec'),env)
rows=[]
for code,label in [(0x30003e,'G138-policy-prediction'),(0x300046,'G139-native-decision')]:
    low=(-code)&0xffffffff
    for full,style in [(-code,'sign-extended'),(low,'zero-extended'),
                       (0x1234567800000000|low,'different-upper32')]:
        r=env['run'](label+'-'+style,transport=(full,),service=0)
        assert r['api_return']=='0x8000000000000007' and len(r['log_writes'])==1
        text=base64.b64decode(r['log_writes'][0]['text_base64'],validate=True).decode()
        assert text==f'tz_armv8_smc_call failed, TzStatus = 0x{low:08X},  SmcId = 0x42000202  \r\n'
        r['printed_text']=text;rows.append(r)
assert len({r['printed_text']for r in rows[:3]})==len({r['printed_text']for r in rows[3:]})==1
assert rows[0]['printed_text']!=rows[3]['printed_text']
out={'passed':True,'cases':len(rows),'SCM_sha256':digest,
     'model_source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
     'bound_G136_runner_sha256':source_sha,'original_SCM_and_formatter_unchanged':True,
     'native_operations':0,'transport_rebases_30003e_to_300046_in_these_cases':False,
     'both_errors_map_to_same_generic_EFI_status':True,'upper32_not_recovered_by_printed_line':True,
     'results':rows,'limits':['Model fixtures do not identify the native secure rejection cause.']}
a.output.write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps({k:v for k,v in out.items()if k!='results'},indent=2))
