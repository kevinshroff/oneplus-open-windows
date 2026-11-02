"""Execute unchanged pinned stock SPMI functions against an explicit MMIO model.

This establishes source access order/formulas, not native MMIO permissions.
Generated original source, binaries and command outputs stay in a new output dir.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--source',required=True,type=Path)
p.add_argument('--output',required=True,type=Path)
a=p.parse_args();a.output=a.output.resolve();a.output.mkdir(parents=True,exist_ok=False)
raw=a.source.read_bytes();digest=hashlib.sha256(raw).hexdigest()
assert digest=='6c7c31ed1b96093b5c6780640710bb5f30a992471b2b12d3390757cf4f662a6d'
source=raw.decode();parts=[];records=[]
def take(name,pattern):
    matches=list(re.finditer(pattern,source,re.M));assert len(matches)==1,name
    start=matches[0].start();brace=source.index('{',matches[0].end()-1)
    depth=1;end=brace+1
    while depth:
        if source[end]=='{':depth+=1
        elif source[end]=='}':depth-=1
        end+=1
    if source[start:start+4]=='enum':end=source.index(';',end)+1
    text=source[start:end];parts.append(text)
    records.append({'name':name,'source_offset':start,'bytes':len(text.encode()),'sha256':hashlib.sha256(text.encode()).hexdigest()})
for name in ['pmic_arb_chnl_status','pmic_arb_cmd_op_code','pmic_arb_channel']:
    take(name,r'^enum '+name+r'\s*\{')
for name in ['PMIC_ARB_CMD','PMIC_ARB_STATUS','PMIC_ARB_WDATA0','PMIC_ARB_WDATA1','PMIC_ARB_RDATA0','PMIC_ARB_RDATA1','PMIC_ARB_TIMEOUT_US','PMIC_ARB_MAX_TRANS_BYTES']:
    match=re.findall(r'^#define '+name+r'\s+[^\n]+',source,re.M);assert len(match)==1
    parts.append(match[0])
parts.append((Path(__file__).parent/'stock-spmi-model.h').read_text())
for name in ['pmic_arb_offset_v7','pmic_arb_fmt_cmd_v2','pmic_arb_base_write','pmic_arb_set_rd_cmd','pmic_arb_write_data','pmic_arb_read_data','pmic_arb_wait_for_done','pmic_arb_write_cmd','pmic_arb_read_cmd']:
    take(name,r'^static (?:inline )?(?:int|u32|void)\s+'+name+r'\s*\(')
(a.output/'stock-spmi.inc').write_text('\n\n'.join(parts)+'\n')
cmd=['clang','-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
     '-fsanitize=address,undefined','-fno-omit-frame-pointer','-g',
     '-I'+str(a.output),str(Path(__file__).parent/'test-stock-spmi.c'),
     '-o',str(a.output/'test-stock-spmi')]
logs=[]
for argv in [cmd,[str(a.output/'test-stock-spmi')]]:
    r=subprocess.run(argv,capture_output=True,text=True,timeout=120)
    logs.append({'argv':argv,'exit_code':r.returncode,'output':r.stdout+r.stderr})
    (a.output/'commands.json').write_text(json.dumps(logs,indent=2)+'\n')
    if r.returncode:raise RuntimeError('Inspect commands.json')
tests=json.loads(logs[-1]['output']);assert tests['cases']==15
result={'phase':'unchanged_stock_SPMI_access_contract_executed_in_CPU_model',
        'source_sha256':digest,'source_commit':'c87f74901db572a762241d6dfcacc42dbdd9f798',
        'original_function_count':9,'source_items':records,'tests':tests,
        'model_sources':{name:hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest()
                         for name in ['verify-stock-spmi.py','stock-spmi-model.h','test-stock-spmi.c']},
        'ASan_UBSan_passed':True,'native_MMIO_access_or_PMIC_write_qualified':False,
        'limits':['PPID-to-APID lookup, platform services, MMIO and peripheral data are modeled.',
                  'Source STATUS reads and CMD/WDATA writes do not establish this Windows boot has access permissions.',
                  'No electrical voltage, AOP coordination or native rail enable is proved.']}
(a.output/'source-contract.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'cases':tests['cases'],'original_functions':9,'native_hardware':False}))
