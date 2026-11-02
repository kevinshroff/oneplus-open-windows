"""Generate a bounded read-only inventory from stock binding and native geometry."""
import argparse,hashlib,json,re
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--binding',type=Path,required=True)
p.add_argument('--native-config',type=Path,required=True)
p.add_argument('--source',type=Path,required=True)
p.add_argument('--reader-source',type=Path,required=True)
p.add_argument('--output',type=Path,required=True);a=p.parse_args()
assert not a.output.exists()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
binding=json.loads(a.binding.read_text());native=json.loads(a.native_config.read_text())
source=a.source.read_text();assert sha(a.source)==binding['inputs']['RSC_source_sha256']
def num(name):
    m=re.findall(r'^#define '+name+r'\s+(0x[0-9A-Fa-f]+|[0-9]+)\s*$',source,re.M);assert len(m)==1
    return int(m[0],0)
values={int(r['address'],16):int(r['value'],16)for r in native['native_result']['reads']}
config=values[0x17a2000c];count=(config>>(num('DRV_NUM_TCS_SHIFT')*2))&num('DRV_NUM_TCS_MASK')
ncpt=(config>>num('DRV_NCPT_SHIFT'))&num('DRV_NCPT_MASK')
assert count==native['decoded']['DRV2_TCS_count']==8 and ncpt==16
candidates=binding['candidate_RSCs'];assert all(c['DRV_base']=='0x17a20000'and c['TCS_base']=='0x17a20d00'for c in candidates)
layout=binding['RSC_layouts']['3_0'];base=int(candidates[0]['TCS_base'],16)
plan={'common':{k:int(v,16)for k,v in candidates[0]['source_used_initial_registers'].items()},
      'irq':{k:base+layout[k]for k in ['RSC_DRV_IRQ_ENABLE','RSC_DRV_IRQ_STATUS']},'TCS':[]}
for i in range(count):
    fields={name:base+layout['RSC_DRV_TCS_OFFSET']*i+layout[name]for name in ['RSC_DRV_STATUS','RSC_DRV_CONTROL','RSC_DRV_CMD_ENABLE']}
    for name in fields:assert ('drv->regs['+name+']')in source
    plan['TCS'].append({'index':i,'fields':fields})
allowed=sorted(set(list(plan['common'].values())+list(plan['irq'].values())+[x for row in plan['TCS']for x in row['fields'].values()]))
assert len(allowed)==29 and all(0x17a20000<=x<x+4<=0x17a30000 for x in allowed)
reader=a.reader_source.read_text();start=reader.index('function g29Read(');end=reader.index('\nfunction g29RSCConfig()')
reader=reader[start:end].replace('g29Read','g29HdrRead').replace('[0x17a20000,0x17a20004,0x17a2000c]','G29_H_ALLOWED')
body='''
function g29RSCHeaders(sample) {
 var s={version:"G29-rsc-headers-1",sample:sample,attempts:[],reads:[],headers:[],MMIO_writes:0,error:null};
 try {
  if(["A","B"].indexOf(sample)<0)throw new Error("Explicit sample A/B required");
  if(g29HdrRead(0x17a20000,s)!==0x30000 || g29HdrRead(0x17a20004,s)!==0x04010100 ||
     g29HdrRead(0x17a2000c,s)!==0x800c8104)throw new Error("Native geometry/identity changed");
  s.irq={};for(var key of Object.keys(G29_H_PLAN.irq))s.irq[key]=g29HdrRead(G29_H_PLAN.irq[key],s);
  for(var row of G29_H_PLAN.TCS) {
   var data={index:row.index};for(var key of Object.keys(row.fields))data[key]=g29HdrRead(row.fields[key],s);
   s.headers.push(data);
  }
 }catch(e){s.error=String(e);}
 s.success=!s.error && s.reads.length===29 && s.headers.length===8;
 host.diagnostics.debugLog("G29_RSC_HEADERS_JSON ",JSON.stringify(s),"\\n");return s;
}
function initializeScript(){return[new host.apiVersionSupport(1,7),new host.functionAlias(g29RSCHeaders,"g29RSCHeaders")];}
'''
script='"use strict";\nvar G29_H_PLAN='+json.dumps(plan,separators=(',',':'))+';\nvar G29_H_ALLOWED='+json.dumps(allowed)+';\n'+reader+'\n'+body
assert '!ed'not in script and script.count('ExecuteCommand(')==1
a.output.write_text(script)
a.output.with_suffix('.json').write_text(json.dumps({'source_binding_sha256':sha(a.binding),'native_config_sha256':sha(a.native_config),'RSC_source_sha256':sha(a.source),'reader_source_sha256':sha(a.reader_source),'script_sha256':sha(a.output),'words_per_sample':29,'command_slots_read':0,'MMIO_writes':0,'plan':plan},indent=2)+'\n')
print(json.dumps({'words':29,'TCS_headers':8,'script_sha256':sha(a.output)}))
