"""Resolve the stock touch supply to RPMh resources without accessing hardware."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--inputs',type=Path,required=True)
p.add_argument('--rpmh-source',type=Path,required=True)
p.add_argument('--output',type=Path,required=True)
a=p.parse_args();assert not a.output.exists()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
decoder=a.inputs/'fdt-analysis/fdtree.py'
spec=importlib.util.spec_from_file_location('fdt',decoder);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
bindings=json.loads((a.inputs/'spi-G27/source-binding.json').read_text())
dbfile=a.inputs/'touch-G25/cmddb-decoded.json';db=json.loads(dbfile.read_text())
entry=[r for r in db['entries']if r['id']=='ldob4'];assert len(entry)==1
entry=entry[0];assert entry['slave_id']==4 and entry['address']=='0x40800'
regulator=a.inputs/'touch-G25/private/rpmh-regulator.c'
assert sha(regulator)=='a15b6840b03917c03e609f160956e568d8f823c3f7bc0ceb158e25b35089974b'
regtext=regulator.read_text()
assert re.search(r'RPMH_REGULATOR_REG_VRM_ENABLE\s*= 1,',regtext)
assert 'cmd[j].addr = aggr_vreg->addr + i * 4;'in regtext
assert 'rpmh_regulator_set_reg(vreg, RPMH_REGULATOR_REG_ENABLE, 1)'in regtext
assert 'mv = DIV_ROUND_UP(min_uv, 1000);'in regtext
rsc=a.rpmh_source/'drivers/soc/qcom/rpmh-rsc.c'
assert sha(rsc)=='8a68f9cc729466be1081c925bb8c0ee83a5ba8a39a872f6518bf9ebcecd6269c'
text=rsc.read_text();layouts={}
for suffix in ['2_7','3_0','3_0_hw_channel']:
    m=re.findall(r'static u32 rpmh_rsc_reg_offsets_ver_'+suffix+r'\[\] = \{(.*?)\n\};',text,re.S);assert len(m)==1
    fields=re.findall(r'\[([A-Z0-9_]+)\]\s*=\s*(0x[0-9a-fA-F]+|[0-9]+),',m[0]);assert len(fields)==21
    layouts[suffix]={k:int(v,0)for k,v in fields}
assert 'if (major_ver >= 3 && minor_ver >= 0)'in text
assert 'drv[i].base = devm_platform_ioremap_resource(pdev, i);'in text
assert 'drv->tcs_base = drv->base + offset;'in text
assert 'if (!tcs->num_tcs || tcs->type == CONTROL_TCS)'in text
header=a.rpmh_source/'include/dt-bindings/soc/qcom,rpmh-rsc.h'
assert sha(header)=='6810c83419f95e8908c1de201ccd40022c9d149ab77f54e2bb12590585370b2d'
types={int(v):k for k,v in re.findall(r'^#define ([A-Z_]+_TCS)\s+([0-9]+)',header.read_text(),re.M)}
assert len(types)==5
result={'phase':'source_and_captured_command_DB_RPMh_binding_only',
        'inputs':{'FDT_decoder_sha256':sha(decoder),'candidate_binding_sha256':sha(a.inputs/'spi-G27/source-binding.json'),
                  'captured_command_DB_decode_sha256':sha(dbfile),'raw_command_DB_sha256':db['source_sha256'],
                  'regulator_source_sha256':sha(regulator),'RSC_source_sha256':sha(rsc)},
        'resource':entry,'resource_address_is_RPMh_message_address_not_CPU_MMIO':True,
        'enable_vote':{'RPMh_address':'0x40804','data':1,'release_vote_data':0},
        'fixed_voltage_vote':{'RPMh_address':'0x40800','millivolts':1800},
        'candidate_RSCs':[], 'RSC_layouts':layouts,
        'native_RSC_reads_or_writes':0,'native_RPMh_vote_qualified':False,
        'limitations':['Active Android overlay and physical touch ICs remain unproven.',
          'The failed direct SPMI reads do not identify the firewall or prove write permission.',
          'RPMh resource addresses must never be passed to physical MMIO writes.',
          'Native RSC version/config, power-domain state, access permissions, TCS ownership and current votes are not captured.',
          'No TCS may be overwritten solely because its status is idle; allocation, active/sleep/wake and inherited votes must be reconciled.',
          'An enable/release vote is not equivalent to a raw PMIC byte undo; preserve other masters and inherited state.',
          'The full native driver still requires serialization, ACK/timeout handling, IRQ/power lifecycle and independent recovery.']}
for candidate in bindings['candidates']:
    dtb=a.inputs/f'fdt-analysis/private/kalama-candidate-{candidate["candidate"]}-first.dtb'
    assert sha(dtb)==candidate['sha256'];f=mod.Fdt.read(dtb);ph=f.phandles()
    supply='/soc/apps_rsc@17a00000/drv@2/rpmh-regulator-ldob4/regulator-pm-humu-l4'
    assert f.strings(supply.rsplit('/',1)[0],'qcom,resource-name')==['ldob4']
    refs=[]
    for node in f.nodes:
        if 'vcc_1v8-supply'in f.nodes[node]and 'goodix'in node:
            cells=f.cells(node,'vcc_1v8-supply');assert len(cells)==1 and ph[cells[0]]==supply;refs.append(node)
    assert len(refs)==2
    drv=supply.split('/rpmh-')[0];parent=drv.rsplit('/',1)[0]
    drv_id,=f.cells(drv,'qcom,drv-id');tcs_offset,=f.cells(drv,'qcom,tcs-offset')
    cells=f.cells(parent,'reg');names=f.strings(parent,'reg-names');assert len(cells)==2*len(names)
    assert drv_id==2 and names[drv_id]=='drv-2';base,size=cells[2*drv_id:2*drv_id+2]
    config=[];slot=0
    for node in f.nodes:
        if node.startswith(drv+'/channel@'):
            pairs=f.cells(node,'qcom,tcs-config');assert len(pairs)==10
            groups=[]
            for i in range(0,len(pairs),2):
                kind,n=pairs[i:i+2];name=types[kind]
                indices=list(range(slot,slot+n))if name!='CONTROL_TCS'else[]
                groups.append({'type':name,'count':n,'source_derived_indices':indices})
                if indices:slot+=n
            config.append({'node':node,'groups':groups})
    assert slot==8 and len(config)==1
    record={'candidate':candidate['candidate'],'DTB_sha256':sha(dtb),'touch_nodes':refs,
            'supply':supply,'qcom_set':f.cells(supply,'qcom,set'),
            'microvolt_range':[f.cells(supply,k)[0]for k in ['regulator-min-microvolt','regulator-max-microvolt']],
            'RSC':parent,'DRV':drv,'DRV_id':drv_id,'DRV_base':hex(base),'DRV_bytes':size,
            'TCS_base':hex(base+tcs_offset),'TCS_offset':hex(tcs_offset),'TCS_configuration':config,
            'power_domain_cells':f.cells(parent,'power-domains'),
            'source_used_initial_registers':{'RSC_DRV_ID':hex(base),'DRV_SOLVER_CONFIG':hex(base+4),'DRV_PRNT_CHLD_CONFIG':hex(base+12)},
            'layout_selection':'Read native major=(ID>>16)&255, minor=(ID>>8)&255; source uses 3_0 for major>=3, otherwise 2_7. HW-channel override is separately conditional.'}
    assert record['microvolt_range']==[1800000,1800000]
    assert base==0x17a20000 and base+tcs_offset==0x17a20d00
    result['candidate_RSCs'].append(record)
a.output.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({'candidates':len(result['candidate_RSCs']),'resource':entry['id'],'message_enable':'0x40804/data1','native_hardware':False}))
