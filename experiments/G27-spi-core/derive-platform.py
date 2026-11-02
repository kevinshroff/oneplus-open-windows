"""Read-only stock candidate/FDT and source binding for the future SPI owner.

No target I/O or pin changes. Keeps contradictory candidate pin settings visible
instead of silently choosing a bias. Actual active Android overlay is unproven.
"""
import argparse,hashlib,importlib.util,json,re
from pathlib import Path

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists()
    w=Path(__file__).parent;binding=json.loads((w/'source-binding.json').read_text())
    decoder=a.inputs/'fdt-analysis/fdtree.py'
    spec=importlib.util.spec_from_file_location('g27_fdt',decoder);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    pinctrl=a.inputs/'gpio-G20/private/pinctrl-kalama.c';text=pinctrl.read_text()
    assert sha(pinctrl)=='fd48c2e5f669c9f3304074b42578e5b6a498ca303855eb0c1d6d47e17d0785ac'
    def constant(name):
        m=re.findall(r'^#define '+name+r'\s+(0x[0-9a-f]+)\s*$',text,re.M);assert len(m)==1
        return int(m[0],16)
    start,stride=constant('REG_BASE'),constant('REG_SIZE')
    assert '.ctl_reg = REG_BASE + REG_SIZE * id' in text
    assert '.io_reg = REG_BASE + 0x4 + REG_SIZE * id' in text
    msm=a.inputs/'gpio-G20/private/pinctrl-msm.c'
    assert sha(msm)=='436c1321b9d5f013221e7001ce8894d0ab947b7482679ef6411388b77a989753'
    assert 'if (val & BIT(g->egpio_present))\n\t\tval |= BIT(g->egpio_enable);' in msm.read_text()
    for field,value in [('mux_bit',2),('pull_bit',0),('drv_bit',6),('oe_bit',9),('egpio_present',11),('egpio_enable',12)]:
        assert re.search(r'\.'+field+r'\s*=\s*'+str(value)+r'\s*,',text)
    result={'source_binding_sha256':sha(w/'source-binding.json'),'FDT_decoder_sha256':sha(decoder),
        'pinctrl_source_sha256':sha(pinctrl),'pinctrl_common_source_sha256':sha(msm),'candidates':[],
        'native_pinmux_or_transfer_qualification':False,
        'limits':['Candidate bindings are not physical controller identification or active Android DTBO selection.',
        'No GPIO44..47/64..67 native snapshot or mutation is performed by this script.',
        'No bias is resolved when conflicting FDT properties are present.',
        'Source mux selection conditionally sets EGPIO_ENABLE when EGPIO_PRESENT; future owner must preserve/verify ownership.']}
    for candidate in binding['candidates']:
        dtb=a.inputs/f'fdt-analysis/private/kalama-candidate-{candidate["candidate"]}-first.dtb'
        assert sha(dtb)==candidate['sha256'];f=mod.Fdt.read(dtb);ph=f.phandles()
        base,size=f.cells('/soc/pinctrl@f000000','reg');nodes=[]
        def property_value(node,key):
            data=f.nodes[node][key]
            if not data:return True
            if key in ['pins','function','compatible','status','pinctrl-names','clock-names','dma-names','interconnect-names']:
                return f.strings(node,key)
            return f.cells(node,key)
        for saved in candidate['nodes']:
            node=saved['path'];assert f.strings(node,'compatible')==['qcom,spi-geni']
            states={};muxes=[]
            for index,name in enumerate(f.strings(node,'pinctrl-names')):
                records=[]
                for h in f.cells(node,'pinctrl-'+str(index)):
                    parent=ph[h]
                    for path,props in f.nodes.items():
                        if path!=parent and not path.startswith(parent+'/'):continue
                        if 'pins' not in props:continue
                        row={'path':path,'properties':{k:property_value(path,k) for k in props if k not in ['phandle','linux,phandle']}}
                        records.append(row)
                        if name=='default' and 'function' in props:
                            func=f.strings(path,'function');assert len(func)==1
                            for pin in f.strings(path,'pins'):
                                assert re.fullmatch('gpio[0-9]+',pin);number=int(pin[4:])
                                m=re.search(r'\['+str(number)+r'\]\s*=\s*PINGROUP\('+str(number)+r',([^)]*)\)',text,re.S);assert m
                                slots=['gpio']+[s.strip() for s in m[1].split(',')[:9]]
                                assert slots.count(func[0])==1;select=slots.index(func[0])
                                address=base+start+stride*number;assert base<=address<address+4<base+size
                                muxes.append({'pin':number,'function':func[0],'mux_selector':select,
                                  'control':hex(address),'io':hex(address+4),'register_derivation':f'{base:#x}+{start:#x}+{stride:#x}*{number}'})
                states[name]=records
            assert sorted(r['pin'] for r in muxes)==([44,45,46,47] if node.endswith('a90000') else [64,65,66,67])
            config={k:property_value(node,k) for k in ['compatible','reg','status','clock-names','clocks','dma-names','dmas','interconnect-names','interconnects'] if k in f.nodes[node]}
            flags=[k for k,v in f.nodes[node].items() if not v]
            nodes.append({'path':node,'configuration':config,'boolean_flags':flags,'pinctrl_states':states,'default_mux':sorted(muxes,key=lambda r:r['pin']),
              'conflicting_bias_nodes':[r['path'] for records in states.values() for r in records if len([k for k in r['properties'] if k.startswith('bias-')])>1]})
        result['candidates'].append({'candidate':candidate['candidate'],'sha256':sha(dtb),'engines':nodes})
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'candidates':len(result['candidates']),'engine_rows':sum(len(r['engines']) for r in result['candidates']),
        'conflicting_bias_nodes':sum(len(e['conflicting_bias_nodes']) for c in result['candidates'] for e in c['engines'])}))
if __name__=='__main__':main()
