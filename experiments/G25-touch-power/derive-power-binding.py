"""Join source, firmware and native evidence without changing hardware."""
from pathlib import Path
import argparse,hashlib,json
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--evidence',required=True,type=Path)
p.add_argument('--output',required=True,type=Path)
a=p.parse_args();assert not a.output.exists()
used={}
def load(n):
    b=(a.evidence/n).read_bytes();used[n]=hashlib.sha256(b).hexdigest();return json.loads(b)
fdt=load('touch-power-source-resolved.json')
aop=load('aop-resource-analysis-v2.json')
inv=load('native-inventory.json');bus1=load('native-bus1-inventory.json')
read=load('native-vddi-mapped-verified.json');gpio=load('native-PMIC-read-verified.json')
smem=load('SMEM-PMIC-identity.json')
for cand in fdt['candidates']:
    assert len(cand['touches'])==2
    for touch in cand['touches']:
        s=touch['resources']['vcc_1v8-supply']
        assert s['supply_parent']['qcom,resource-name']==['ldob4']
        assert s['provider']['regulator-min-microvolt']==s['provider']['regulator-max-microvolt']==[1800000]
supply=aop['touch_supply'];assert supply['pmic_index']==1 and supply['ldo_number']==4
assert supply['configured_min_millivolts']==supply['configured_max_millivolts']==1800
assert all(hex(x)in aop['peripheral_bitmaps'][1]['implemented_peripherals']for x in range(0xc1,0xd2))
byid={t['ppid']:t for t in read['targets']}
assert byid[0x101]['identity'][4:7]==[0x51,0x49,1]
assert smem['models'][1]['subtype']==0x49 and smem['double_read_identical']
assert byid[0x1c1]['identity'][4]==byid[0x1c4]['identity'][4]==4
routes=[r for r in inv['map_rows']if int(r['ppid'],16)==0x1c4]
selected=routes[0]
for r in routes:
    if r['owner']==0:selected=r
assert selected['apid']==byid[0x1c4]['apid']==695 and selected['owner']==0
cfg=byid[0x1c4]['configuration'];mv=int.from_bytes(bytes(cfg[:2]),'little')
assert mv==1800 and cfg[5]==7 and cfg[6]==0
assert read['all_logged_MMIO_writes_are_observer_read_commands']and read['raw_observer_write_count']==5
assert sum(t['error']is not None for t in read['targets'])==0
assert not any(int(r['ppid'],16)==0x143 for r in inv['map_rows']+bus1['map_rows'])
pmicgpio=[]
for ppid in [0x58e,0x793]:
    t=next(t for t in gpio['targets']if t['ppid']==ppid)
    assert t['identity'][4]==0x10 and t['configuration'][0]&3==0
    pmicgpio.append(dict(ppid=hex(ppid),apid=t['apid'],identity_hex=bytes(t['identity']).hex(),configuration_hex=bytes(t['configuration']).hex(),mode='input',pull='down'))
report=dict(evidence_sha256=used,
    binding=dict(resource='ldob4',PMIC_index=1,source_PM8550_SID=1,LDO_number=4,register_base='0xc400',PPID='0x1c4',APID=695,write_EE=0,observer_base=hex(0xc440000+695*0x20)),
    native=dict(revision_identity_hex=bytes(byid[0x101]['identity']).hex(),first_LDO_identity_hex=bytes(byid[0x1c1]['identity']).hex(),LDO4_identity_hex=bytes(byid[0x1c4]['identity']).hex(),configuration_40_47_hex=bytes(cfg).hex(),VSET_millivolts=mv,MODE_CTL_raw=cfg[5],EN_CTL_raw=cfg[6],enable_bit7=False,status_08_raw=byid[0x1c4]['status'][0]),
    secondary_touch_GPIOs=pmicgpio,
    established=['Both derived stock touch nodes request the same 1.8V ldob4 supply.',
                 'AOP resource lookup and config identify PMIC index1 LDO4, with 1800mV limits.',
                 'Native anchor/LDO4 types, source stride, observed route and exact VSET agree.',
                 'Native EN_CTL bit7 is clear; no enabling or output-driving test occurred.'],
    next=['Prepare guarded enable/readback/undo of the existing 1800mV rail setting.',
          'Combine source-matched AVDD/reset/pinmux timing with a primary SPI identification read.',
          'Advance interrupt/HID input and proper regulator/bus interfaces after transport works.'],
    limitations=['VSET is the programmed voltage, not an electrical voltage measurement.',
                 'Stock FDT candidates and captured A-slot firmware do not prove active Android overlay/live AOP selection.',
                 'No physical Goodix SPI identity, touch event, rail enable, GPIO output or IRQ has been demonstrated.',
                 'Command-database auxiliary bytes remain opaque; the rejected PPID0x147 guess is not used.'])
a.output.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(dict(binding=report['binding'],native=report['native'])))
