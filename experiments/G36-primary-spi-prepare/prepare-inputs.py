"""Reproduce G36 firmware binding and source/capture-based SPI prerequisites."""
from pathlib import Path
import argparse,hashlib,json
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);G=a.inputs
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();j=lambda p:json.loads(p.read_text())
old=G/'status-G35/private/inputs';header=old/'g35_binding.h';assert sha(header)=='2ab9e14d67a03476998ce77af7e8b9064af8300234d7b9f25cf20b28c5365770'
assert sha(old/'binding.json')=='f01349972fd2578176fea8875410f3ef0a3ae23b3246238a172bde555fb43110'
(a.output/'g36_binding.h').write_text(header.read_text().replace('G35','G36'));(a.output/'binding.json').write_bytes((old/'binding.json').read_bytes())
native=G/'status-G35/native-qualification.json';n=j(native);assert n['phase']=='unloaded_service_and_endpoint_absent_control8CPUs'
assert all(c['pmic_status_raw']==0x43 and c['configuration']==[8,7,0,0,7,7,0,0]for c in n['captures'].values())
pins=G/'gpio-G20/native-GPIO-result.json';rows=[r for r in j(pins)['pins']if r['pin']in[44,45,46,47]];assert len(rows)==4
for r in rows:assert r['raw']=={'control':'0x1','inout':'0x0','interrupt_config':'0xe2','interrupt_status':'0x0'}
clock=G/'bus-G24/native-bus-result.json';c=j(clock)['clock_probe']['candidates'][0]
assert c['vote_restored']and c['full_vote_matches_baseline']and c['identity_read']and c['main_fw_revision']=='102'
proof={'G35_header_sha256':sha(header),'G35_native_state_sha256':sha(native),'G20_pin_capture_sha256':sha(pins),'G24_clock_native_sha256':sha(clock),'G27_platform_binding_sha256':sha(G/'spi-G27/platform-binding-v2.json'),'phone_session':n['phone_session'],'PMIC_raw_baseline':67,'PMIC_configuration':[8,7,0,0,7,7,0,0],'primary_roles':{'MISO':44,'MOSI':45,'CLK':46,'CS0':47},'pin_control_baseline':1,'pin_control_active':133,'pin_control_writable_mask':'mux3c/drive1c0/pull3; fixed baseline excludes OE/EGPIO','clock_vote_baseline':'0x40002380','clock_vote_stages':['0x100000','0x200000','0x4000000'],'clock_vote_enable':'0x44302380','maximum_new_write_attempts':14,'only_new_write_addresses':['0x152008','0xf12c000','0xf12d000','0xf12e000','0xf12f000'],'SPI_transfer_reset_supply_or_IRQ_writes':0,'native_current_values_must_be_rechecked_in_driver':True}
(a.output/'spi-binding.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps({'primary_pins':4,'write_budget':14,'native_commands_submitted':0}))
