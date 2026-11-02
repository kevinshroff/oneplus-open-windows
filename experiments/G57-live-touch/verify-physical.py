"""Replay only persisted native bytes through real input cores, audit Win32 delivery."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();W=Path(__file__).resolve().parent;J=lambda p:json.loads(p.read_text());s=J(W/'live-native-physical.json');n=J(W/'native-qualification-physical.json');out=W/'private/live-native-physical-01';d=J(out/'power-decoded.json');poll=d['touch']['poll'];state=s['after'];assert s['hardware_and_power_restoration_verified']and state['accepted_mask']==0 and state['last_submit_status']==0
assert d['operation_code']==d['restore_error']==d['touch']['operation_code']==poll['operation_code']==0 and poll['cycles']==100
assert state['live_complete']==1 and state['live_error']==0
assert n['phase']=='owned_input_devices_packages_service_removed_original_baseline_restored'
v=n['audit_after'];assert v['owned_roots']==0 and v['source_interfaces']==[] and not v['source_service']['present'] and not v['inbox_include']['present'] and v['processors']==8 and v['inventory']['SM_DIGITIZER']==0
assert n['baseline']['files']==v['inventory']['files'] and n['baseline']['services']==v['inventory']['services'] and n['baseline']['DSDT_sha256']==v['inventory']['DSDT_sha256']
assert len(s['fixed50_comparison'])==50 and all(r['before']==r['after'] for r in s['fixed50_comparison'])
assert s['pmic_before']['pmic_status_raw']==s['pmic_after']['pmic_status_raw']==0x43 and s['pmic_before']['configuration']==s['pmic_after']['configuration']
assert s['pmic_before']['operation_code']==s['pmic_after']['operation_code']==0 and s['pmic_before']['fixed_registers_unchanged']==s['pmic_after']['fixed_registers_unchanged']==1
assert J(W/'remove-disconnected-physical.json')['phase']=='two_exact_owned_descendants_and_unused_child_package_removed_without_force'
recovered=[];retried_idle=[]
for i,r in enumerate(poll['records']):
 if r['header_retry']:
  first=bytes(r['first_raw']);assert len(first)==26 and (sum(first[:6])&65535)!=struct.unpack_from('<H',first,6)[0]
  assert r['irq_mask']==15
  if r['kind']==1:
   assert r['flags']==r['header_checked']==r['clear_attempted']==0;retried_idle.append(i+1);continue
  assert r['header_valid']==1 and r['clear_completed']==1
  recovered.append({'cycle':i+1,'first_raw':first.hex(),'fresh_raw':bytes(r['raw_bytes'][:r['read_bytes']]).hex(),'GPIO':r['irq_samples']})
assert len(recovered)==poll['headers_recovered']and len(recovered)+len(retried_idle)==poll['header_retries']
model=W/'private/physical-oracle';model.mkdir(exist_ok=True);raw=model/'raw-frames.bin';stream=bytearray();hardware_lifts=0;prior=0
for r in poll['records']:
 if r['kind']!=3 or not r['clear_completed']:continue
 b=bytes(r['raw_bytes'][:r['read_bytes']]);stream+=struct.pack('<I',len(b))+b
 if prior and r['point_count']==0:hardware_lifts+=1
 prior=r['contact_mask']
raw.write_bytes(stream)
c=model/'oracle.c';c.write_text(r'''
#include "g57_input.h"
#include <stdio.h>
#include <string.h>
static unsigned Count;static int Submit(void*x,const uint8_t b[64]){Count++;return fwrite(b,1,64,(FILE*)x)==64;}
int main(int argc,char**argv){G57_INPUT s;uint32_t n;uint8_t b[90];if(argc!=3)return 2;memset(&s,0,sizeof(s));FILE*in=fopen(argv[1],"rb"),*out=fopen(argv[2],"wb");if(!in||!out)return 3;G57_INPUT_IO io={out,Submit};
 while(fread(&n,4,1,in)==1){if(n>90||fread(b,1,n,in)!=n||!G57InputStage(&s,b,n,0)||!G57InputPublish(&s,&io,b,n))return 4;}
 if(ferror(in)||!G57InputStop(&s,&io,0)||s.Accepted.Mask||s.Error)return 5;fclose(in);if(fclose(out))return 6;
 printf("{\"reports\":%u,\"generation\":%u,\"cleanup_UP\":%u,\"mask\":%u}\n",Count,s.Accepted.Generation,s.StopAccepted,s.Accepted.Mask);return 0;}
''');exe=model/'oracle';sources=['g57_input.c','g57hid_lifecycle.c','g57_report.c'];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();hashes={v:sha(W/v)for v in sources+['g57_input.h','g57hid_lifecycle.h','g57_report.h']}
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I',str(W),str(c),*[str(W/v)for v in sources],'-o',str(exe.resolve())],capture_output=True,text=True);assert q.returncode==0,q.stderr
reports=model/'reports.bin';q=subprocess.run([str(exe.resolve()),str(raw.resolve()),str(reports.resolve())],capture_output=True,text=True);assert q.returncode==0 and not q.stderr,(q.stdout,q.stderr);oracle=json.loads(q.stdout);assert oracle['reports']==state['reports_accepted']==state['reports_submitted']==state['accepted_generation']==oracle['generation']and oracle['cleanup_UP']==state['stop_accepted']
ready=J(out/'ready.json');done=J(out/'done.json');events=[json.loads(x)for x in(out/'events.jsonl').read_text().splitlines()if x];assert not done['dropped']and done['window_closed']
points=[]
for e in events:
 assert not e.get('history_truncated')and not e.get('history_error')
 if e.get('GetPointerInfo_ok')and e['pointer']['Type']==2:
  assert e['window']==e['pointer']['Target']==ready['Window']
  points.append(e)
assert points and {e['source_device_name'].casefold()for e in points}=={n['caps_ready']['owned_HID_interfaces'][0]['interface_path'].casefold()}
downs=[e for e in points if e['message']=='0x246'];moves=[e for e in points if e['message']=='0x245'];ups=[e for e in points if e['message']=='0x247'];assert downs and moves and ups
assert hardware_lifts>=1 and len(ups)>oracle['cleanup_UP'],'Need a hardware lift and a consumer UP beyond any one final cleanup UP'
assert all(e['pointer']['Flags']&0x10000 and e['pointer']['Flags']&4 for e in downs)and all(e['pointer']['Flags']&0x40000 and not(e['pointer']['Flags']&4)for e in ups)
b=reports.read_bytes();assert len(b)==64*oracle['reports'];expected=[]
for at in range(0,len(b),64):
 r=b[at:at+64];assert r[0]==1 and r[63]<=10
 for i in range(r[63]):
  j=1+i*6;flags=r[j];cid=r[j+1];x,y=struct.unpack_from('<HH',r,j+2);expected.append({'tip':bool(flags&1),'confidence':bool(flags&2),'id':cid,'X':x/22680*ready['Width'],'Y':y/24400*ready['Height']})
samples=[]
for e in points:
 samples.append(e['pointer']);samples.extend(e.get('history',[]))
max_error=0
for sample in samples:
 pos=sample['RawPixel'];candidates=[r for r in expected if r['tip']==bool(sample['Flags']&4)];assert candidates
 err=min(max(abs(pos['X']-r['X']),abs(pos['Y']-r['Y']))for r in candidates);assert err<=3,(sample,err);max_error=max(max_error,err)
positions={(e['pointer']['RawPixel']['X'],e['pointer']['RawPixel']['Y'])for e in moves};assert len(positions)>=2,'Need observable physical movement'
assert all(sha(W/v)==h for v,h in hashes.items())
report={'passed':True,'native_live_finger_DOWN_MOVE_UP':True,'full100_cycle_physical_session_completed':True,'header_retries':poll['header_retries'],'headers_recovered':poll['headers_recovered'],'actual_header_recovery_qualified':bool(recovered),'recovered_samples':recovered,'retried_to_idle_cycles':retried_idle,'native_hardware_lifts':hardware_lifts,'Windows_downs':len(downs),'Windows_updates':len(moves),'Windows_ups':len(ups),'Windows_pointer_IDs':sorted({e['pointer']['ID']for e in points}),'accepted_reports':oracle['reports'],'final_cleanup_UP':oracle['cleanup_UP'],'max_pixel_error_against_actual_C_lifecycle':max_error,'source_equals_owned_HID_interface':True,'window_target_verified':True,'native_poll_us':poll['elapsed_us'],'native_raw_sha256':sha(out/'power.bin'),'oracle_source_sha256':hashes,'ASan_UBSan_oracle':True,'all50_hardware_words_exactly_restored':True,'independent_before_after_PMIC_off':True,'all_owned_nodes_packages_service_removed':True,'original_driver_hashes_service_configuration_and_DSDT_equal':True,'same_G17_boot_8_CPUs_control_healthy':True,'physical_multitouch_qualified':False,'outer_screen_qualified':False,'continuous_driver_qualified':False,'limits':['A brief physical test does not establish long-run polling/IRQ, power/resource ownership or exact edge calibration.','Coordinates are matched to the actual C mapping of accepted native packets; coalesced motion need not expose every report.']};a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
