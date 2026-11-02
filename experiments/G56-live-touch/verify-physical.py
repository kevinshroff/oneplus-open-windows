"""Replay only persisted native bytes through real input cores, audit Win32 delivery."""
from pathlib import Path
import argparse,hashlib,json,struct,subprocess
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();W=Path(__file__).resolve().parent;J=lambda p:json.loads(p.read_text());s=J(W/'live-native-physical.json');n=J(W/'native-qualification-physical.json');out=W/'private/live-native-physical-01';d=J(out/'power-decoded.json');poll=d['touch']['poll'];state=s['after'];assert s['hardware_and_power_restoration_verified']and state['accepted_mask']==0 and state['last_submit_status']==0
assert d['operation_code']==6 and d['restore_error']==0 and d['touch']['operation_code']==18 and poll['operation_code']==4 and poll['cycles']==73
terminal=poll['records'][-1];assert terminal['kind']==0 and terminal['error']==2 and terminal['header_checked']==1 and terminal['header_valid']==terminal['clear_attempted']==terminal['clear_completed']==0
assert state['live_complete']==0 and state['live_error']==6
terminal_raw=bytes(terminal['raw_bytes'][:terminal['read_bytes']]);checksum=sum(terminal_raw[:6])&65535;stored=struct.unpack_from('<H',terminal_raw,6)[0];assert checksum!=stored
model=W/'private/physical-oracle';model.mkdir(exist_ok=True);raw=model/'raw-frames.bin';stream=bytearray();hardware_lifts=0;prior=0
for r in poll['records']:
 if r['kind']!=3 or not r['clear_completed']:continue
 b=bytes(r['raw_bytes'][:r['read_bytes']]);stream+=struct.pack('<I',len(b))+b
 if prior and r['point_count']==0:hardware_lifts+=1
 prior=r['contact_mask']
raw.write_bytes(stream)
c=model/'oracle.c';c.write_text(r'''
#include "g56_input.h"
#include <stdio.h>
#include <string.h>
static unsigned Count;static int Submit(void*x,const uint8_t b[64]){Count++;return fwrite(b,1,64,(FILE*)x)==64;}
int main(int argc,char**argv){G56_INPUT s;uint32_t n;uint8_t b[90];if(argc!=3)return 2;memset(&s,0,sizeof(s));FILE*in=fopen(argv[1],"rb"),*out=fopen(argv[2],"wb");if(!in||!out)return 3;G56_INPUT_IO io={out,Submit};
 while(fread(&n,4,1,in)==1){if(n>90||fread(b,1,n,in)!=n||!G56InputStage(&s,b,n,0)||!G56InputPublish(&s,&io,b,n))return 4;}
 if(ferror(in)||!G56InputStop(&s,&io,0)||s.Accepted.Mask||s.Error)return 5;fclose(in);if(fclose(out))return 6;
 printf("{\"reports\":%u,\"generation\":%u,\"cleanup_UP\":%u,\"mask\":%u}\n",Count,s.Accepted.Generation,s.StopAccepted,s.Accepted.Mask);return 0;}
''');exe=model/'oracle';sources=['g56_input.c','g56hid_lifecycle.c','g56_report.c'];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();hashes={v:sha(W/v)for v in sources+['g56_input.h','g56hid_lifecycle.h','g56_report.h']}
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
report={'passed':True,'native_live_finger_DOWN_MOVE_UP':True,'full100_cycle_physical_session_completed':False,'guard_stop':{'poll_cycle':73,'reason':'header checksum','computed':checksum,'stored':stored,'raw':terminal_raw.hex(),'invalid_frame_cleared':False,'remaining_contact_released_once':state['stop_accepted']==1,'all29_VHF_submissions_accepted':True},'native_hardware_lifts':hardware_lifts,'Windows_downs':len(downs),'Windows_updates':len(moves),'Windows_ups':len(ups),'Windows_pointer_IDs':sorted({e['pointer']['ID']for e in points}),'accepted_reports':oracle['reports'],'final_cleanup_UP':oracle['cleanup_UP'],'max_pixel_error_against_actual_C_lifecycle':max_error,'source_equals_owned_HID_interface':True,'window_target_verified':True,'native_poll_us':poll['elapsed_us'],'native_raw_sha256':sha(out/'power.bin'),'oracle_source_sha256':hashes,'ASan_UBSan_oracle':True,'physical_multitouch_qualified':False,'outer_screen_qualified':False,'continuous_driver_qualified':False,'limits':['A brief physical test does not establish long-run polling/IRQ, power/resource ownership or exact edge calibration.','Coordinates are matched to the actual C mapping of accepted native packets; coalesced motion need not expose every report.']};a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
