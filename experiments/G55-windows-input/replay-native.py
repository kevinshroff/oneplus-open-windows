"""One finite owned-window replay; capture delivery independently of VHF acceptance."""
from pathlib import Path
import hashlib,json,uuid
from relay import Relay
W=Path(__file__).resolve().parent;R=Relay('replay-native.json');N=Relay('native-qualification.json');s=R.s;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();base=r'X:\OpenG17\payloads';admin=base+r'\G55-admin.exe';receiver=base+r'\G55-receiver-v5.exe';out=W/'private/replay-native-01';out.mkdir(exist_ok=True)
assert N.s['phase']=='Windows_HID_parser_physical_axes_and_owned_tree_verified_no_input'
for name,folder,remote in [('admin','admin-04',admin),('receiver','receiver-05',receiver)]:
 m=json.loads((W/'private'/folder/'build.json').read_text());assert m['source_sha256']==sha(W/('g55_'+name+'.go'));r=R.op('hash-'+name,'phone','hash',path=remote);assert r['status']=='ok'and r['sha256']==m['binary_sha256']
def native(label,argv):
 r=R.op(label,'phone','exec',argv=argv);assert r['status']=='ok'and r.get('exit_code',0)==0,r;q=json.loads(r['output']);assert q['ok'],q;return q['result']
s['before']=native('status-before',[admin,'status']);R.persist();assert s['before']['replay_attempts']==s['before']['accepted_mask']==s['before']['replay_submitted']==0 and s['before']['D0']==s['before']['started']==1
if 'token'not in s:s.update(token=uuid.uuid4().hex,max_replay_invocations=1,max_reports_including_cleanup=5,window_seconds=8);R.persist()
admin_sha=json.loads((W/'private/admin-04/build.json').read_text())['binary_sha256']
r=R.op('single-replay-window-job','phone','exec',argv=[receiver,'replay',base,s['token'],admin,admin_sha],timeout=30);s['window_receipt']=r;R.persist()
# Always observe this same completed job and preserve available files, including
# a refused/failed helper. Never substitute a new replay when evidence is weak.
for label,suffix in [('ready','ready.json'),('qualification','qualification.json'),('events','events.jsonl'),('done','done.json')]:
 dest=out/suffix;r=R.op('get-'+label,'phone','get',path=base+'\\G55-receiver-'+s['token']+'-'+suffix,save=dest if not dest.exists()else None)
 if r['status']=='ok':assert dest.exists()and sha(dest)==r['sha256']
s['after']=native('status-after',[admin,'status']);R.persist()
summary={'driver_acceptance_verified':False,'consumer_down_move_up_verified':False,'all_three_saved_positions_seen':False,'window_closed':False,'source_matches_owned_HID_interface':False}
try:
 window=s['window_receipt'];q=json.loads(window['output']);assert window['status']=='ok'and window['exit_code']==0 and q['ok']
 ready=json.loads((out/'ready.json').read_text());done=json.loads((out/'done.json').read_text());qualification=json.loads((out/'qualification.json').read_text())
 assert ready['Token']==done['token']==s['token']and ready['Foreground']and ready['DPIAware']and done['window_closed']and done['dropped']==0 and qualification['owned_foreground_verified'];summary['window_closed']=True
 child=done['admin'];assert child['Started']and child['ExitCode']==0 and not child['Error'];response=json.loads(child['Output']);assert response['ok'];status=response['result'];s['submitted_status']=status
 for v in[status,s['after']]:assert v['replay_attempts']==v['replay_complete']==1 and v['replay_submitted']==v['replay_accepted']==v['accepted_generation']==4 and v['replay_error']==v['last_submit_status']==v['accepted_mask']==v['cleanup_attempted']==v['cleanup_accepted']==0
 assert status['owned_receiver_verified_immediately_before_submit']['Window']==ready['Window'];summary['driver_acceptance_verified']=True
 events=[json.loads(x)for x in(out/'events.jsonl').read_text().splitlines()if x.strip()];pointer=[e for e in events if e.get('GetPointerInfo_ok')and e.get('pointer',{}).get('Type')==2]
 down=[e for e in pointer if e['message']=='0x246'];up=[e for e in pointer if e['message']=='0x247'];moves=[e for e in pointer if e['message']=='0x245'];assert len(down)==len(up)==1 and len(moves)>=1
 ids={e['pointer']['ID']for e in pointer};sources={e['pointer']['Source']for e in pointer};assert len(ids)==len(sources)==1 and all(e['window']==e['pointer']['Target']==ready['Window']for e in pointer)
 assert down[0]['pointer']['Flags']&0x10000 and down[0]['pointer']['Flags']&4 and up[0]['pointer']['Flags']&0x40000 and not(up[0]['pointer']['Flags']&4)
 summary['consumer_down_move_up_verified']=True
 width,height=ready['Width'],ready['Height'];expected=[(12328/24400*width,(1-10989/22680)*height),(2967/24400*width,(1-19107/22680)*height),(21559/24400*width,(1-19781/22680)*height)]
 samples=[]
 for e in pointer:
  samples.append(e['pointer'])
  assert not e.get('history_truncated',False)and'history_error'not in e
  samples.extend(e.get('history',[]))
 matches=[]
 for x,y in expected:matches.append(any(abs(p['RawPixel']['X']-x)<=3 and abs(p['RawPixel']['Y']-y)<=3 for p in samples))
 assert all(matches),{'expected_pixels':expected,'observed_raw':[p['RawPixel']for p in samples]};summary['all_three_saved_positions_seen']=True
 last=up[0]['pointer']['RawPixel'];assert abs(last['X']-expected[-1][0])<=3 and abs(last['Y']-expected[-1][1])<=3
 owned=N.s['caps_ready']['owned_HID_interfaces'][0]['interface_path'].casefold();names={e['source_device_name'].casefold()for e in pointer if e.get('source_device_name')};assert names=={owned},names;summary['source_matches_owned_HID_interface']=True
 summary.update(pointer_id=next(iter(ids)),source_handle=next(iter(sources)),messages=[e['message']for e in pointer],raw_positions=[e['pointer']['RawPixel']for e in pointer],expected_pixels=expected,contact_release_ends_at_last_accepted_position=True,continuous_physical_input_claimed=False)
 s['phase']='native_Windows_consumer_down_move_up_and_owned_source_verified';N.s['phase']='native_consumer_replay_completed'
except Exception as e:
 summary['verification_failure']=str(e);s['phase']='native_replay_evidence_requires_analysis_no_replay';N.s['phase']='native_consumer_replay_failed'
s['summary']=summary;R.persist();N.s['replay_summary']=summary;N.s['replay_evidence']='replay-native.json';N.persist();print(json.dumps({'phase':s['phase'],'summary':summary}))
