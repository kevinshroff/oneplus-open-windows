"""Prepare a fresh default-enable baseline using unchanged qualified tools.

No native command is submitted here. The later controller has no SET24 step.
"""
from pathlib import Path
import hashlib,json,py_compile

w=Path(__file__).resolve().parent;p=w/'private';p.mkdir(exist_ok=True)
prior=w.parent/'charging-G170'
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
obs=json.loads((p/'host-observation.json').read_text())
assert obs['pid']==4468 and obs['pipe']=='OpenG80' and not obs['task_has_trigger']
ready=json.loads((prior/'private/readiness.json').read_text())
assert ready['compiled_sources_match'] and ready['signed_CMS_verified_by_host']
for n,h in ready['sources'].items():assert sha(prior/n)==h,n
for n,h in ready['client_sources'].items():assert sha(prior/'client'/n)==h,n
files={}
for n,item in ready['files'].items():
 f=Path(item['path']);assert sha(f)==item['sha256'];files[n]=f
observer=json.loads((prior/'private/observer-build.json').read_text())
for n,h in observer['sources'].items():assert sha(prior/'helpers'/n)==h,n
f=prior/'private/G170-observe.exe';assert sha(f)==observer['sha256'];files[f.name]=f
for camp in ['G167','G160','G172']:
 root=w.parent/('charging-'+camp)
 audit=json.loads((root/'private/signature-and-source-audit.json').read_text())
 assert audit['passed'] and audit['all_compiled_source_hashes_match']
 for n,h in audit.get('source_sha256',{}).items():assert sha(root/'probe'/n)==h,n
 if camp=='G160':
  compiled=json.loads((root/'private/compile-02/compile.json').read_text());assert compiled['passed']
  for n,h in compiled['sources'].items():assert sha(root/'probe'/n)==h,n
 for n,item in audit['files'].items():
  f=Path(item['path']);assert sha(f)==item['sha256'];files[n]=f
for n,h in {
 'G154-install-arm64.exe':'d6fb3079f3b02aef839724ec783be623af9b8c7c4ca9f8e174e599f2c631d5c7',
 'G155-read-DSP.exe':'c85e5c2d32b0d4dcdaed3d6423eed1177ca67653223e9c3698e42d6ca98236aa',
}.items():
 f=w.parent/('charging-G155/private/release/'+n if n.startswith('G154')else'charging-G155/private/'+n)
 assert sha(f)==h;files[n]=f

ps=(prior/'Refresh-Debugger-G170.ps1').read_text()
ps=ps.replace('$expectedPid=[uint32]4284','$expectedPid=[uint32]4468')
ps=ps.replace('G169-20261025-224600','G170-20261025-232359')
ps=ps.replace("('debug\\G170-'","('debug\\G174-'").replace('G170_INITIAL_ATTACH','G174_INITIAL_ATTACH').replace('G170_fresh_debug_listener','G174_fresh_debug_listener')
assert obs['log']in ps and '$expectedPid=[uint32]4468'in ps
(w/'Refresh-Debugger-G174.ps1').write_text(ps)
ps=(prior/'Boot-Existing-Image-G170.ps1').read_text().replace('G170','G174')
(w/'Boot-Existing-Image-G174.ps1').write_text(ps)
(w/'G174-Restore-EEM.ps1').write_bytes((w.parent/'reboot-G154/Restore-Project-EEM.ps1').read_bytes())
for n in ['Refresh-Debugger-G174.ps1','Boot-Existing-Image-G174.ps1','G174-Restore-EEM.ps1']:files[n]=w/n

# Preserve the proven self-restoring reboot sequence; bind it to this campaign
# and the current session rather than replaying any old native job.
s=(prior/'launch-fresh.py').read_text()
begin=s.index("sha=lambda f:");end=s.index("hostIntent=json.loads")
s=s[:begin]+"manifest=json.loads((p/'package.json').read_text())\nfor n,item in manifest['files'].items():assert hashlib.sha256(Path(item['path']).read_bytes()).hexdigest()==item['sha256'],n\n"+s[end:]
s=s.replace('G170_immediate_launch_ready','G174_immediate_launch_ready').replace('Boot-Existing-Image-G170.ps1','Boot-Existing-Image-G174.ps1')
s=s.replace("oldPhone='84fdac8bbe73daa69a645b32b95bab14'","oldPhone='e79446a6f1d685f8a873cf5de2581d26'")
s=s.replace("helper=w.parent/", "sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()\nclosed=json.loads((p/'old-owner-close-intent.json').read_text());assert closed['complete'] and closed['native_closed_and_unloaded']\nhelper=w.parent/")
s=s.replace('Fresh original DSP advertisement for the fixed4470mV and bounded charge-pulse owner. Old G169 endpoint retired or retained without forced unload; no same-boot reopen.','Fresh default-enable baseline: unchanged G155 and fixed readers; optional independently admitted board4470mV correction only. No SET24, no same-boot reopen.')
(w/'launch-fresh.py').write_text(s)

s=(prior/'close-old-owner.py').read_text().replace('G169','G170').replace('Immediate audited G170 replacement','Immediate audited G174 baseline')
s=s.replace('G170_immediate_launch_ready','G174_immediate_launch_ready').replace("session='00000000000000000000000000000000'","session='00000000000000000000000000000000'")
s=s.replace("capture('old-close','close'", "assert a['last_command_id']==4 and a['state']['PulseDisableAcked']==1 and not a['state']['RpcUncertain'] and not a['state']['TransportUncertain']\ncapture('old-close','close'")
(w/'close-current.py').write_text(s)

# Reuse the qualified start/sample/FV interface, but exclude pulse/stop and
# same-boot restart from this campaign's command vocabulary.
s=(prior/'native-once.py').read_text()
s=s.replace("choices=['stage','load','start','sample1','sample2','idle','board-fv','charge-pulse','stop-pulse','close','retire']","choices=['stage','load','start','sample1','idle','board-fv']")
s=s.replace("ready=json.loads((p/'readiness.json').read_text())","qualified=w.parent/'charging-G170';ready=json.loads((qualified/'private/readiness.json').read_text())")
s=s.replace("sha(p/n)","sha(Path(f['path']))")
s=s.replace("observer=json.loads((p/'observer-build.json').read_text());assert sha(p/'G170-observe.exe')==observer['sha256']","observer=json.loads((qualified/'private/observer-build.json').read_text());assert sha(qualified/'private/G170-observe.exe')==observer['sha256']")
s=s.replace("q(n+'-phone-put','put',file=p/n,path=n,timeout=20)","q(n+'-phone-put','put',file=qualified/'private'/n,path=n,timeout=20)")
s=s.replace("for camp in ['G167','G160']:","for camp in ['G167','G160','G172']:")
s=s[:s.index("elif args.step=='close':")]+"s.update(complete=True,completed=time.time());save()\n"
assert "args.step=='charge-pulse'"not in s
(w/'native-once.py').write_text(s)

s=(prior/'observe-hardware.py').read_text()
s=s.replace("choices=['before-fv','after-fv','during-pulse','after-pulse']","choices=['before-fv','after-fv']")
s=s.replace("observer=json.loads((p/'observer-build.json').read_text());assert sha(p/'G170-observe.exe')==observer['sha256']","observer=json.loads((w.parent/'charging-G170/private/observer-build.json').read_text());assert sha(w.parent/'charging-G170/private/G170-observe.exe')==observer['sha256']")
s=s.replace("verified before one fixed90s enable/disable pulse","verified; retain boot default enable; no SET24")
s=s.replace("'before-pulse-proof.json'","'after-FV-proof.json'")
(w/'observe-hardware.py').write_text(s)

s=(w.parent/'charging-G172/run-native.py').read_text()
s=s.replace("session='00000000000000000000000000000000'","session=json.loads((p/'native-session.json').read_text())['session']")
s=s.replace("audit=json.loads((p/'signature-and-source-audit.json').read_text())","qualified=w.parent/'charging-G172';audit=json.loads((qualified/'private/signature-and-source-audit.json').read_text())")
s=s.replace("sha(w/'probe'/n)","sha(qualified/'probe'/n)").replace("cwd=w/'probe'","cwd=qualified/'probe'")
s=s.replace("existing post-off context","fresh boot default-enable context")
s=s.replace("for n,item in audit['files'].items():q(n+'-put','put',file=Path(item['path']),path=n,timeout=20)","assert json.loads((p/'native-stage-intent.json').read_text())['complete'],'All native files must already be staged'")
(w/'read-effective-input.py').write_text(s)
for f in w.glob('*.py'):py_compile.compile(str(f),doraise=True)
manifest={'campaign':'G174','purpose':'Measure effective input and status with default enable1 in a fresh unchanged G155 boot. No SET24; optional fixed4470 FV only after disjoint physical/mode admission.','previous_session':'00000000000000000000000000000000','host_session':'00000000000000000000000000000000','files':{n:{'path':str(f),'sha256':sha(f),'bytes':f.stat().st_size}for n,f in files.items()},'python_sha256':{f.name:sha(f)for f in w.glob('*.py')},'compiled_sources_match':True,'signed_CMS_verified_by_host':True,'partition_flashes':0,'SET24':0}
(p/'package.json').write_text(json.dumps(manifest,indent=2)+'\n')
print({'files':len(files),'python_syntax':'pass','SET24_steps':0,'phone_operations':0})
