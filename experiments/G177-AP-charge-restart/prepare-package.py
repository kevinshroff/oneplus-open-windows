"""Prepare full immediate software-reboot/native package; no native operations."""
from pathlib import Path
import hashlib,json,py_compile
w=Path(__file__).resolve().parent;p=w/'private';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
old='ba4970cc22f920c0ea929465bc38d05b';host='70ebee492cfe3fb6f43a755c8f60e7ae'
obs=json.loads((p/'host-observation.json').read_text());assert obs['pid']==11960 and obs['pipe']=='OpenG80'and not obs['task_has_trigger']
ready=json.loads((p/'readiness.json').read_text());assert ready['compiled_sources_match']and ready['signed_CMS_verified_by_host']
for n,h in ready['sources'].items():assert sha(w/n)==h,n
for n,h in ready['client_sources'].items():assert sha(w/'client'/n)==h,n
files={n:Path(v['path'])for n,v in ready['files'].items()}
cycle=json.loads((p/'cycle-build.json').read_text())
for n,h in cycle['sources'].items():assert sha(w/'helpers'/n)==h,n
assert sha(p/'G177-cycle.exe')==cycle['sha256'];files['G177-cycle.exe']=p/'G177-cycle.exe'
prior=w.parent/'charging-G170';o=json.loads((prior/'private/observer-build.json').read_text())
for n,h in o['sources'].items():assert sha(prior/'helpers'/n)==h,n
assert sha(prior/'private/G170-observe.exe')==o['sha256'];files['G170-observe.exe']=prior/'private/G170-observe.exe'
for campaign in ['G167','G160','G172']:
 root=w.parent/('charging-'+campaign);a=json.loads((root/'private/signature-and-source-audit.json').read_text());assert a['passed']and a['all_compiled_source_hashes_match']
 for n,h in a.get('source_sha256',{}).items():assert sha(root/'probe'/n)==h,n
 if campaign=='G160':
  compiled=json.loads((root/'private/compile-02/compile.json').read_text());assert compiled['passed']
  for n,h in compiled['sources'].items():assert sha(root/'probe'/n)==h,n
 for n,v in a['files'].items():
  f=Path(v['path']);assert sha(f)==v['sha256'];files[n]=f
for n,h in {'G154-install-arm64.exe':'d6fb3079f3b02aef839724ec783be623af9b8c7c4ca9f8e174e599f2c631d5c7','G155-read-DSP.exe':'c85e5c2d32b0d4dcdaed3d6423eed1177ca67653223e9c3698e42d6ca98236aa'}.items():
 f=w.parent/('charging-G155/private/release/'+n if n.startswith('G154')else'charging-G155/private/'+n);assert sha(f)==h;files[n]=f

# These copies are new one-shot controllers, not replay of consumed jobs.
baseline=w.parent/'charging-G174'
s=(baseline/'Refresh-Debugger-G174.ps1').read_text().replace('G174','G177')
s=s.replace('$expectedPid=[uint32]4468','$expectedPid=[uint32]11960').replace('G170-20261025-232359','G174-20261026-003557')
assert '$expectedPid=[uint32]11960'in s and obs['log']in s
(w/'Refresh-Debugger-G177.ps1').write_text(s)
(w/'Boot-Existing-Image-G177.ps1').write_text((baseline/'Boot-Existing-Image-G174.ps1').read_text().replace('G174','G177'))
(w/'G177-Restore-EEM.ps1').write_bytes((w.parent/'reboot-G154/Restore-Project-EEM.ps1').read_bytes())
for n in ['Refresh-Debugger-G177.ps1','Boot-Existing-Image-G177.ps1','G177-Restore-EEM.ps1']:files[n]=w/n
s=(baseline/'launch-fresh.py').read_text().replace('G174','G177').replace('e79446a6f1d685f8a873cf5de2581d26',old)
s=s.replace('Fresh default-enable baseline: unchanged G155 and fixed readers; optional independently admitted board4470mV correction only. No SET24, no same-boot reopen.','One fresh G155 boot for a fixed AP off/5s/on/90s/off test, only after physical mode/FCC/voltage/temperature and4470mV readback admission. No same-boot reopen.')
(w/'launch-fresh.py').write_text(s)
s=(baseline/'close-current.py').read_text().replace('G174','G177').replace('e79446a6f1d685f8a873cf5de2581d26',old)
s=s.replace("a['last_command_id']==4 and a['state']['PulseDisableAcked']==1", "a['last_command_id']==2 and a['state']['BoardFvAcked']==1 and a['state']['PulseAttempted']==0")
assert "a['last_command_id']==2"in s
(w/'close-current.py').write_text(s)

s=(prior/'native-once.py').read_text().replace('G170','G177').replace('134592','136672')
s=s.replace("choices=['stage','load','start','sample1','sample2','idle','board-fv','charge-pulse','stop-pulse','close','retire']","choices=['stage','load','start','sample1','idle','board-fv']")
begin=s.index(" observer=json.loads",s.index("if args.step=='stage':"));end=s.index(" v=exe('fresh-DSP-report'",begin)
s=s[:begin]+" manifest=json.loads((p/'package.json').read_text())\n for n,item in manifest['files'].items():\n  if Path(n).suffix in ['.exe','.sys']:\n   file=Path(item['path']);assert sha(file)==item['sha256'];q(n+'-phone-put','put',file=file,path=n,timeout=20)\n reader=w.parent/'charging-G155/private/G155-read-DSP.exe'\n"+s[end:]
s=s[:s.index("elif args.step=='close':")]+"s.update(complete=True,completed=time.time());save()\n"
assert "args.step=='charge-pulse'"not in s and 'G177-observe.exe'not in s
(w/'native-once.py').write_text(s)
s=(baseline/'observe-hardware.py').read_text()
s=s.replace("'after-FV-proof.json'","'before-pulse-proof.json'").replace('verified; retain boot default enable; no SET24','verified before fixed AP off/5s/on/90s/off sequence')
point="if args.phase in ['before-fv','after-fv']:"
insertion="""# Independently parse the fixed2640 result byte, not a cache value.
raw=(p/(args.phase+'-G167-raw.bin')).read_bytes();assert len(raw)==1096
enable=raw[184+7*8+6]&1;assert enable==1,'Require boot-default enable1 before this explicit0->1 test'
summary['physical_enable_bit']=enable
"""
s=s.replace(point,insertion+point)
(w/'observe-hardware.py').write_text(s)
for f in w.glob('*.py'):py_compile.compile(str(f),doraise=True)
manifest={'campaign':'G177','purpose':'Fixed one-time AP off/5s/on/90s/off with physical/config captures and automatic kernel finaloff. No generic property/value/duration.','previous_session':old,'host_session':host,'files':{n:{'path':str(f),'sha256':sha(f),'bytes':f.stat().st_size}for n,f in files.items()},'python_sha256':{f.name:sha(f)for f in w.glob('*.py')},'compiled_sources_match':True,'signed_CMS_verified_by_host':True,'partition_flashes':0,'same_boot_PAS_retries':0}
assert len(files)==19
for n,h in cycle['pins'].items():assert manifest['files'][n]['sha256']==h,n
(p/'package.json').write_text(json.dumps(manifest,indent=2)+'\n');print({'files':len(files),'python_syntax':'pass','phone_operations':0})
