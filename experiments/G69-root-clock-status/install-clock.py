"""Install the exact G69 package in a proved RAM boot, then capture without MMIO."""
from pathlib import Path
import hashlib,json,re,subprocess,sys,uuid
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';B=W
boot=json.loads((W/'boot-resource.json').read_text())
assert boot['phase']=='fresh_boot_root_and_all_protected_metadata_verified'and boot['root']['x_is_ramdisk']and boot['all_six_GPTs_byte_identical_to_baseline']
assert boot['API_DSDT']=={'bytes':742,'sha256':'1682de06510a8dc8f1d82a10be035e3ac9e8ecbd5b116f0ad160d8f43e1832f1','exact_expected_table':True}
R=Relay('native-clock.json',phone_session=boot['session']);s=R.s
for name in ['setup_token','before_nonce','cycle_nonce']:
 if name not in s:s[name]=uuid.uuid4().hex;R.persist()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def op(label,action,**kw):
 r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
def stage(label,p,remote,expected):
 assert sha(p)==expected
 assert op('put-'+label,'put',file=p,path=remote)['sha256']==expected
 assert op('hash-'+label,'hash',path=remote)['sha256']==expected
def retain_log():
 op('copy-RAM-setup-log','exec',argv=['cmd.exe','/d','/c',r'copy /b X:\Windows\INF\setupapi.dev.log X:\OpenG17\payloads\G69-setupapi.dev.log'])
 op('retain-RAM-setup-log','get',path=r'X:\OpenG17\payloads\G69-setupapi.dev.log',save=P/'G69-RAM-setupapi.dev.log')
 op('post-install-health','probe')
setup=r'X:\OpenG17\payloads\G69-setup.exe'
stage('setup',P/'setup-01/g69-setup-arm64.exe',setup,'8c22ead52b5e44f1f67894f1aca7226cafb3b495ddd8793d5d095343c193f6de')
v=json.loads(op('RAM-description','exec',argv=[setup,'describe'])['output']);assert v['ok'];s['description']=v;R.persist()
manifest=B/'private/package.json';assert sha(manifest)=='718bd9e634d0c5fcf709fc30401a98fc65431578dd8d78fb723fe8267921d56f'
m=json.loads(manifest.read_text());assert m['hardware_id']==r'ACPI\OPEN0067'
base=r'X:\OpenG17\payloads\G69-clock-package'
for name,p in [('package.json',manifest),('OpenG69.sys',B/'private/G69-signed.sys'),('OpenG69.inf',B/'OpenG69.inf'),('OpenG69.cat',B/'private/OpenG69.cat'),('G69-public.cer',B/'private/G69-public.cer')]:
 stage(name,p,base+'\\'+name,sha(manifest)if name=='package.json'else m['files'][name])
for phase in ['trust','stage','bind']:
 r=R.op('single-'+phase,'phone','exec',argv=[setup,phase,s['setup_token']],timeout=180)
 s[phase+'_result']=json.loads(r['output'])if r.get('output')else None;R.persist()
 if r['status']!='ok' or r.get('exit_code',0)!=0 or not s[phase+'_result']['ok']:
  retain_log();s.update(phase='native_clock_'+phase+'_failed_evidence_retained',native_cycle_qualified=False);R.persist()
  raise RuntimeError('Native '+phase+' failed; retain the exact receipt and log without replay.')
 if phase=='bind':assert s[phase+'_result']['result']['result']['bound']and not s[phase+'_result']['result']['result']['reboot_requested']
image=op('inspect-bound-service-image-path','exec',argv=[r'X:\Windows\System32\reg.exe','query',r'HKLM\SYSTEM\CurrentControlSet\Services\OpenG69','/v','ImagePath'])
match=re.search(r'(?im)^\s*ImagePath\s+REG_EXPAND_SZ\s+(\\SystemRoot\\System32\\DriverStore\\FileRepository\\openg69\.inf_arm64_[0-9a-f]{16}\\OpenG69\.sys)\s*$',image['output'])
assert match,'Service image must resolve to the exact ARM64 Driver Store package'
path=r'X:\Windows'+match[1][len(r'\SystemRoot'):]
assert op('bound-driver-store-file-hash','hash',path=path)['sha256']==m['files']['OpenG69.sys']
s['native_driver_image_path']=path;R.persist()
retain_log()
client=r'X:\OpenG17\payloads\G69-client.exe'
stage('client',B/'private/G69-client.exe',client,'73c18aaa1367a6bdf8400f0743ed3beb158928a9c7de1c1b9aee33371a92dc64')
r=R.op('single-query-before-cycle','phone','exec',argv=[client,'query',s['before_nonce']])
s['before_query_result']=json.loads(r['output'])if r.get('output')else None;R.persist()
assert r['status']=='ok'and r.get('exit_code',0)==0 and s['before_query_result']['ok'],r
remote=r'X:\OpenG17\payloads\G69-clock-'+s['before_nonce']+'.bin'
op('retain-before-packet','get',path=remote,save=P/'G69-native-before.bin')
assert (P/'G69-native-before.bin').stat().st_size==1872
subprocess.run([sys.executable,str(W/'audit-native.py'),'before'],check=True)
s.update(phase='native_resource_admission_and_cached_query_verified_no_clock_cycle_yet',native_cycle_qualified=False,certificate_scope='RAM-only phone session');R.persist()
print(s['phase'],flush=True)
