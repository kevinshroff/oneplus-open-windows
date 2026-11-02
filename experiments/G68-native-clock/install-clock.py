"""Install the exact G67 package in a proved RAM boot, then capture without MMIO."""
from pathlib import Path
import hashlib,json,re,subprocess,sys,uuid
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';B=W.parent/'clock-owner-G67'
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
 op('copy-RAM-setup-log','exec',argv=['cmd.exe','/d','/c',r'copy /b X:\Windows\INF\setupapi.dev.log X:\OpenG17\payloads\G68-setupapi.dev.log'])
 op('retain-RAM-setup-log','get',path=r'X:\OpenG17\payloads\G68-setupapi.dev.log',save=P/'G68-RAM-setupapi.dev.log')
 op('post-install-health','probe')
setup=r'X:\OpenG17\payloads\G68-setup.exe'
stage('setup',P/'setup-01/g68-setup-arm64.exe',setup,'853f949d22ffa1692624401c939bbb7b3c505f765e9bcd231fc44c764660d33c')
v=json.loads(op('RAM-description','exec',argv=[setup,'describe'])['output']);assert v['ok'];s['description']=v;R.persist()
manifest=B/'private/package.json';assert sha(manifest)=='26b0a84d18d8d6d460cefbca609f3975783a0b28d7f4e0cbdddc6dca4017a757'
m=json.loads(manifest.read_text());assert m['hardware_id']==r'ACPI\OPEN0067'
base=r'X:\OpenG17\payloads\G68-G67-package'
for name,p in [('package.json',manifest),('OpenG67.sys',B/'private/G67-signed.sys'),('OpenG67.inf',B/'OpenG67.inf'),('OpenG67.cat',B/'private/OpenG67.cat'),('G67-public.cer',B/'private/G67-public.cer')]:
 stage(name,p,base+'\\'+name,sha(manifest)if name=='package.json'else m['files'][name])
for phase in ['trust','stage','bind']:
 r=R.op('single-'+phase,'phone','exec',argv=[setup,phase,s['setup_token']],timeout=180)
 s[phase+'_result']=json.loads(r['output'])if r.get('output')else None;R.persist()
 if r['status']!='ok' or r.get('exit_code',0)!=0 or not s[phase+'_result']['ok']:
  retain_log();s.update(phase='native_clock_'+phase+'_failed_evidence_retained',native_cycle_qualified=False);R.persist()
  raise RuntimeError('Native '+phase+' failed; retain the exact receipt and log without replay.')
 if phase=='bind':assert s[phase+'_result']['result']['result']['bound']and not s[phase+'_result']['result']['result']['reboot_requested']
image=op('inspect-bound-service-image-path','exec',argv=[r'X:\Windows\System32\reg.exe','query',r'HKLM\SYSTEM\CurrentControlSet\Services\OpenG67','/v','ImagePath'])
match=re.search(r'(?im)^\s*ImagePath\s+REG_EXPAND_SZ\s+(\\SystemRoot\\System32\\DriverStore\\FileRepository\\openg67\.inf_arm64_[0-9a-f]{16}\\OpenG67\.sys)\s*$',image['output'])
assert match,'Service image must resolve to the exact ARM64 Driver Store package'
path=r'X:\Windows'+match[1][len(r'\SystemRoot'):]
assert op('bound-driver-store-file-hash','hash',path=path)['sha256']==m['files']['OpenG67.sys']
s['native_driver_image_path']=path;s['driver_path_correction']='INF DIRID13 and actual service ImagePath used; original guessed System32/drivers check was missing-file only, no install phase replayed.';R.persist()
retain_log()
client=r'X:\OpenG17\payloads\G67-client.exe'
stage('client',B/'private/G67-client-v5.exe',client,'1560529b8c0d46eabb54825a4cedaf07c743746f8df08b211a0e43c963116a87')
r=R.op('single-query-before-cycle','phone','exec',argv=[client,'query',s['before_nonce']])
s['before_query_result']=json.loads(r['output'])if r.get('output')else None;R.persist()
assert r['status']=='ok'and r.get('exit_code',0)==0 and s['before_query_result']['ok'],r
remote=r'X:\OpenG17\payloads\G67-clock-'+s['before_nonce']+'.bin'
op('retain-before-packet','get',path=remote,save=P/'G67-native-before.bin')
assert (P/'G67-native-before.bin').stat().st_size==1872
subprocess.run([sys.executable,str(W/'audit-native.py'),'before'],check=True)
s.update(phase='native_resource_admission_and_cached_query_verified_no_clock_cycle_yet',native_cycle_qualified=False,certificate_scope='RAM-only phone session');R.persist()
print(s['phase'],flush=True)
