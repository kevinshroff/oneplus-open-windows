"""Install/query the sealed recorder only inside the proved G63 RAM session."""
from pathlib import Path
import hashlib,json,uuid
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';B=W.parent/'resources-G63'
boot=json.loads((W/'boot-ram.json').read_text())
assert boot['phase']=='fresh_boot_root_and_all_protected_metadata_verified'and boot['root']['x_is_ramdisk']and boot['all_six_GPTs_byte_identical_to_baseline']
assert boot['API_DSDT']=={'bytes':730,'sha256':'cdc95eadbedcaf60088741e36803b9c96297ccc72afa48b2adb5d9b9c3205ece','exact_expected_table':True}
R=Relay('native-resource-recorder.json',phone_session=boot['session']);s=R.s
if'token'not in s:s['token']=uuid.uuid4().hex;R.persist()
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def op(label,action,**kw):
    r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
def stage(label,p,remote,expected):
    assert sha(p)==expected
    assert op('put-'+label,'put',file=p,path=remote)['sha256']==expected
    assert op('hash-'+label,'hash',path=remote)['sha256']==expected
setup=r'X:\OpenG17\payloads\G64-setup.exe'
stage('setup',P/'setup-02/g64-setup-arm64.exe',setup,'7e490e4cfe999b5a1a08471417fbf14caa13b5e64c9dfe9e9a3c0254ba601203')
v=json.loads(op('RAM-description','exec',argv=[setup,'describe'])['output']);assert v['ok'];s['description']=v;R.persist()
manifest=B/'private/package.json';assert sha(manifest)=='db82ea3d266206c41401e6274f77a2d763dadf4a93f2687dbf83d70eed253dd9';m=json.loads(manifest.read_text())
base=r'X:\OpenG17\payloads\G64-G63-package'
for name,p in [('package.json',manifest),('OpenG63.sys',B/'private/G63-signed.sys'),('OpenG63.inf',B/'OpenG63.inf'),('OpenG63.cat',B/'private/OpenG63.cat'),('G63-public.cer',B/'private/G63-public.cer')]:
    stage(name,p,base+'\\'+name,sha(manifest)if name=='package.json'else m['files'][name])
for phase in ['trust','stage','bind']:
    r=R.op('single-'+phase,'phone','exec',argv=[setup,phase,s['token']],timeout=180)
    s[phase+'_result']=json.loads(r['output'])if r.get('output')else None;R.persist()
    assert r['status']=='ok'and r.get('exit_code',0)==0 and s[phase+'_result']['ok'],r
    if phase=='bind':assert s[phase+'_result']['result']['result']['bound']and not s[phase+'_result']['result']['result']['reboot_requested']
query=r'X:\OpenG17\payloads\G63-admin.exe'
stage('query',B/'private/admin-01/g63-admin-arm64.exe',query,'ecaca80bff976c4b367c2efda41669fe59ee87b36755ea1ce92aab69b5643757')
r=R.op('single-resource-capture','phone','exec',argv=[query,'capture',s['token']])
s['capture_result']=json.loads(r['output'])if r.get('output')else None;R.persist()
# Preserve raw bytes even if the strict decoder rejects a native descriptor.
remote=r'X:\OpenG17\payloads\G63-assigned-'+s['token']+'.bin'
raw=P/'G63-native-assigned.bin';get=R.op('retain-raw-resource-capture','phone','get',path=remote,save=raw)
assert get['status']=='ok'and raw.stat().st_size==608
s['raw_resource_sha256']=sha(raw);R.persist()
assert r['status']=='ok'and r.get('exit_code',0)==0 and s['capture_result']['ok'],r
assert s['capture_result']['result']['bytes']==608 and s['capture_result']['result']['sha256']==sha(raw)
op('copy-RAM-setup-log','exec',argv=['cmd.exe','/d','/c',r'copy /b X:\Windows\INF\setupapi.dev.log X:\OpenG17\payloads\G64-setupapi.dev.log'])
op('retain-RAM-setup-log','get',path=r'X:\OpenG17\payloads\G64-setupapi.dev.log',save=P/'G64-RAM-setupapi.dev.log')
op('post-query-health','probe')
s.update(phase='native_KMDF_raw_and_translated_resource_capture_retained',session=boot['session'],native_resource_handoff_qualified=True,hardware_mapping_or_register_operation_performed=False,interrupt_delivery_qualified=False,DMA_or_SPI_function_qualified=False,certificate_scope='RAM-only phone session',host_trust_changed=False)
R.persist();print(json.dumps({k:s[k]for k in ['phase','raw_resource_sha256','native_resource_handoff_qualified','interrupt_delivery_qualified']}),flush=True)
