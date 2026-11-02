"""Fresh original-G17 root, helper refusal, protected metadata and FAT backups."""
from pathlib import Path
import hashlib,json,re,zipfile
from relay import Relay

W=Path(__file__).resolve().parent;P=W/'private';R=Relay('native-preflight-v2.json');s=R.s
sha=lambda b:hashlib.sha256(b).hexdigest()
def op(label,action,**kw):
    r=R.op(label,'phone',action,**kw)
    assert r['status']=='ok' and r.get('exit_code',0)==0,r
    return r
def native(label,args):
    r=op(label,'exec',argv=[r'X:\OpenG17\payloads\G18-disktool-r4.exe',*args],timeout=180)
    return json.JSONDecoder().raw_decode(r['output'].lstrip())[0]
for label,local,remote,expected in [
    ('root',W.parent/'ram-witness-arm64.exe','G64-root-witness.exe','3d8bbf8b451adc041dcc0b59772170f1f2895d9006daad251e4bf8bb8296387a'),
    ('probe',W.parent/'firmware-trial/readonly-probe-arm64.exe','G64-readonly-probe.exe','935b2605f8afec8c2882b671d391f6cd291de4dbcd97062e3cf55cb53e1eb19b'),
    ('r4',W.parent/'disktool-arm64-r4.exe','G18-disktool-r4.exe','7b944d4bf025423ab213b4ad133f8f9b59acd1e787b1875b551bc9735dfc902f'),
    ('r5',W.parent/'gpio-G21/private/G21-disktool-r5.exe','G21-disktool-r5.exe','db925d3106b153f9688cfaef4b08e15851dc3c8939e4f6652ea754b2774e51c1'),
    ('setup',P/'setup-02/g64-setup-arm64.exe','G64-setup.exe','7e490e4cfe999b5a1a08471417fbf14caa13b5e64c9dfe9e9a3c0254ba601203')]:
    assert sha(local.read_bytes())==expected
    assert op('stage-'+label,'put',file=local,path=remote)['sha256']==expected
    assert op('hash-'+label,'hash',path='X:\\OpenG17\\payloads\\'+remote)['sha256']==expected
root=json.loads(op('physical-root','exec',argv=[r'X:\OpenG17\payloads\G64-root-witness.exe'])['output'])
assert not root['x_is_ramdisk'] and 'rdisk(0)partition(6)'in root['system_boot_device_registry']
assert root['raw_disk_handles']==root['raw_writes']==0
s['root']=root;R.persist()
cleanup=r'X:\OpenG17\payloads\G59-cleanup.exe'
before=json.loads(op('software-before','exec',argv=[cleanup,'audit'])['output'])['result']
assert before==json.loads((W.parent/'resources-G63/normal-G17-refusal.json').read_text())['audit_after']
r=R.op('setup-original-root-refusal','phone','exec',argv=[r'X:\OpenG17\payloads\G64-setup.exe','describe'])
assert r['status']=='error'and r['exit_code']==1,r
negative=json.loads(r['output']);assert not negative['ok']and'G64 setup requires'in negative['error']
assert negative['result']['environment']['DSDT_bytes']==576
assert negative['result']['environment']['DSDT_sha256']=='c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01'
after=json.loads(op('software-after','exec',argv=[cleanup,'audit'])['output'])['result'];assert before==after
s.update(setup_refuses_original_G17_before_mutation=True,software_before=before,software_after=after);R.persist()
remote=r'X:\OpenG17\payloads\G64-preflight-v2-metadata.zip'
r=op('capture-metadata','exec',argv=[r'X:\OpenG17\payloads\G64-readonly-probe.exe',remote],timeout=120)
m=re.search(r'bytes=(\d+) sha256=([a-f0-9]{64})',r['output']);assert m
local=P/'G64-preflight-v2-metadata.zip';op('download-metadata','get',path=remote,save=local)
assert local.stat().st_size==int(m[1])and sha(local.read_bytes())==m[2]
base=W.parent/'firmware-trial/private/native-restored-20261021T025351Z.zip';checks=[]
with zipfile.ZipFile(base)as a,zipfile.ZipFile(local)as b:
    assert a.testzip()is None and b.testzip()is None
    ar,br=[json.loads(z.read('report.json'))for z in [a,b]]
    assert br['raw_disk_write_calls']==br['write_ioctls']==0
    ad={d['disk_guid']:d for d in ar['disks']};bd={d['disk_guid']:d for d in br['disks']}
    assert len(ad)==len(bd)==6 and ad.keys()==bd.keys()
    for guid in ad:
        x,y=ad[guid],bd[guid]
        for k in ['length_bytes','geometry_length_bytes','logical_sector_bytes','partition_count','partitions']:assert x[k]==y[k]
        old={Path(t['capture']['file']).name:t for t in x['raw_gpt_double_reads']}
        new={Path(t['capture']['file']).name:t for t in y['raw_gpt_double_reads']}
        assert len(old)==len(new)==5 and old.keys()==new.keys()
        for k in old:
            t=new[k];data=b.read(t['capture']['file'])
            assert t['equal']and data==a.read(old[k]['capture']['file'])
            assert sha(data)==t['first_sha256']==t['second_sha256']==t['capture']['sha256']
        checks.append({'disk_guid':guid,'byte_identical_regions':5,'partition_count':y['partition_count']})
    t=next(t for t in br['firmware']['tables']if t['signature']=='DSDT'and'capture'in t)
    dsdt=b.read(t['capture']['file']);assert len(dsdt)==576 and sha(dsdt)=='c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01'
s.update(GPT_checks=checks,partition_count=sum(d['partition_count']for d in bd.values()),all_six_GPTs_byte_identical=True,original_DSDT_active=True,metadata_sha256=m[2]);assert s['partition_count']==138;R.persist()
s['protected_boot_hashes']={}
for name,expected in [('boot_a','f52c793d01d73eb773bc2f442cdf6eefcd6b7ee395e3af290c8147fefd8caa8e'),('boot_b','07dba7ac86e02ea0ff628250991d638da09b8e0680886aee1933df8f56bc4d3b')]:
    r=native('full-'+name,['hash',name,'0','201326592']);assert r['sha256']==expected and r['raw_writes']==0
    s['protected_boot_hashes'][name]=r;R.persist()
r=native('original-maintenance-WIM',['filehash',r'X:\OpenG18\G18-maintenance.wim']);assert r['sha256']=='1db2c5d735281ddcb11f1723bb729753e81a74793a495a83c0bece2ffd26d7e9';s['original_G18_WIM']=r;R.persist()
r=native('inactive-trial-source',['filehash',r'X:\OpenG18\G20-acpi-canary.wim']);assert r['sha256']=='bf8da75a5ff96af9c65fb5f059e6cbb8206595aeeee9c5057e31e31bd4e30250'and r['bytes']==592882167;s['inactive_trial_source']=r;R.persist()
prefix=r'X:\OpenG17\payloads\G64-FAT-preflight-v2'
manifest=native('fresh-FAT-backup',['backup','userdata','0','268435456',prefix]);s['FAT_manifest']=manifest;R.persist()
raw=bytearray()
for i,piece in enumerate(manifest['pieces']):
    assert re.fullmatch(re.escape(prefix)+r'-\d{3}\.zip',piece['path'])
    path=P/('FAT-v2-piece-%02d.zip'%i);op('FAT-download-%02d'%i,'get',path=piece['path'],save=path)
    assert sha(path.read_bytes())==piece['zip_sha256']
    with zipfile.ZipFile(path)as z:
        assert z.testzip()is None and z.namelist()==['raw.bin'];data=z.read('raw.bin')
    assert sha(data)==piece['raw_sha256']and len(data)==piece['raw_bytes']and len(raw)==piece['offset']
    raw.extend(data)
assert len(raw)==268435456 and sha(raw)==manifest['raw_sha256']
path=P/'userdata-before.img'
if path.exists():assert path.read_bytes()==raw
else:
    with path.open('xb')as f:f.write(raw)
s.update(phase='fresh_original_G17_protected_metadata_and_FAT_verified',file=str(path),sha256=sha(raw),raw_writes=0)
R.persist();print(json.dumps({k:s[k]for k in ['phase','sha256','all_six_GPTs_byte_identical','partition_count','setup_refuses_original_G17_before_mutation']}),flush=True)
