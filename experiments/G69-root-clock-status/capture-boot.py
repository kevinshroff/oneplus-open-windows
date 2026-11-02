"""Adopt a fresh recorded resource or original G17 boot and verify its metadata."""
from pathlib import Path
import argparse,hashlib,json,sqlite3,struct,time,zipfile,zlib
from relay import Relay,SESSIONS
W=Path(__file__).resolve().parent;P=W/'private';cli=argparse.ArgumentParser();cli.add_argument('kind',choices=['initial','maintenance','resource','physical']);a=cli.parse_args()
kind=a.kind;state=W/('boot-'+kind+'.json')
if kind=='initial':
    old=None
elif kind=='maintenance':
    trigger=json.loads((W/'maintenance-activation.json').read_text());assert 'single-maintenance-reboot'in trigger['jobs'];old=json.loads((W/'boot-initial.json').read_text())['session']
elif kind=='resource':
    trigger=json.loads((W/'resource-activation.json').read_text());assert 'single-resource-reboot'in trigger['jobs'];old=json.loads((W/'boot-initial.json').read_text())['session']
else:
    trigger=json.loads((W/'return-to-G17.json').read_text());assert 'single-return-reboot'in trigger['jobs'];old=json.loads((W/'boot-resource.json').read_text())['session']
with sqlite3.connect(W.parent.parent/'control-G17/private/queue.sqlite3')as db:
    sid,seen=db.execute("select session,seen from nodes where node='phone'").fetchone()
assert time.time()-seen<15,'Control heartbeat stale'
assert sid!=old if old else sid==SESSIONS['phone'],'Unexpected session; observe before proceeding'
R=Relay(state.name,phone_session=sid);s=R.s
s.update(session=sid,previous_session=old,expected=kind);R.persist()
def op(label,action,**kw):
    r=R.op(label,'phone',action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
probe=op('fresh-health','probe');assert probe['detail']['arch']=='arm64'and probe['detail']['cpus']==8 and probe['detail']['system_root'].lower()==r'x:\windows'
if kind in ('maintenance','resource'):
    import re
    reg=op('small-native-RAM-boot-witness','exec',argv=[r'X:\Windows\System32\reg.exe','query',r'HKLM\SYSTEM\CurrentControlSet\Control','/v','SystemBootDevice'])
    assert re.search(r'(?im)^\s*SystemBootDevice\s+REG_SZ\s+ramdisk\(0\)\s*$',reg['output']),reg
    s['small_native_RAM_boot_witness']=True;R.persist()
prefix='G64' if kind in ('initial','physical') else 'G68'
for label,local,remote,expected in [
 ('witness',W.parent/'ram-witness-arm64.exe',prefix+'-root-witness.exe','3d8bbf8b451adc041dcc0b59772170f1f2895d9006daad251e4bf8bb8296387a'),
 ('metadata',W.parent/'firmware-trial/readonly-probe-arm64.exe',prefix+'-readonly-probe.exe','935b2605f8afec8c2882b671d391f6cd291de4dbcd97062e3cf55cb53e1eb19b')]:
    assert hashlib.sha256(local.read_bytes()).hexdigest()==expected
    if kind in ('initial','physical'):
        assert op('existing-'+label+'-hash','hash',path='X:\\OpenG17\\payloads\\'+remote)['sha256']==expected
    else:
        assert op('stage-'+label,'put',file=local,path=remote)['sha256']==expected
root=json.loads(op('independent-root-witness','exec',argv=['X:\\OpenG17\\payloads\\'+prefix+'-root-witness.exe'])['output'])
assert root['raw_disk_handles']==root['raw_writes']==0 and not root['registry_query_error']
if kind in ('maintenance','resource'):assert root['x_is_ramdisk']and'ramdisk(0)'in root['system_boot_device_registry']
else:assert not root['x_is_ramdisk']and'rdisk(0)partition(6)'in root['system_boot_device_registry']
s['root']=root;s['phase']='fresh_session_root_verified';R.persist()
remote=r'X:\OpenG17\payloads\G69-'+kind+'-metadata.zip'
r=op('capture-protected-metadata','exec',argv=['X:\\OpenG17\\payloads\\'+prefix+'-readonly-probe.exe',remote],timeout=120)
import re
m=re.search(r'bytes=(\d+) sha256=([a-f0-9]{64})',r['output']);assert m
local=P/('G69-'+kind+'-metadata.zip');op('retain-protected-metadata','get',path=remote,save=local)
sha=lambda b:hashlib.sha256(b).hexdigest()
assert local.stat().st_size==int(m[1])and sha(local.read_bytes())==m[2]
base=W.parent/'firmware-trial/private/native-restored-20261021T025351Z.zip'
with zipfile.ZipFile(base)as za,zipfile.ZipFile(local)as zb:
    assert za.testzip()is None and zb.testzip()is None
    ar,br=[json.loads(z.read('report.json'))for z in [za,zb]]
    assert br['raw_disk_write_calls']==br['write_ioctls']==0
    ad={d['disk_guid']:d for d in ar['disks']};bd={d['disk_guid']:d for d in br['disks']}
    assert len(ad)==len(bd)==6 and ad.keys()==bd.keys();checks=[]
    for guid in ad:
        x,y=ad[guid],bd[guid]
        for key in ['length_bytes','geometry_length_bytes','logical_sector_bytes','partition_count','partitions']:assert x[key]==y[key],(guid,key)
        assert y['logical_sector_bytes']==4096
        oldg={Path(t['capture']['file']).name:t for t in x['raw_gpt_double_reads']}
        newg={Path(t['capture']['file']).name:t for t in y['raw_gpt_double_reads']}
        assert len(oldg)==len(newg)==5 and oldg.keys()==newg.keys()
        for n in oldg:
            t=newg[n];b=zb.read(t['capture']['file'])
            assert t['equal']and len(b)==t['first_bytes']==t['second_bytes']==t['bytes_requested']
            assert sha(b)==t['first_sha256']==t['second_sha256']==t['capture']['sha256']and b==za.read(oldg[n]['capture']['file'])
            if b[:8]==b'EFI PART':
                size=struct.unpack_from('<I',b,12)[0];h=bytearray(b[:size]);h[16:20]=bytes(4)
                assert zlib.crc32(h)==struct.unpack_from('<I',b,16)[0]
        checks.append({'disk_guid':guid,'byte_identical_regions':5,'partition_count':y['partition_count']})
    def tables(z,report):
        result={}
        for t in report['firmware']['tables']:
            if 'capture'not in t:continue
            b=z.read(t['capture']['file'])
            assert len(b)==struct.unpack_from('<I',b,4)[0]and sum(b)%256==0 and sha(b)==t['capture']['sha256']
            result[t['signature']]=b
        return result
    at,bt=tables(za,ar),tables(zb,br);assert at.keys()==bt.keys()
    for name in ['IORT','APIC','MCFG','CSRT','GTDT','PPTT','SSDT']:assert at[name]==bt[name],name
    o=bt['OGPT'];assert o[16:24]==b'GPTG16  ';tx=o[512:692]
    assert tx[:8]==b'OPG16TX\0'and struct.unpack_from('<IIQII',tx,8)==(10,2,0,0,0)
    expected=(W.parent/'clock-owner-G67/private/acpi-02/acpitabl.dat').read_bytes() if kind=='resource' else at['DSDT']
    assert bt['DSDT']==expected
    s['API_DSDT']={'bytes':len(expected),'sha256':sha(expected),'exact_expected_table':True}
    s.update(all_six_GPTs_byte_identical_to_baseline=True,GPT_checks=checks,partition_count=sum(d['partition_count']for d in bd.values()),G16_reported_zero_GPT_writes=True)
    assert s['partition_count']==138
s.update(phase='fresh_boot_root_and_all_protected_metadata_verified',native_capture_file=str(local),native_capture_sha256=m[2]);R.persist()
print(json.dumps({k:s[k]for k in ['phase','expected','session','all_six_GPTs_byte_identical_to_baseline','partition_count','API_DSDT']}),flush=True)
