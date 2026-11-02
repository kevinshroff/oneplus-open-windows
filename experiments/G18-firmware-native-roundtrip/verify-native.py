"""Independently compare executed firmware and every captured GPT to pretrial data."""
from pathlib import Path
import hashlib,json,struct,sys,uuid,zipfile,zlib
W=Path(__file__).resolve().parent;R=W.parents[2];OUT=R/'outputs/bringup-20261020/maintenance-G18'
label=sys.argv[1];assert label in ['trial','restored']
a=json.loads(sorted(OUT.glob('firmware-trial-native-before-*.json'))[-1].read_text());b=json.loads(sorted(OUT.glob('firmware-trial-native-'+label+'-*.json'))[-1].read_text())
witness=json.loads(sorted(OUT.glob('firmware-trial-'+label+'-boot-witness-*.json'))[-1].read_text());assert b['session']==witness['session'] and b['session']!=a['session']
expected='GPTG18T1' if label=='trial' else 'GPTG16  '
assert b['phase']=='native_readonly_capture_verified' and b['acpi_oem_table_id']==expected
sha=lambda b:hashlib.sha256(b).hexdigest()
with zipfile.ZipFile(R/a['private_file']) as za,zipfile.ZipFile(R/b['private_file']) as zb:
 assert za.testzip() is None and zb.testzip() is None
 ar,br=[json.loads(z.read('report.json')) for z in [za,zb]]
 assert br['raw_disk_write_calls']==br['write_ioctls']==0 and len(br['disks'])==6
 ad={d['disk_guid']:d for d in ar['disks']};bd={d['disk_guid']:d for d in br['disks']};assert len(ad)==len(bd)==6 and ad.keys()==bd.keys()
 checks=[]
 for guid in ad:
  x,y=ad[guid],bd[guid]
  for k in ['length_bytes','geometry_length_bytes','logical_sector_bytes','partition_count','partitions']:assert x[k]==y[k],(guid,k)
  assert y['logical_sector_bytes']==4096
  old={Path(p['capture']['file']).name:p for p in x['raw_gpt_double_reads']}
  new={Path(p['capture']['file']).name:p for p in y['raw_gpt_double_reads']};assert len(old)==len(new)==5 and old.keys()==new.keys()
  for n in old:
   p=new[n];raw=zb.read(p['capture']['file']);assert p['equal'] and len(raw)==p['first_bytes']==p['second_bytes']==p['bytes_requested']
   assert sha(raw)==p['first_sha256']==p['second_sha256']==p['capture']['sha256']
   assert raw==za.read(old[n]['capture']['file']),(guid,n)
   if raw[:8]==b'EFI PART':
    size=struct.unpack_from('<I',raw,12)[0];assert 92<=size<=4096
    h=bytearray(raw[:size]);h[16:20]=bytes(4);assert zlib.crc32(h)==struct.unpack_from('<I',raw,16)[0]
    assert str(uuid.UUID(bytes_le=raw[56:72]))==guid
  checks.append({'disk_guid':guid,'raw_regions_byte_identical':5,'partition_count':y['partition_count'],'ioctl_layout_unchanged':True})
 def tables(z,report):
  result={}
  for t in report['firmware']['tables']:
   if 'capture' not in t:continue
   raw=z.read(t['capture']['file']);assert len(raw)==struct.unpack_from('<I',raw,4)[0] and sum(raw)%256==0 and sha(raw)==t['capture']['sha256'] and raw[:4].decode()==t['signature']
   assert t['signature'] not in result;result[t['signature']]=raw
  return result
 at,bt=tables(za,ar),tables(zb,br)
 assert at.keys()==bt.keys()
 critical=['DSDT','IORT','APIC','MCFG','CSRT','GTDT','PPTT','SSDT']
 for n in critical:assert at[n]==bt[n],('unexpected platform ACPI change',n)
 ogpt=bt['OGPT'];assert ogpt[16:24].decode()==expected and ogpt[36:44]==b'OPG15V1\0' and len(ogpt)==24576
 assert struct.unpack_from('<I',ogpt,48)[0]==0x7f and struct.unpack_from('<II',ogpt,108)==(5,48)
 tx=ogpt[512:692]
 if label=='trial':assert tx==bytes(180)
 else:
  assert tx[:8]==b'OPG16TX\0' and struct.unpack_from('<IIQII',tx,8)==(10,2,0,0,0)
 # Every published firmware snapshot sector must equal the current raw LUN0
 # capture as well as the verified exact G16 corrected baseline.
 d=next(d for d in br['disks'] if d['disk_guid']=='bc5c99e5-16e0-14b8-b43a-de06f8ea711b')
 reads={p['lba']:p for p in d['raw_gpt_double_reads']}
 for i in range(5):
  kind,flags,lba,n,off,s1,s2,c1,c2=struct.unpack_from('<IIQIIQQII',ogpt,116+i*48)
  assert kind==i and flags==7 and s1==s2==0 and n==4096 and off>=4096 and off+n<=len(ogpt)
  raw=ogpt[off:off+n];assert zlib.crc32(raw)==c1==c2 and raw==zb.read(reads[lba]['capture']['file'])
r={'label':label,'phase':'executed_firmware_and_protected_metadata_verified','session':b['session'],'native_capture_receipt':str(sorted(OUT.glob('firmware-trial-native-'+label+'-*.json'))[-1].relative_to(R)),'executed_firmware_marker':expected,'all_six_GPTs_byte_identical_to_before':True,'GPT_region_comparisons':checks,'total_partitions':sum(c['partition_count'] for c in checks),'critical_platform_ACPI_byte_identical':critical,'mode9_migration_record_zero':label=='trial','firmware_GPT_snapshots_match_current_raw_and_baseline':True,'restored_G16_reported_zero_GPT_writes':label=='restored','native_session_system_device':witness['system_device']['x_device'],'native_capture_sha256':b['zip_sha256']}
p=W/('native-'+label+'-verification.json');assert not p.exists();p.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
