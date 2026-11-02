"""Remove only exact reconstructible local copies; retain preimages and plans."""
from pathlib import Path
import base64,hashlib,json

W=Path(__file__).resolve().parent;P=W/'private';P.chmod(0o700)
out=W/'duplicate-reclamation.json';assert not out.exists()
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
f=json.loads((W/'fresh-FAT-proof.json').read_text());g=json.loads((W/'fresh-trial-FAT-backup.json').read_text())
rows=[]
for version,source in [('G65v2',Path(f['file'])),('G65v3',Path(g['file']))]:
 plan_path=P/(version+'-FAT-onetime.json');plan=json.loads(plan_path.read_text());image=P/('userdata-'+version+'-onetime.img')
 assert sha(source)==plan['before_sha256'] and sha(image)==plan['after_sha256']
 changes={v['offset']:v for v in plan['changes']};h=hashlib.sha256()
 with source.open('rb')as src:
  for off in range(0,plan['prefix_bytes'],4096):
   b=src.read(4096);assert len(b)==4096
   if off in changes:
    c=changes[off];assert b==base64.b64decode(c['before'],validate=True)
    b=base64.b64decode(c['after'],validate=True);assert len(b)==4096
   h.update(b)
  assert not src.read(1)
 assert h.hexdigest()==plan['after_sha256']
 rows.append({'file':image.name,'bytes':image.stat().st_size,'sha256':plan['after_sha256'],'retained_preimage':str(source),'retained_plan':str(plan_path),'entire_postimage_reconstructed_exactly':True})
 image.unlink()
assert sha(Path(g['file']))==g['sha256']
for i,part in enumerate(g['native_manifest']['pieces']):
 p=P/('trial-FAT-piece-%02d.zip'%i);assert sha(p)==part['zip_sha256']
 rows.append({'file':p.name,'bytes':p.stat().st_size,'sha256':part['zip_sha256'],'retained_complete_verified_raw_image':g['file']});p.unlink()
repro=P/'updater-reproduction-01/G65-disktool-r6.exe';original=P/'updater-01/G65-disktool-r6.exe'
assert sha(repro)==sha(original)=='a9f338b1059e94bd5a2c1fbc6294561f671c6a79099947a073390d150fa0cb1f'
rows.append({'file':str(repro.relative_to(P)),'bytes':repro.stat().st_size,'sha256':sha(repro),'retained_identical_executable':str(original)});repro.unlink()
s={'phase':'exact_reconstructible_private_duplicates_removed','files':rows,'bytes_reclaimed':sum(v['bytes']for v in rows),'protected_preimages_or_WIMs_deleted':False,'phone_operations':0}
out.write_text(json.dumps(s,indent=2)+'\n');print(json.dumps({k:s[k]for k in ['phase','bytes_reclaimed','protected_preimages_or_WIMs_deleted','phone_operations']}))
