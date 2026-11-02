"""Retain the fully verified VM-native candidate, verify the retained copy, and audit all original streams."""
from pathlib import Path
import hashlib,json,subprocess,sys
W=Path(__file__).resolve().parent;P=W/'private';s=json.loads((W/'build-native-v2-state.json').read_text());assert s['phase']=='native_v2_fully_verified'
assert all(c['exit_code']==0 for c in s['commands']);assert [c['phase'] for c in s['commands']]==['verify-original-before-v2','export-native-v2','verify-native-v2-before-update','update-native-v2','verify-native-v2-after-update']
dest=P/'G20-canary-native-v2.wim';assert not dest.exists()
code='''from pathlib import Path
import hashlib,json,os,shutil,sys
src,dst,expected=sys.argv[1:];a=Path(src);b=Path(dst)
def digest(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
assert digest(a)==expected
with a.open('rb') as f,b.open('xb') as g:
 shutil.copyfileobj(f,g,8*1024*1024);g.flush();os.fsync(g.fileno())
assert digest(b)==expected
print('Verified native candidate copied to the Mac work area.')
'''
subprocess.run(['colima','ssh','--','python3','-c',code,s['target'],str(dest),s['final_sha256']],check=True)
h=hashlib.sha256()
with dest.open('rb') as f:
 for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
assert h.hexdigest()==s['final_sha256'] and dest.stat().st_size==s['final_bytes']
log=P/'verify-retained-Mac-v2.log';assert not log.exists()
with log.open('xb') as f:r=subprocess.run(['colima','ssh','--','wimlib-imagex','verify',str(dest)],stdout=f,stderr=subprocess.STDOUT)
assert r.returncode==0,log.read_text(errors='replace')[-1200:]
subprocess.run([sys.executable,str(W/'audit-wim.py'),'--trial',str(dest),'--run','v2'],check=True)
info=subprocess.check_output(['colima','ssh','--','wimlib-imagex','info',str(dest)],text=True);assert 'Boot Index:      1' in info or __import__('re').search(r'Boot Index:\s+1\b',info);(P/'native-v2-image-info.txt').write_text(info)
x={'phase':'retained_image_fully_verified_and_audited','image':str(dest),'bytes':s['final_bytes'],'sha256':s['final_sha256'],'source_sha256':s['source_sha256_expected'],'all_resources_verified_on_native_filesystem_before_and_after_update':True,'retained_Mac_image_resources_verified':True,'Mac_and_guest_SHA256_match':True,'all_original_file_streams_unchanged_plus_canary_only':True,'boot_index':1,'failed_v1_candidate_preserved_and_rejected':True,'native_staging':'not yet started'}
(W/'image-qualified-v2.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps(x,indent=2))
