from pathlib import Path
import subprocess,json,hashlib,difflib
w=Path(__file__).resolve().parent;r=w.parents[1];b=r/'work/gpu-cold-start-reconcile-G736/src'
for name,file in [('test_reset','test_reset.c'),('test_strict','test_strict_cold_hold.c')]:
 args=['clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-I'+str(w/'source'),str(w/'source/cold_hold.c'),str(w/'tests'/file),'-o',str(w/'build'/name)]
 q=subprocess.run(args,capture_output=True,text=True);assert q.returncode==0,q.stderr
 q=subprocess.run([str(w/'build'/name)],capture_output=True,text=True);(w/'evidence'/(name+'.log')).write_text(q.stdout+q.stderr);assert q.returncode==0,q.stderr;print(q.stdout,end='')
for name in ['test_handoff.py','test_runtime_phase.py']:
 q=subprocess.run(['python3',str(w/'tests'/name)],capture_output=True,text=True);assert q.returncode==0,q.stdout+q.stderr;print(q.stdout,end='')
rows=json.loads((w/'build/COMPILE.json').read_text())
for row in rows:
 q=subprocess.run(row['argv'],capture_output=True,text=True);row['returncode']=q.returncode;(w/row['object']).with_suffix('.log').write_text(q.stdout+q.stderr);assert q.returncode==0,row['source']+q.stderr
 data=(w/row['object']).read_bytes();assert data[:2]==b'\x64\xaa';(w/row['object']).write_bytes(data[:4]+bytes(4)+data[8:])
(w/'build/COMPILE.json').write_text(json.dumps(rows,indent=2)+'\n')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
patch=[];changed=[]
for sub in ['source','reference']:
 for f in (w/sub).rglob('*'):
  if f.is_file():
   old=b/f.relative_to(w)
   if old.exists() and old.read_bytes()!=f.read_bytes():
    n=str(f.relative_to(w));changed.append(n);patch.extend(difflib.unified_diff(old.read_text().splitlines(True),f.read_text().splitlines(True),fromfile='G736/'+n,tofile='G778/'+n))
(w/'G778-DELTA.patch').write_text(''.join(patch))
# Verify exact vendor call ordering and retain source identity, rather than
# inventing field semantics for the observed inherited bit3.
v=r/'work/gpu-policy-G191/private/adreno_gen7_gmu.c';s=v.read_text()
config=s[s.index('void gen7_gmu_register_config('):s.index('void gen7_gmu_register_config(')+6500]
assert config.index('GEN7_GMU_CM3_CFG, 0x4052')<config.index('GEN7_GBIF_HALT, 0x0')<config.index('gen7_gmu_power_config(')
first=s[s.index('static int gen7_gmu_first_boot('):s.index('static int gen7_gmu_first_boot(')+4500]
assert first.index('gen7_gmu_enable_clks(')<first.index('gen7_gmu_load_fw(')<first.index('gen7_gmu_register_config(')<first.index('gen7_gmu_device_start(')
audit=r/'work/gpu-cold-start-reconcile-G736/firmware-r2/evidence/WRITE-TARGET-AUDIT.json';j=json.loads(audit.read_text());assert '0x3d0f114' not in {a for x in j['MMIO_write_sites'] for a in x['possible_addresses']}
report={'status':'OFFLINE_IMPLEMENTED_TESTED_COMPILED_PENDING_ROOT_REVIEW_NO_NATIVE_QUALIFICATION','changed_files':changed,'candidate_source_pins':{n:sha(w/n) for n in changed},'baseline_manifest_sha256':sha(b/'MANIFEST.json'),'vendor_gen7_GMU_source_sha256':sha(v),'vendor_source_commit':'46cfd06fc4c0e12dbe294badb924a533f1d9fb06','vendor_source_lines':{'firstboot':'1790-1834','preboot_unhalt':'851-900','halt_teardown':'1323-1388,2497-2515'},'firmware_audit_sha256':sha(audit),'root_firmware_finite_write_audit_contains_GBIF_HALT':False,'initial_HALT8_origin':'UNKNOWN: no bit3 semantics/resetdefault or pre-Windows firstwriter established; firmware externalprotocol internals and retained boot chain not covered','fresh_mode':'CGH_RESET_QUIESCENT; neverCGH_HELD/owned','actual_tests':{'reset_core':14,'legacy_strict':'retained actual core test passes','production_handoff_body':6,'production_broker_phase_body':6},'ARM64_WDK_translation_units':len(rows),'physical_ACK_writes':0,'runtime_calls':0,'signing_or_installation':0}
(w/'REVIEW.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS:',len(rows),'ARM64 owner+broker translation units, actual state/body tests; no live calls')
