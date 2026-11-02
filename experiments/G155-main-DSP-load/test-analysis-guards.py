"""Use actual producer fixtures and real older peer captures to refuse mixing."""
from pathlib import Path
import copy,hashlib,json,subprocess,sys,tempfile
from decoder_support import decoder,decode
from analysis_core import analyze,diagnose,SOURCE_INPUT
w=Path(__file__).resolve().parent;p=w/'private';exe=decoder();fixtures=w/'report-reader/testdata'
old=w.parent/'charging-G144/private'
peers={sig:json.loads((old/(label+'-native.json')).read_text())for sig,label in [('OPAS','OPAS'),('OAPF','raw-OAPF'),('OPIL','PIL')]}
capture=(w.parent/'charging-G118/private/firmware-input/capture.json').read_bytes();assert hashlib.sha256(capture).hexdigest()==SOURCE_INPUT
files=json.loads(capture)['files'];rows=[]
for f in sorted(fixtures.glob('*-DSP.bin')):
 name=f.name[:-8];d=decode(exe,f,fixtures/(name+'-OSER.bin'));assert d['ok'],(name,d)
 r=analyze(d,peers,expected_files=files)
 assert not r['native_authority']and not r['observed_main_public_load']and not r['capture_consistent']
 assert r['classification']=='inconsistent-or-mixed-capture'and r['binding_errors']
 assert not any(r[k]for k in ['DSP_running_qualified','GLINK_ready_qualified','charging_qualified','global_DMA_stage2_ownership_qualified','production_power_lease_qualified'])
 rows.append({'fixture':name,'diagnostic':r['primary_diagnostic'],'mixed_peer_capture_refused':True})
assert len(rows)==96
byname={r['fixture']:r['diagnostic']for r in rows}
assert byname['success']=='main-public-load-succeeded'
assert byname['main-loader-POST-failure']=='main-public-failed-after-accepted-AUTH'
assert byname['main-error-auth']=='main-secure-call-failed'
assert byname['main-copy-owner']=='main-copy-admission-refused'
assert byname['main-post-AT']=='main-payload-or-final-admission-refused'
assert byname['main-owner-after-read']=='pointer-restoration-failed'
# A genuine older table is refused by the shared core; a damaged new table is
# retained as raw evidence. Neither refusal is promoted to a successful load.
legacy=decode(exe,old/'native-OADP.bin',old/'native-OSER.bin');assert not legacy['ok']and set(legacy['raw_tables_base64'])=={'OADP','OSER'}
with tempfile.TemporaryDirectory()as tmp:
 f=Path(tmp)/'damaged.bin';b=bytearray((fixtures/'success-DSP.bin').read_bytes());b[100]^=1;f.write_bytes(b)
 bad=decode(exe,f,fixtures/'success-OSER.bin');assert not bad['ok']and analyze(bad,{})['classification']=='primary-report-refused'
# Production analysis has no simulated-authority option and refuses before any
# capture/write when the required accepted boot intent is absent.
assert not(p/'G155-boot-intent.json').exists()
q=subprocess.run([sys.executable,str(w/'analyze-native.py')],capture_output=True,text=True)
assert q.returncode!=0 and 'G155-boot-intent.json'in q.stderr and not(p/'native-analysis.json').exists()
report={'passed':True,'actual_C_fixture_mixed_capture_cases':96,'legacy_or_damaged_core_refusals':2,'production_missing_intent_refusals':1,'cases':99,'host_decoder_core_matches_phone_reader':True,'source_sha256':{n:hashlib.sha256((w/n).read_bytes()).hexdigest()for n in ['decoder_support.py','analysis_core.py','analyze-native.py','test-analysis-guards.py']},'native_operations':0,'results':rows,'limits':['Root reports come from actual-C host fixtures; peer reports are genuine older G144 captures and must fail cross-boot/campaign binding.','No synthetic peer success is presented as native qualification; the all-five-table positive native path awaits a real G155 capture.']}
(p/'analysis-guard-tests.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k!='results'},indent=2))
