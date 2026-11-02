"""Prove G170 overlap using its actual interrupt clock, not QPC epoch equality."""
from pathlib import Path
import hashlib,json,struct
w=Path(__file__).resolve().parent;old=w.parent/'charging-G170/private';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();wire=json.loads((old/'pulse-wire-proof.json').read_text());a,b=wire['enable_us'],wire['disable_us'];rows={}
for phase in ['before-fv','after-fv','during-pulse','after-pulse']:
 intent=json.loads((old/(phase+'-hardware-intent.json')).read_text());assert intent['complete']
 def raw(c):
  f=old/(phase+'-'+c+'-raw.bin');assert sha(f)==intent['results'][c]['capture_sha256']and intent['results'][c]['independent_decode_equal'];return f.read_bytes()
 config=raw('G167');gauge=raw('G160');get=lambda v,at:struct.unpack_from('<Q',v,at)[0]
 rows[phase]={'config_begin_interrupt_us':get(config,104)//10,'config_end_interrupt_us':get(config,112)//10,'gauge_final_status_interrupt_us':get(gauge,56)//10,'config_begin_QPC_us':get(config,168),'capture_hashes':{c:intent['results'][c]['capture_sha256']for c in ['G167','G160']}}
 assert rows[phase]['config_begin_interrupt_us']<=rows[phase]['config_end_interrupt_us']<rows[phase]['gauge_final_status_interrupt_us']
d=rows['during-pulse'];assert a<d['config_begin_interrupt_us']<=d['config_end_interrupt_us']<d['gauge_final_status_interrupt_us']<b
assert b<rows['after-pulse']['config_begin_interrupt_us']
proof={'passed':True,'pulse_enable_interrupt_us':a,'pulse_disable_interrupt_us':b,'phases':rows,'gauge_begin_order_basis':'The exact source-built G170 observer helper synchronously completes/retire-checks G167 before starting G160; G160 final Status.InterruptTime is written after G104Identify finishes. Thus the gauge collection is after config begin and before its own final status point.','clock_limit':'G167/G160 result begin_us/end_us are QPC-based and cannot be directly compared to G170 interrupt-time timestamps. Prior within-pulse conclusion is confirmed using compatible capture-wrapper/final-status interrupt times; the QPC comparison itself is superseded.','source_checks':{}}
for c in ['G167','G160']:
 prior=w.parent/('charging-'+c);audit=json.loads((prior/'private/signature-and-source-audit.json').read_text())
 assert audit['passed']and audit['all_compiled_source_hashes_match']
 pins=audit['source_sha256']if 'source_sha256'in audit else json.loads((prior/'private/compile-02/compile.json').read_text())['sources']
 for name in [c.lower()+'_driver.c','guard-and-status.inc']:
  f=prior/'probe'/name;assert sha(f)==pins[name];proof['source_checks'][c+'/'+name]=sha(f)
owner=w.parent/'charging-G170';ready=json.loads((owner/'private/readiness.json').read_text());helper=json.loads((owner/'private/observer-build.json').read_text())
for name,pin in [('native/driver.c',ready['sources']['native/driver.c']),('helpers/observe_windows.go',helper['sources']['observe_windows.go'])]:
 assert sha(owner/name)==pin;proof['source_checks']['G170/'+name]=pin
(w/'private/prior-pulse-clock-proof.json').write_text(json.dumps(proof,indent=2)+'\n');print({'pulse_overlap_confirmed_with_shared_interrupt_clock':True,'during_config_begin_s_after_enable':(d['config_begin_interrupt_us']-a)/1e6,'during_gauge_final_s_after_enable':(d['gauge_final_status_interrupt_us']-a)/1e6,'QPC_epoch_was_not_assumed':True})
