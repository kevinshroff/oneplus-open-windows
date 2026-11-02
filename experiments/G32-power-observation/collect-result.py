"""Reconstruct bounded G32 result chunks and verify against the native trace.

This reads saved files only. Missing chunks are never grounds to repeat a trial.
"""
import argparse,hashlib,json,re
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--work',type=Path,default=Path(__file__).resolve().parent)
p.add_argument('--capture',default='power-test')
p.add_argument('--tag',default='G32_POWER_TEST')
p.add_argument('--trace-capture',default='power-test')
a=p.parse_args();W=a.work

def read(name):
 raw=W/'private'/(name+'-debug.txt')
 receipt=json.loads((W/(name+'-capture.json')).read_text())['receipt']
 assert hashlib.sha256(raw.read_bytes()).hexdigest()==receipt['sha256']
 return raw.read_text(errors='replace').replace('\r\n','\n'),receipt['sha256']
text,rawsha=read(a.capture)
start=text.rindex('\n'+a.tag+'_BEGIN\n');end=text.rindex(a.tag+'_END\n');assert end>start
scope=text[start:end]
infos=[json.loads(x[len('G32_RESULT_INFO '):])for x in scope.splitlines()if x.startswith('G32_RESULT_INFO ')]
chunks=[json.loads(x[len('G32_RESULT_CHUNK '):])for x in scope.splitlines()if x.startswith('G32_RESULT_CHUNK ')]
assert len(infos)==1
info=infos[0];binding=json.loads((W/'trial/binding.json').read_text())
assert info['nonce']==binding['nonce']
assert len(chunks)==info['parts'] and [c['index']for c in chunks]==list(range(info['parts']))
assert all(c['nonce']==info['nonce'] and len(c['text'])<=768 for c in chunks)
serialized=''.join(c['text']for c in chunks);assert len(serialized)==info['characters']
s=json.loads(serialized)
assert s['nonce']==info['nonce'] and len(s['events'])==info['events']
for k in ['success','restored','needs_recovery']:assert s[k]==info[k]
trace,tracesha=read(a.trace_capture)
trace=trace[trace.rindex('\nG32_POWER_TEST_BEGIN\n'):trace.rindex('G32_POWER_TEST_END\n')]
reads=[int(x,16)for x in re.findall(r'^!dd \[uc\] -m ([0-9a-f]+) L1$',trace,re.M)]
writes=[(int(x,16),int(y,16))for x,y in re.findall(r'^!ed \[uc\] ([0-9a-f]+) ([0-9a-f]+)$',trace,re.M)]
eventreads=[e['address']for e in s['events']if e['kind']=='read']
eventwrites=[(e['address'],e['value'])for e in s['events']if e['kind']=='write_attempt']
assert len(reads)==s['native_reads'] and len(writes)==s['native_write_attempts']
assert reads==eventreads and writes==eventwrites
out=W/'trial/native-result.json';assert not out.exists(), 'Never overwrite the historical native result'
out.write_text(json.dumps(s,indent=2)+'\n')
report={'complete_original_context_chunks':True,'nonce':s['nonce'],'source_log_sha256':rawsha,'trace_log_sha256':tracesha,'chunks':len(chunks),'characters':len(serialized),'events':len(s['events']),'all_native_read_addresses_write_addresses_and_values_match_trace':True,'native_reads':len(reads),'native_write_attempts':len(writes),'hardware_trial_replayed':False,'host_projection_or_supplementation_needed':False,'end_echo_may_follow_truncated_dx_display_without_newline':True}
(W/'capture-verification.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:s.get(k)for k in ['success','error','restore_error','restored','needs_recovery','rsc_uncertain','observer_uncertain','ready_observed','native_reads','native_write_attempts','observer_read_requests','supply_vote_message_attempts','preflight_client_raw','enabled_client_raw','restored_client_raw','enabled_pmic','restored_pmic']}))
