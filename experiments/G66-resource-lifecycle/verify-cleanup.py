"""Observe probe removal and exact restored callback code before returning G17."""
from pathlib import Path
import hashlib,json,re,sqlite3,time
from relay import Relay
W=Path(__file__).resolve().parent;P=W/'private';b=json.loads((W/'boot-resource.json').read_text());launch=json.loads((W/'callback-debugger-launch.json').read_text())
c=json.loads((W/'debugger-cleanup.json').read_text());assert c['phase']=='owned_probe_cleanup_submitted_once'
R=Relay('cleanup-verification.json',phone_session=b['session']);s=R.s
def op(label,node,action,**kw):
 r=R.op(label,node,action,**kw);assert r['status']=='ok'and r.get('exit_code',0)==0,r;return r
log=P/'callback-after-cleanup.txt';op('retain-cleanup-trace','host','get',path=launch['launch']['run']+r'\windbg.txt',save=log)
raw=log.read_bytes();text=raw.decode('utf-16')if raw.startswith((b'\xff\xfe',b'\xfe\xff'))else raw.decode('utf-8','replace');lines=text.splitlines()
start=next(i for i,l in enumerate(lines)if l.strip()=='G66_CLEAN_BREAKPOINTS');code=next(i for i,l in enumerate(lines)if i>start and l.strip()=='G66_POST_CODE_BEGIN')
assert not any(re.match(r'^\s*\d+\s+[ed]\s',l)for l in lines[start+1:code]),'Breakpoints remain'
end=next(i for i,l in enumerate(lines)if i>code and l.strip()=='G66_POST_CODE_END');data=bytearray();base=None
for l in lines[code+1:end]:
 m=re.match(r'^\s*([0-9a-fA-F`]+)\s+(.+)$',l)
 if not m:continue
 a=int(m[1].replace('`',''),16);v=m[2].replace('-',' ').split()[:16];assert len(v)==16 and all(re.fullmatch('[0-9a-fA-F]{2}',x)for x in v)
 if base is None:base=a
 assert a==base+len(data);data.extend(bytes.fromhex(''.join(v)))
assert bytes(data)==(P/'expected-native-code.bin').read_bytes()and len(data)==1424
assert any(l.strip()=='G66_CLEAN_END'for l in lines[end+1:])
with sqlite3.connect(W.parent.parent/'control-G17/private/queue.sqlite3')as db:sid,seen=db.execute("select session,seen from nodes where node='phone'").fetchone()
assert sid==b['session']and time.time()-seen<15,'Observe the same target until resumed'
health=op('post-cleanup-health','phone','probe');assert health['detail']['cpus']==8
f=json.loads((W/'native-cycle.json').read_text());nonce=f['disable_response']['result']['nonce']
for part in ['intent','result']:
 op('retain-refused-disable-'+part,'phone','get',path=r'X:\OpenG17\payloads\G66-'+nonce+'-disable-'+part+'.json',save=P/('refused-disable-'+part+'.json'))
s.update(phase='all_five_probes_removed_exact_callback_code_restored_target_resumed',breakpoints_remaining=0,restored_native_code_bytes=len(data),restored_native_code_sha256=hashlib.sha256(data).hexdigest(),session=sid)
R.persist();print(json.dumps({k:s[k]for k in ['phase','breakpoints_remaining','restored_native_code_bytes']}),flush=True)
