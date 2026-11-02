"""Wait for a fresh acknowledged boot, then run its guarded verifier once."""
from pathlib import Path
import argparse,json,sqlite3,subprocess,sys,time

W=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('kind',choices=['resource','physical']);a=p.parse_args()
if a.kind=='resource':
 trigger=json.loads((W/'resource-activation.json').read_text());job='single-resource-reboot';old=trigger['starting_session']
else:
 trigger=json.loads((W/'return-to-G17.json').read_text());job='single-return-reboot';old=json.loads((W/'boot-resource.json').read_text())['session']
assert trigger['jobs'][job]['receipt']['status']=='ok'
deadline=time.monotonic()+300
while time.monotonic()<deadline:
 with sqlite3.connect(W.parent.parent/'control-G17/private/queue.sqlite3')as db:
  sid,seen=db.execute("select session,seen from nodes where node='phone'").fetchone()
 if sid!=old and time.time()-seen<15:
  print(json.dumps({'fresh_session':sid,'expected_boot':a.kind}),flush=True)
  subprocess.run([sys.executable,str(W/'capture-boot.py'),a.kind],check=True)
  break
 time.sleep(5)
else:
 raise TimeoutError('No fresh control session yet; observe existing reboot/debugger without replay.')
