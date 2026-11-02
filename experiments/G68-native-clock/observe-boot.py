"""Observe an already acknowledged reboot; never repeat or create a reboot job."""
from pathlib import Path
import argparse,json,sqlite3,subprocess,sys,time
W=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('kind',choices=['maintenance','resource','physical']);a=p.parse_args()
source={'maintenance':'maintenance-activation.json','resource':'resource-activation.json','physical':'return-to-G17.json'}[a.kind]
job={'maintenance':'single-maintenance-reboot','resource':'single-resource-reboot','physical':'single-return-reboot'}[a.kind]
t=json.loads((W/source).read_text());assert t['jobs'][job]['receipt']['status']=='ok'
old=t['starting_session'];deadline=time.monotonic()+55
while time.monotonic()<deadline:
 with sqlite3.connect(W.parent.parent/'control-G17/private/queue.sqlite3')as db:
  sid,seen=db.execute("select session,seen from nodes where node='phone'").fetchone()
 if sid!=old and time.time()-seen<15:
  print(json.dumps({'fresh_session':sid,'expected_boot':a.kind}),flush=True)
  subprocess.run([sys.executable,str(W/'capture-boot.py'),a.kind],check=True);break
 time.sleep(5)
else:raise TimeoutError('No fresh heartbeat yet; inspect this same reboot/debugger, never replay.')
