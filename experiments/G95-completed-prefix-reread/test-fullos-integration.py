from pathlib import Path
import json,subprocess,hashlib,os
import argparse
W=Path(__file__).resolve().parent;p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args();O=a.output.resolve();O.mkdir(parents=True)
# Native measured clock configuration and IC bytes: reuse existing immutable fixture header.
(O/'native-model-input.h').write_bytes((W/'model-inputs/native-model-input.h').read_bytes())
names=['g95_observer.c','g95_rsc.c','g95_power.c','g95_spi.c','g95_engine.c','g95_touch.c','g95_contract.c','g95_plan.c','g95_report.c','g95_poll.c','geni_fifo.c','g95_input.c','g95hid_lifecycle.c','test-trial.c'];exe=O/'model'
q=subprocess.run(['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(O),*[str(W/n)for n in names],'-o',str(exe)],capture_output=True,text=True);assert q.returncode==0,q.stderr
child=subprocess.Popen([str(exe),'--batch'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
rows=[]
def run(label,limit=8,scenario=0,read=0,write=0,barrier=0,stop=0,fixture=False):
 f=O/(label+'.bin');child.stdin.write(f'{limit} {read} {write} {scenario} {barrier} {stop} '+(str(f)if fixture else'-')+'\n');child.stdin.flush();line=child.stdout.readline();assert line,(label,child.stderr.read());d=json.loads(line);rows.append(dict(label=label,**d));assert d['accepted_mask']==0 and d['enables']<=1 and d['releases']<=1 and d['cancels']<=1 and d['aborts']<=1
 if d['power_restored']:assert d['physical_model_restored'],(label,d)
 return d
for label,sc in [('idle',0),('mixed',500),('max',501),('release',509),('retry',510),('retrymax',512),('bodyretry',513)]:
 d=run(label,scenario=sc,fixture=True);assert d['power_code']==d['touch_code']==d['poll_code']==0 and d['poll_cycles']==8 and d['power_restored'] and d['safe_release'],(label,d)
 for n in ['reads','writes','barriers']:
  for i in sorted(set([1,d[n]//2,d[n]-1,d[n]])):
   for sign in [-1,1]if n=='writes'else[1]:
    r=run(label+n+str(sign*i),scenario=sc,**{{'reads':'read','writes':'write','barriers':'barrier'}[n]:sign*i});assert r['power_code']or r['power_restore_error']or not r['power_restored']
 for st in [1,d['stop_checks']//2,d['stop_checks']-1,d['stop_checks']]:
  r=run(label+'stop'+str(st),scenario=sc,stop=st);assert r['touch_code']==21 and r['power_restored'] and r['safe_release'],r
 for limit in [401,2500,3000]:
  r=run(label+str(limit),limit=limit,scenario=sc,fixture=True);assert r['power_code']==r['touch_code']==r['poll_code']==0 and r['poll_cycles']==limit and r['power_restored'] and r['advance_calls']==limit,(label,limit,r)
for sc in [104,105,109,210,303,403,603,606,702,704]:
 r=run('unsafe'+str(sc),scenario=sc);assert not r['safe_release'] and not r['power_restored'] and r['enabled']==1 and r['releases']==0,(sc,r)
for sc in [111,112]:
 r=run('badraw'+str(sc),scenario=sc);assert r['power_code']==3 and r['enables']==r['commands']==0,(sc,r)
r=run('bodyretry-fails-twice',scenario=514);assert r['poll_code']==4 and r['poll_wire_count']==2 and r['event_writes']==1 and r['power_restored'] and r['safe_release'] and not r['sink_calls'],r
child.stdin.close();assert child.wait()==0;err=child.stderr.read();assert not err,err
out={'passed':True,'cases':len(rows),'ASan_UBSan':True,'cold_raw0_and_PMIC87_model':True,'limits':[8,401,2500,3000],'safe_release_faults_checked':True,'native_access':False,'source_hashes':{n:hashlib.sha256((W/n).read_bytes()).hexdigest()for n in names},'results':rows};(O/'tests.json').write_text(json.dumps(out,indent=2));print(json.dumps({k:v for k,v in out.items()if k not in ['results','source_hashes']}))
