"""Read-only end-of-turn health check of the retained ongoing owner."""
import json,secrets,subprocess,time
from ops import P,PHONE,q,good,observe
remote='X:\\OpenG17\\payloads\\G183-exit-'+secrets.token_hex(5)+'.bin'
r=good(q('exit-health','phone',session=PHONE,argv=[r'X:\OpenG17\payloads\G183-status.exe',remote],timeout=20));v=json.loads(r['output']);assert v['ok']and v['sample_valid'];a=v['status'];assert a['Instance']==21331086396 and a['Fault']==a['Uncertain']==a['ProducerQualified']==0 and a['MapCalls']==a['MapCount']==20 and a['Completed']>=23
r=good(q('exit-health-get','phone','get',session=PHONE,path=remote,timeout=20));observe('exit-health-get',save=P/'exit.bin');proof=json.loads(subprocess.check_output([str(P/'analyze-snapshot'),str(P/'exit.bin')],text=True));assert proof['passed'];(P/'exit-analysis.json').write_text(json.dumps(proof,indent=2)+'\n')
f=P/'exit-state.json';s=json.loads(f.read_text());s.update(final_observed=a,observed=time.time());f.write_text(json.dumps(s,indent=2)+'\n');print({'retained_healthy':True,'latest':proof},flush=True)
