"""Install one exact RAM-only sensor package and qualify ongoing reads/restart."""
from pathlib import Path
import hashlib,json,re,secrets,sqlite3,time
from ops import q,good,ps,observe,P,PHONE,lab
w=Path(__file__).resolve().parent;p=P;statefile=p/'native-run.json';assert not statefile.exists(),'Observe recorded jobs/intent; never replay install or restart'
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest();meta=json.loads((p/'compile-final/compile.json').read_text())
for n,h in meta['source_sha256'].items():assert sha(w/n)==h,n
for n in ['driver-ASan-final','driver-TSan-final']:
 v=json.loads((p/n/'verification.json').read_text());assert v['passed']and v['actual_driver_cases']==50
 for f,h in v['source_sha256'].items():assert sha(w/f)==h,(n,f)
assert json.loads((w/'file-signature-verification.json').read_text())['signed_image_SHA256_matches']
s={'session':PHONE,'created':time.time(),'phase':'staging','snapshots':[],'partition_flashes':0,'PMIC_configuration_writes':0,'GLINK_requests':0};save=lambda:statefile.write_text(json.dumps(s,indent=2)+'\n');save();base='X:\\OpenG17\\payloads\\';tool=r'X:\Windows\System32\pnputil.exe'
def call(label,argv,timeout=25):return good(q(label,'phone',session=PHONE,argv=argv,timeout=timeout))
package=json.loads((p/'package-build.json').read_text());files={n:p/n for n in ['OpenG183.inf','OpenG183.sys','OpenG183.cat','G183-public.cer']};files['G183-status.exe']=p/'client-final/G183-status.exe'
for n,f in files.items():
 if n in package['files']:assert sha(f)==package['files'][n]['sha256']
 r=good(q('native-put-'+n,'phone','put',session=PHONE,file=f,path=n,timeout=20));assert r['sha256']==sha(f)
r=call('native-before-inventory',[tool,'/enum-devices','/deviceid',r'ACPI\OPEN0182','/services','/stack']);assert r['output'].count(r'ACPI\OPEN0182\1')==1 and 'OpenG182'not in r['output']and 'OpenG183'not in r['output']
s['phase']='before_drvload';save();call('native-load',[r'X:\Windows\System32\drvload.exe',base+'OpenG183.inf'],35);s['phase']='loaded';save()
def capture(label):
 remote=base+'G183-'+label+'-'+secrets.token_hex(5)+'.bin';r=call('native-'+label,[base+'G183-status.exe',remote]);v=json.loads(r['output']);assert v['ok'];s['snapshots'].append({'label':label,'remote':remote,'native':v,'observed':time.time()});save()
 r=good(q('native-get-'+label,'phone','get',session=PHONE,path=remote,timeout=20));observe('native-get-'+label,save=p/(label+'.bin'));assert sha(p/(label+'.bin'))==r['sha256'];a=v['status'];assert a['Fault']==a['Uncertain']==a['ProducerQualified']==0,a
 assert a['MapCalls']==a['MapCount']==20 and a['UnmapCalls']==0 and a['D0Active']==1
 if v['sample_valid']:
  import subprocess
  r=subprocess.run([str(p/'analyze-snapshot'),str(p/(label+'.bin'))],capture_output=True,text=True);assert r.returncode==0,r.stderr+str(r.returncode);analysis=json.loads(r.stdout);(p/(label+'-analysis.json')).write_text(json.dumps(analysis,indent=2)+'\n');print({'label':label,**analysis},flush=True)
 return v
v=capture('initial')
if not v['sample_valid']:time.sleep(1);v=capture('initial-ready')
assert v['sample_valid'];first=v['status'];s['phase']='ongoing_60sec';save()
for label in ['middle','sustained']:
 time.sleep(30);v=capture(label);assert v['sample_valid']and v['status']['Instance']==first['Instance']and v['status']['Completed']>s['snapshots'][-2]['native']['status']['Completed']
last=v['status'];assert last['Completed']>=first['Completed']+10 and last['Ticks']>=50
s['phase']='before_PnP_restart';save();call('native-PnP-restart',[tool,'/restart-device',r'ACPI\OPEN0182\1']);s['phase']='restart_returned';save()
time.sleep(2);v=capture('restart');assert v['sample_valid']and v['status']['Instance']>first['Instance'];time.sleep(6);after=capture('restart-ongoing');assert after['sample_valid']and after['status']['Completed']>v['status']['Completed']
call('native-after-inventory',[tool,'/enum-devices','/deviceid',r'ACPI\OPEN0182','/resources','/services','/stack'])
text=r'''$ErrorActionPreference='Stop';$owners=@(Get-NetUDPEndpoint -LocalPort 50000|Select-Object -ExpandProperty OwningProcess -Unique)
if($owners.Count -ne 1 -or $owners[0] -ne 8172){throw 'Debugger ownership changed'}
$lines=@(Get-Content -LiteralPath 'C:\Users\PUBLIC_USER\Downloads\OnePlusOpen-BootRepair-G80\debug\G182-20261026-045608\kd.txt'|Where-Object{$_ -match 'G183 release maps_before='}|ForEach-Object{[string]$_})
@{release_lines=@($lines);debugger_pid=8172}|ConvertTo-Json -Compress
'''
r=ps('native-release-witness',text);v=json.loads(r['output']);assert len(v['release_lines'])==1;line=v['release_lines'][0];assert re.search(r'maps_before=20 maps_after=0 map_calls=20 unmap_calls=20 busy=0 queued=0 valid=0 fault=0 uncertain=0',line),line
s.update(phase='native_ongoing_and_restart_qualified',complete=True,release=v,final=after['status'],completed=time.time(),retained_live=True);save();print({'native_ongoing':True,'restart_clean_release':True,'retained_live':True,'final':after['status']},flush=True)
