"""Continue only read-only checks after the recorded terminal PnP restart."""
from pathlib import Path
import hashlib,json,re,secrets,subprocess,time
from ops import P,q,good,observe,ps,PHONE
w=Path(__file__).resolve().parent;p=P;f=p/'native-run.json';s=json.loads(f.read_text());assert s['phase']=='restart_returned'and not s.get('complete');prior=json.loads((p/'native-restart-receipt.json').read_text());assert prior['status']=='ok'and prior['exit_code']==0
base='X:\\OpenG17\\payloads\\';save=lambda:f.write_text(json.dumps(s,indent=2)+'\n')
def capture(label):
 remote=base+'G183-'+label+'-'+secrets.token_hex(5)+'.bin';r=good(q('native-'+label,'phone',session=PHONE,argv=[base+'G183-status.exe',remote],timeout=20));v=json.loads(r['output']);s['snapshots'].append({'label':label,'remote':remote,'native':v,'observed':time.time()});save();assert v['ok']and v['sample_valid']and not v['status']['Fault']and not v['status']['Uncertain'];good(q('native-get-'+label,'phone','get',session=PHONE,path=remote,timeout=20));observe('native-get-'+label,save=p/(label+'.bin'));r=subprocess.run([str(p/'analyze-snapshot'),str(p/(label+'.bin'))],capture_output=True,text=True);assert r.returncode==0,r.stderr+str(r.returncode);a=json.loads(r.stdout);(p/(label+'-analysis.json')).write_text(json.dumps(a,indent=2)+'\n');print({'label':label,**a},flush=True);return v
v=capture('restarted-sample');assert v['status']['Instance']>s['snapshots'][0]['native']['status']['Instance'];time.sleep(6);after=capture('restarted-ongoing');assert after['status']['Completed']>v['status']['Completed']
r=good(q('native-after-inventory','phone',session=PHONE,argv=[r'X:\Windows\System32\pnputil.exe','/enum-devices','/deviceid',r'ACPI\OPEN0182','/resources','/services','/stack'],timeout=20));assert 'OpenG183'in r['output']
text=r'''$ErrorActionPreference='Stop';$owners=@(Get-NetUDPEndpoint -LocalPort 50000|Select-Object -ExpandProperty OwningProcess -Unique)
if($owners.Count -ne 1 -or $owners[0] -ne 8172){throw 'Debugger ownership changed'}
$lines=@(Get-Content -LiteralPath 'C:\Users\PUBLIC_USER\Downloads\OnePlusOpen-BootRepair-G80\debug\G182-20261026-045608\kd.txt'|Where-Object{$_ -match 'G183 release maps_before='})
@{release_lines=@($lines);debugger_pid=8172}|ConvertTo-Json -Compress
'''
r=ps('native-release-witness',text);v=json.loads(r['output']);assert len(v['release_lines'])==1;line=v['release_lines'][0];line=line['value']if isinstance(line,dict)else line;assert re.search(r'maps_before=20 maps_after=0 map_calls=20 unmap_calls=20 busy=0 queued=0 valid=0 fault=0 uncertain=0',line),line
s.update(phase='native_ongoing_and_restart_qualified',complete=True,release_line=line,final=after['status'],completed=time.time(),retained_live=True,wrapper_correction='Distinct restart-operation and status-query labels; saved successful restart was not replayed.');save();print({'native_ongoing':True,'restart_clean_release':True,'retained_live':True,'final':after['status']},flush=True)
