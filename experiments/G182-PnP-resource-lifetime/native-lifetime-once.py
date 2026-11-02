"""One PnP restart and exact-package removal; resource-only native qualification."""
from pathlib import Path
import json,re,time
from ops import P,q,good,ps
s=json.loads((P/'native-stage.json').read_text());assert s['phase']=='native_PnP_resource_owner_started';session=s['session'];f=P/'native-lifetime.json';assert not f.exists();state={'session':session,'created':time.time(),'phase':'before_restart','register_accesses':0};save=lambda:f.write_text(json.dumps(state,indent=2)+'\n');save()
base='X:\\OpenG17\\payloads\\';pnputil=r'X:\Windows\System32\pnputil.exe';instance=r'ACPI\OPEN0182\1'
def call(label,argv):return good(q(label,'phone',session=session,argv=argv,timeout=35))
r=call('native-PnP-restart',[pnputil,'/restart-device',instance]);state['phase']='restart_returned';save()
v=json.loads(call('native-after-restart-status',[base+'G182-status.exe'])['output']);assert v['ok']and v['status']['ProducerQualified']==0;state['after_restart']=v['status'];save()
r=call('native-after-restart-inventory',[pnputil,'/enum-devices','/instanceid',instance,'/resources','/services','/stack']);text=r['output'];assert text.count(instance)==1 and 'OpenG182'in text,text[:1500]
names=re.findall(r'(?im)^Driver Name:\s*(oem[0-9]+\.inf)\s*$',text);assert len(names)==1,names;inf=names[0];state['published_INF']=inf;state['phase']='before_uninstall';save()
r=call('native-exact-package-uninstall',[pnputil,'/delete-driver',inf,'/uninstall']);state['phase']='uninstall_returned';save()
r=q('native-interface-absent','phone',session=session,argv=[base+'G182-status.exe'],timeout=20);assert r['status']=='error'and r.get('exit_code')==1;v=json.loads(r['output']);assert not v['ok']and 'interface size'in v.get('error',''),v
r=call('native-after-uninstall-inventory',[pnputil,'/enum-devices','/instanceid',instance,'/resources','/services','/stack']);assert 'OpenG182'not in r['output']
b=json.loads((P/'corrected-launch.json').read_text());d=b['debugger'];text=r'''$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$owners=@(Get-NetUDPEndpoint -LocalPort 50000|Select-Object -ExpandProperty OwningProcess -Unique)
if($owners.Count -ne 1 -or $owners[0] -ne __PID__){throw 'Debugger ownership changed'}
$lines=@(Get-Content -LiteralPath '__LOG__'|Where-Object{$_ -match 'G182 release maps_before='})
@{debugger_pid=__PID__;release_lines=@($lines);utc=[DateTime]::UtcNow.ToString('o')}|ConvertTo-Json -Compress
'''.replace('__PID__',str(d['pid'])).replace('__LOG__',d['run']+'\\kd.txt')
v=json.loads(ps('native-release-debug-witness',text)['output']);(P/'native-release-debug.json').write_text(json.dumps(v,indent=2)+'\n');assert len(v['release_lines'])>=2,v
for line in v['release_lines']:
 line=line['value']if isinstance(line,dict)else line
 m=re.search(r'maps_before=(\d+) maps_after=(\d+) map_calls=(\d+) unmap_calls=(\d+) releases=(\d+) prepared=(\d+) producer=(\d+)',line);assert m;before,after,maps,unmaps,releases,prepared,producer=map(int,m.groups());assert before==20 and after==0 and maps==unmaps and releases and not prepared and not producer
state.update(phase='native_restart_and_release_qualified',complete=True,completed=time.time(),release_debug=v,interface_absent=True);save();print({'session':session,'restart_status':state['after_restart'],'release_records':len(v['release_lines']),'package_removed_from_RAM':inf,'hardware_producer_qualified':False})
