"""Offline source/identity checks and negative once/ordering model; no native execution."""
from pathlib import Path
import re,json,hashlib
r=Path(__file__).resolve().parent
root=r.parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
old=root/'work/gpu-gmu-install-source-r4'
assert sha(r/'Common.ps1')==sha(old/'Common.ps1')=='45d1f603af15aed0a3d105f3d2669b88ccdf9bfc18190489a2f437a164889e87'
ps={p.name:p.read_text() for p in r.glob('*.ps1')}
# Balance executable delimiters while ignoring comments and PS strings/C# payloads.
def balance(s):
 stack=[];i=0;quote=None
 while i<len(s):
  c=s[i]
  if quote:
   if c=='`' and quote=='"':i+=2;continue
   if c==quote:
    if i+1<len(s) and s[i+1]==quote:i+=2;continue
    quote=None
  elif c in "'\"":quote=c
  elif c=='#':
   end=s.find('\n',i);i=len(s) if end<0 else end;continue
  elif c in '({[':stack.append(c)
  elif c in ')}]':assert stack and stack.pop()=={')':'(','}':'{',']':'['}[c]
  i+=1
 assert not stack and quote is None
for s in ps.values():balance(s)
g=ps['Activation-Guards.ps1'];exe=ps['Install-G736Once.ps1'];launch=ps['Launch-G736Activation.ps1'];run=ps['Invoke-G736Activation.ps1']
# Validate literal path regexes actually admit normal Windows paths; deny traversal/other roots.
patterns=re.findall(r"-cnotmatch '([^']+)'",g)
pathpatterns=[x for x in patterns if x.startswith('^C:')]
assert pathpatterns
for pat in pathpatterns:
 accepted=r'C:\OpenG81\qualifications\G736-Boot101-once' if 'qualifications' in pat else r'C:\OpenG81\payloads\G736-actual-report.json'
 assert re.fullmatch(pat,accepted),(pat,accepted)
 assert not re.fullmatch(pat,r'C:\OpenG81\payloads\..\escape.json')
 assert not re.fullmatch(pat,r'C:\Other\payloads\G736.json')
assert '0x7FFE02C4' in g and '-le 67' in g and 'G736-first-owner' in g
assert all(x not in g+exe+launch+run for x in ['G692-first-owner-R4','G692-postboot-owner','OpenGpuGmuR3-Boot66','OpenGpuGmuR4-Boot','OwnerAbsent;','sc.exe','/scan-devices','Restart-Service','Stop-Service','Restart-PnpDevice'])
assert "gpu0-prestart-pdo-resource-observation.json" in exe and 'unavailable_is_install_gate=$false' in exe
assert "if($resourceExit -ne 0)" not in exe and 'actual_START_raw_translated_grants_attested=$false' in exe
assert 'actual_OGBT_IORT_MMU1_resources_and_GPU0_prestart_observation_reviewed' in g
assert exe.count("InstallExact 'broker'")==exe.count("InstallExact 'owner'")==1
order=['Environment;Inputs736;ColdBoth736 $d',"$parent=Device 'OPEN0182'",'$n=[OpenOwnerAcpi]','FreshReceipts736','WriteNew (Join-Path $onceRoot',"InstallExact 'broker'","$qualified=Qualified 'OPEN0D01'","$gpu=Device 'OPEN0515'",'ColdOwner736 $d;Inputs736',"InstallExact 'owner'","$owner=Qualified 'OPEN0515'"]
pos=[exe.index(x) for x in order];assert pos==sorted(pos)
# R4 exact OGBT schema/checksum acceptance remains unchanged.
original=(old/'Install-AfterCleanBoot-R4.ps1').read_text();a=original.index('$n=[OpenOwnerAcpi]');b=original.index("$broker=Device 'OPEN0D01'")
assert original[a:b] in exe
# Qualified source is byte-identical; no new raw clock mask admission exists.
assert 'function Qualified' in ps['Common.ps1'];assert 'Qualified means PnP0/OK/started' in exe
assert 'GMU_HFI_or_acceleration_success_inferred=$false' in exe
assert launch.count('$registered.Run($null)')==1
assert "$t.Settings.ExecutionTimeLimit='PT0S'" in launch and '$t.Settings.AllowHardTerminate=$false' in launch
assert "$registered=$folder.RegisterTaskDefinition($taskName,$t,2,'S-1-5-18',$null,5,$null)" in launch
for token in ['$t.Triggers.Count -ne 0','$check.Triggers.Count -ne 0','$check.Settings.RestartCount -ne 0','$check.Settings.ExecutionTimeLimit -cne \'PT0S\'','$check.Principal.LogonType -ne 5']:
 assert token in launch
assert '$elapsed -gt 15' in run and 'GetTimestamp()' in run
assert run.count("& 'C:\\OpenG81\\GpuG736Activation-source\\Install-G736Once.ps1'")==1
# Pin all current reviewed package members (13 includes DER, not 13 binaries/catalogs).
pins=json.loads((r/'SIGNED-13-MEMBER-PINS.json').read_text());assert len(pins['files'])==13
extracted=root/'work/handover-resume-G737/signed-G736-review/extracted'
for name,pin in pins['files'].items():
 p=extracted/name;assert sha(p)==pin['sha256'] and p.stat().st_size==pin['bytes']
req=json.loads((r/'ROOT-REQUEST-TEMPLATE.json').read_text());d=json.loads((r/'ROOT-DECISION-TEMPLATE.json').read_text())
assert req['approved'] is False and d['accepted'] is False and req['session'] is req['BootId'] is d['session'] is d['BootId'] is None
for k,f in [('executor_sha256','Install-G736Once.ps1'),('launcher_sha256','Launch-G736Activation.ps1'),('runner_sha256','Invoke-G736Activation.ps1'),('guards_sha256','Activation-Guards.ps1'),('common_sha256','Common.ps1'),('signed_pins_sha256','SIGNED-13-MEMBER-PINS.json'),('signed_review_sha256','SIGNED-ROOT-REVIEW.json')]:assert req[k]==sha(r/f)
# Actual native raw+translated START guards remain exactly manifest-pinned.
native=root/'work/gpu-cold-start-reconcile-G736/src'
assert sha(native/'MANIFEST.json')=='59081a33e3d9e0bf1b2f6680eec6ecf4bc0a6539a19ab4e3e612e139a86a76e1'
nm=json.loads((native/'MANIFEST.json').read_text())
for path in ['source/owner/owner_entry.c','source/broker/open_smmu_wdm.c']:
 assert sha(native/path)==nm['files'][path]['sha256']
owner_source=(native/'source/owner/owner_entry.c').read_text()
broker_source=(native/'source/broker/open_smmu_wdm.c').read_text()
assert 'PartialResourceList.Count!=5' in owner_source
assert 'CheckResources(sp->Parameters.StartDevice.AllocatedResources)' in owner_source
assert 'CheckResources(sp->Parameters.StartDevice.AllocatedResourcesTranslated)' in owner_source
assert 'ValidateResources(p,sp->Parameters.StartDevice.AllocatedResources)' in broker_source
assert 'ValidateResources(p,sp->Parameters.StartDevice.AllocatedResourcesTranslated)' in broker_source
# Independent negative state model: dispatch and execution marker keyed by BootId,
# not session; broker-return uncertainty/qualification failure forbids owner.
def attempt(boot,dispatch,marker,broker_return,qualified,owner_cold):
 if boot in dispatch:return 'refused-dispatch'
 dispatch.add(boot)
 if boot in marker:return 'refused-marker'
 marker.add(boot)
 if not broker_return:return 'broker-uncertain-no-owner'
 if not qualified:return 'broker-unqualified-no-owner'
 if not owner_cold:return 'old-owner-changed-no-owner'
 return 'one-owner-call'
for failcase in [(False,False,True),(True,False,True),(True,True,False)]:
 dis=set();mark=set();result=attempt(101,dis,mark,*failcase);assert 'one-owner' not in result
 assert attempt(101,dis,mark,True,True,True)=='refused-dispatch'
dis=set();mark=set();assert attempt(102,dis,mark,True,True,True)=='one-owner-call';assert attempt(102,dis,mark,True,True,True)=='refused-dispatch'
# Prestart resources unavailable is deliberately independent of actual START admission.
dis=set();mark=set();prestart_resources_available=False
assert attempt(103,dis,mark,True,True,True)=='one-owner-call' and not prestart_resources_available
report={'scope':'offline static source/identity checks and independent once-ordering model; not native PowerShell execution or hardware evidence','common_unchanged':True,'Qualified_unchanged':True,'actual_OGBT124_checks_unchanged':True,'signed_member_count':13,'includes_public_DER':True,'fresh_templates_not_approval':True,'one_broker_then_qualified_then_one_owner':True,'SYSTEM_PT0S_task_single_Run_no_replay':True,'normal_Windows_path_regex_positive_negative_tests':True,'model_cases':5,'prestart_GPU0_unavailable_not_gate':True,'actual_native_START_grant_checks_unchanged':True,'native_parse':'PENDING ROOT','native_actions':0,'clock_mask_changes':0}
(r/'SOURCE-CHECK.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
