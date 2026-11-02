from pathlib import Path
import hashlib,json
from Registry import Registry
W=Path(__file__).resolve().parents[1]
G81=W.parent/'setup-retry-G81'
def values(p):
 r=Registry.Registry(str(p));out={};keys=set()
 def walk(k):
  keys.add(k.path().lower())
  for v in k.values():out[(k.path().lower(),v.name().lower())]=(v.value_type(),v.raw_data().hex())
  for sub in k.subkeys():walk(sub)
 walk(r.root());return keys,out
before=G81/'private/after-dialog-replayed/SYSTEM';after=W/'private/SYSTEM-after-RAM-trial'
bk,b=values(before);ak,a=values(after)
assert bk==ak, 'No added or removed registry keys allowed'
diff=[{'key':k[0],'name':k[1],'before':b.get(k),'after':a.get(k)} for k in sorted(b.keys()|a.keys()) if b.get(k)!=a.get(k)]
nic='root\\controlset001\\services\\tcpip\\parameters\\interfaces\\{50d561fb-94dc-4295-87cd-e78f0135d5a6}'
expected={('root\\setup\\status\\childcompletion','setup.exe'),('root\\setup','cmdline'),(nic,'enabledhcp'),(nic,'ipaddress'),(nic,'subnetmask')}
assert {(d['key'],d['name']) for d in diff}==expected
r=Registry.Registry(str(after))
assert r.open('Setup\\Status\\ChildCompletion').value('setup.exe').value()==0
assert r.open('Setup\\Status\\SysprepStatus').value('GeneralizationState').value()==4
assert r.open('Setup').value('CmdLine').value()==r'cmd.exe /d /c C:\OpenG81\run-setup-G82.cmd'
n=r.open(nic.removeprefix('root\\'))
assert n.value('IPAddress').value()[0]=='192.0.2.10' and n.value('IPAddress').value_type()==7
assert n.value('SubnetMask').value()[0]=='255.255.0.0' and n.value('SubnetMask').value_type()==7
assert n.value('EnableDHCP').value()==0
report={'phase':'native_RAM_trial_semantic_proof','before_sha256':hashlib.sha256(before.read_bytes()).hexdigest(),'after_sha256':hashlib.sha256(after.read_bytes()).hexdigest(),'before_value_count':len(b),'after_value_count':len(a),'changed_values':diff,'registry_keys_added_or_removed':0,'completion_marked_successful':False,'installed_OS_writes':0}
(W/'captures/RAM-trial-proof.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
