from pathlib import Path
import hashlib,json,struct
from Registry import Registry
W=Path(__file__).resolve().parents[1]
G83=W.parent/'setup-queue-G83'
def values(p):
 b=p.read_bytes();a,c=struct.unpack_from('<II',b,4);assert a==c,'Native transaction replay required'
 r=Registry.Registry(str(p));out={};keys=set()
 def walk(k):
  keys.add(k.path().lower())
  for v in k.values():out[(k.path().lower(),v.name().lower())]=(v.value_type(),v.raw_data().hex())
  for sub in k.subkeys():walk(sub)
 walk(r.root());return keys,out
before=G83/'private/post-phase4/C/Windows/System32/config/SYSTEM';after=W/'private/SYSTEM-trial'
bk,b=values(before);ak,a=values(after);assert bk==ak
changes=[{'key':k[0],'name':k[1],'before':b.get(k),'after':a.get(k)} for k in sorted(b.keys()|a.keys()) if b.get(k)!=a.get(k)]
assert [(v['key'],v['name']) for v in changes]==[('root\\setup','cmdline')]
s=Registry.Registry(str(after))
assert s.open('Setup').value('CmdLine').value()==r'cmd.exe /d /c C:\OpenG81\run-setup-G83.cmd'
assert s.open('Setup').value('SystemSetupInProgress').value()==0
assert s.open('Setup').value('OOBEInProgress').value()==1
assert s.open('Setup\\Status\\SysprepStatus').value('GeneralizationState').value()==7
assert s.open('Setup\\Status\\ChildCompletion').value('setup.exe').value()==3
proof={'before_sha256':hashlib.sha256(before.read_bytes()).hexdigest(),'trial_sha256':hashlib.sha256(after.read_bytes()).hexdigest(),'value_count':len(a),'registry_keys_added_or_removed':0,'changed_values':changes,'completion_or_ImageState_changes':False,'source_hive_sequences_equal':True}
(W/'captures/RAM-trial-proof.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof,indent=2))
