"""Exhaustively compare all registry values before allowing a trial BCD onto the FAT image."""
from pathlib import Path
import hashlib,json,re
W=Path(__file__).resolve().parent;P=W/'private'
def parse(p,tag):
 s=p.read_text(encoding='utf-16');s=re.sub(r'\\\r?\n\s*','',s);result={};key=None;prefix='HKEY_LOCAL_MACHINE\\'+tag
 for line in s.splitlines():
  line=line.strip()
  if not line or line=='Windows Registry Editor Version 5.00':continue
  if line.startswith('[') and line.endswith(']'):
   full=line[1:-1];assert full==prefix or full.startswith(prefix+'\\');key=full[len(prefix):].lstrip('\\').lower();assert key not in result;result[key]={};continue
  assert key is not None and '=' in line
  name,value=line.split('=',1);name=name.lower();assert name not in result[key]
  if value.startswith('hex:') or value.startswith('hex('):value=re.sub(r'\s+','',value).lower()
  result[key][name]=value
 return result
x=parse(P/'G20-native-v2-before.reg','G20_NATV2_BEFORE');y=parse(P/'G20-native-v3-after.reg','G20_NATV3_AFTER')
loader='{98a7ea09-cd06-11f1-9482-c0a810591275}';template='{c94d8c9e-a81c-4de9-968d-ded00f001818}'
base='objects\\';new=base+loader;old=base+template;sequence=r'objects\{9dea862c-5cdd-4e70-acc1-f32b344d4795}\elements\24000002'
removed=sorted(x.keys()-y.keys());changed=sorted(k for k in x.keys()&y.keys() if x[k]!=y[k]);added=sorted(y.keys()-x.keys())
assert removed==changed==[],(removed,changed)
expected=[sequence]+[new+k[len(old):] for k in x if k==old or k.startswith(old+'\\')]
assert added==sorted(expected),added
raw=lambda s:bytes.fromhex(s.split(':',1)[1].replace(',',''))
assert y[sequence].keys()=={'"element"'} and y[sequence]['"element"'].startswith('hex(7):')
assert raw(y[sequence]['"element"']).decode('utf-16le')==loader+'\0\0'
exceptions={'elements\\12000004','elements\\11000001','elements\\21000001'}
diff=[]
for k,v in x.items():
 if k!=old and not k.startswith(old+'\\'):continue
 suffix=k[len(old):].lstrip('\\');n=y[new+k[len(old):]]
 if suffix not in exceptions:assert n==v,(suffix,'unexpected clone change');continue
 assert v.keys()==n.keys()=={'"element"'}
 if suffix=='elements\\12000004':
  assert n['"element"']=='"G20 RAM ACPI canary"'
 else:
  a=raw(v['"element"']);b=raw(n['"element"']);needle='\\G18-maintenance.wim'.encode('utf-16le');replacement='\\G20-acpi-canary.wim'.encode('utf-16le')
  assert len(needle)==len(replacement) and a.count(needle)==1
  assert b==a.replace(needle,replacement),(suffix,'opaque descriptor differs beyond filename')
 diff.append(suffix)
assert set(diff)==exceptions
r={'all_original_registry_keys_values_unchanged':True,'removed_keys':removed,'changed_original_keys':changed,'new_loader_is_exact_template_clone_except_description_and_two_paths':True,'device_descriptors_only_same_length_UTF16_filename_changed':True,'one_time_bootsequence_is_new_loader':True,'G17_default_unchanged':True,'testsigning_and_debug_settings_unchanged':True,'before_keys':len(x),'after_keys':len(y),'added_keys':added,'loader':loader,'template':template,'canary_path':r'\OpenG18\G20-acpi-canary.wim','normalized_candidate_sha256':hashlib.sha256((P/'G20-native-v3-after.bcd').read_bytes()).hexdigest(),'live_FAT_modified':False}
(W/'BCD-semantics-native-v2.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:r[k] for k in r if k!='added_keys'},indent=2))
