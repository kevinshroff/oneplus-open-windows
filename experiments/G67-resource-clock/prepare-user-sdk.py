"""Extract only reached headers and two import libraries from pinned packages."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,re,zipfile
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
B=a.inputs;pack=B/'spi-G27/private/wdk-packages';headers=pack/'microsoft.windows.sdk.cpp.nupkg';libraries=pack/'microsoft.windows.sdk.cpp.arm64.nupkg'
def filehash(path):
 h=hashlib.sha256()
 with path.open('rb')as f:
  for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
 return h.hexdigest()
assert filehash(headers)=='5d31b38205bdd9ac761b4cb39fbbc6b7209b01c11194324afc674d7d119483a0'
assert filehash(libraries)=='ac06922186fdd75e4ff1033a304ea629d7917bd0ca85e483762f8109584ccfc4'
selected=[]
with zipfile.ZipFile(headers)as z:
 names={n.lower():n for n in z.namelist()if n.startswith('c/Include/10.0.26100.0/')and not n.endswith('/')}
 pending=['windows.h','cfgmgr32.h'];seen=set()
 while pending:
  name=pending.pop().lower().replace('\\','/');entries=[names[prefix+name]for prefix in ['c/include/10.0.26100.0/um/','c/include/10.0.26100.0/shared/','c/include/10.0.26100.0/ucrt/']if prefix+name in names]
  if not entries:continue
  entry=entries[0]
  if entry in seen:continue
  seen.add(entry);data=z.read(entry)
  pending.extend(x.decode('ascii')for x in re.findall(rb'^\s*#\s*include\s*[<"]([^">]+)[">]',data,re.M)if all(c<128 for c in x))
  if '/um/'not in entry:continue
  relative=PurePosixPath(entry).relative_to('c/Include/10.0.26100.0/um');assert '..'not in relative.parts
  dest=a.output/'um'/str(relative);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(data);selected.append({'entry':entry,'output':str(dest.relative_to(a.output)),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
with zipfile.ZipFile(libraries)as z:
 for entry in ['c/um/arm64/kernel32.Lib','c/um/arm64/cfgmgr32.lib']:
  data=z.read(entry);dest=a.output/'lib'/Path(entry).name;dest.parent.mkdir(exist_ok=True);dest.write_bytes(data);selected.append({'entry':entry,'output':str(dest.relative_to(a.output)),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
receipt={'packages':{'headers_sha256':filehash(headers),'ARM64_libraries_sha256':filehash(libraries)},'files':selected,'native_operations':0};(a.output/'extraction.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({'files':len(selected),'bytes':sum(x['bytes']for x in selected),'native_operations':0}))
