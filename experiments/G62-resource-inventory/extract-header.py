"""Extract the exact SDK26100 configuration-manager header from retained NuGet."""
from pathlib import Path
import argparse,hashlib,json,zipfile
p=argparse.ArgumentParser();p.add_argument('--package',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();assert hashlib.sha256(a.package.read_bytes()).hexdigest()=='5d31b38205bdd9ac761b4cb39fbbc6b7209b01c11194324afc674d7d119483a0'
entry='c/Include/10.0.26100.0/um/cfgmgr32.h'
with zipfile.ZipFile(a.package)as z:b=z.read(entry)
a.output.mkdir(parents=True);(a.output/'cfgmgr32.h').write_bytes(b)
r={'package':'Microsoft.Windows.SDK.CPP','version':'10.0.26100.6584','package_url':'https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.cpp/10.0.26100.6584/microsoft.windows.sdk.cpp.10.0.26100.6584.nupkg','package_sha256':'5d31b38205bdd9ac761b4cb39fbbc6b7209b01c11194324afc674d7d119483a0','entry':entry,'header_bytes':len(b),'header_sha256':hashlib.sha256(b).hexdigest(),'native_operations':0};(a.output/'receipt.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
