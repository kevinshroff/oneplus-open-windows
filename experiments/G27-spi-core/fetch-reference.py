"""Download only pinned public OnePlus source inputs, verifying exact hashes."""
import argparse, hashlib, json, urllib.request
from pathlib import Path

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
assert not a.output.exists();a.output.mkdir(parents=True)
binding=json.loads((Path(__file__).parent/'source-binding.json').read_text())
kernel='https://raw.githubusercontent.com/OnePlusOSS/android_kernel_oneplus_sm8550/'+binding['kernel_commit']+'/'
modules='https://raw.githubusercontent.com/OnePlusOSS/android_kernel_modules_and_devicetree_oneplus_sm8550/'+binding['modules_commit']+'/'
source_paths={'spi-msm-geni.c':'drivers/spi/spi-msm-geni.c','spi-geni-qcom.c':'drivers/spi/spi-geni-qcom.c',
              'qcom-geni-se.c':'drivers/soc/qcom/qcom-geni-se.c','qcom-geni-se.h':'include/linux/qcom-geni-se.h'}
records=[]
for relative,expected in binding['files'].items():
    name=Path(relative).name
    if relative.startswith('reference-goodix/'):
        url=modules+'vendor/oplus/kernel/touchpanel/oplus_touchscreen_v2/Goodix/GT9966/'+name.removeprefix('GT9966-')
    else:url=kernel+source_paths[name]
    with urllib.request.urlopen(url,timeout=60) as r:b=r.read(expected['bytes']+1)
    assert len(b)==expected['bytes'] and hashlib.sha256(b).hexdigest()==expected['sha256'],relative
    target=a.output/relative;target.parent.mkdir(parents=True,exist_ok=True);assert not target.exists();target.write_bytes(b)
    records.append({'file':relative,'url':url,**expected})
(a.output/'fetch-receipt.json').write_text(json.dumps(records,indent=2)+'\n')
print(json.dumps({'files':len(records),'bytes':sum(r['bytes'] for r in records),'exact_hashes_verified':True}))
