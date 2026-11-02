"""Audit logical file streams across the original and trial WIM; do not boot or write the phone."""
from pathlib import Path
import hashlib
import argparse
import json
import re
import subprocess

W = Path(__file__).resolve().parent
P = W/'private'
source = W.parent/'private/G18-maintenance.wim'
parser=argparse.ArgumentParser();parser.add_argument('--trial',type=Path,default=P/'G20-canary-LZX.wim');parser.add_argument('--run',default='');args=parser.parse_args();assert re.fullmatch('[A-Za-z0-9-]*',args.run);suffix=('-'+args.run) if args.run else '';trial=args.trial
assert hashlib.sha256(source.read_bytes()).hexdigest() == '1db2c5d735281ddcb11f1723bb729753e81a74793a495a83c0bece2ffd26d7e9'

def manifest(path, name):
    raw = subprocess.check_output(['colima','ssh','--','wimlib-imagex','dir',str(path),'1','--detailed'])
    (P/(name+suffix+'-detailed-dir.txt')).write_bytes(raw)
    text = raw.decode('utf8')
    blocks = re.split(r'(?m)^Full Path\s*=\s*',text)
    result = {}
    for block in blocks[1:]:
        first, _, body = block.partition('\n')
        assert first.startswith('"') and first.endswith('"')
        path_name = first[1:-1].replace('\\','/').strip('/')
        assert path_name not in result
        streams = []
        hashes = list(re.finditer(r'(?m)^Hash\s*=\s*0x([0-9a-fA-F]{40})\s*\nUncompressed size\s*=\s*(\d+) bytes',body))
        assert len(hashes)==len(re.findall(r'(?m)^Hash\s*=',body))
        for m in hashes:
            headers = [l.strip() for l in body[:m.start()].splitlines() if 'data stream' in l.lower()]
            assert headers
            streams.append({'stream':headers[-1],'sha1':m[1].lower(),'bytes':int(m[2])})
        attrs = re.search(r'(?m)^Attributes\s*=\s*(0x[0-9a-fA-F]+)',body)
        sd = re.search(r'(?m)^Security Descriptor\s*=\s*([^\n]*)',body)
        result[path_name] = {'streams':sorted(streams,key=lambda x:x['stream']),'attributes':attrs[1] if attrs else None,'security_descriptor':sd[1] if sd else None}
    assert len(result)>17000
    (P/(name+suffix+'-logical-manifest.json')).write_text(json.dumps(result,indent=2)+'\n')
    return result, {'detailed_bytes':len(raw),'detailed_sha256':hashlib.sha256(raw).hexdigest(),'path_entries':len(result),'stream_entries':sum(len(v['streams']) for v in result.values())}

a, ar = manifest(source,'source')
b, br = manifest(trial,'canary')
added = sorted(b.keys()-a.keys())
removed = sorted(a.keys()-b.keys())
changed = sorted(k for k in a.keys()&b.keys() if a[k]!=b[k])
assert not removed and not changed, (removed,changed)
assert added==['Windows/System32/acpitabl.dat'],added
assert b[added[0]]['streams']==[{'stream':'Unnamed data stream:','sha1':hashlib.sha1((P/'acpitabl.dat').read_bytes()).hexdigest(),'bytes':586}]
r = {'source_wim_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'trial_wim_sha256':hashlib.sha256(trial.read_bytes()).hexdigest(),'trial_wim_bytes':trial.stat().st_size,'source_manifest':ar,'trial_manifest':br,'only_added_path':added,'removed_paths':removed,'changed_existing_file_streams_attributes_security':changed,'all_existing_file_stream_hashes_unchanged':True,'canary_sha256':hashlib.sha256((P/'acpitabl.dat').read_bytes()).hexdigest(),'scope':'logical contents, attributes and security descriptors; compression/metadata offsets and timestamps can differ; Windows table override not yet tested'}
(W/('WIM-content-audit'+suffix+'.json')).write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r,indent=2))
