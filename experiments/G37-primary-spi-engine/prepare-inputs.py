"""Derive G37 firmware/fixed-state binding from the retained qualified G36 input."""
from pathlib import Path
import argparse,hashlib,json
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
old=a.inputs/'fault-G36/private/inputs';h=old/'g36_binding.h';b=old/'binding.json';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(h)=='388b661feb74103baf5895f77ba38bdbd611d86879b47167b4c745d27e9768a6'
assert sha(b)=='f01349972fd2578176fea8875410f3ef0a3ae23b3246238a172bde555fb43110'
(a.output/'g37_binding.h').write_text(h.read_text().replace('G36','G37'));(a.output/'binding.json').write_bytes(b.read_bytes());print(json.dumps({'fixed_registers':50,'source_G36_header_sha256':sha(h),'generated_header_sha256':sha(a.output/'g37_binding.h')}))
