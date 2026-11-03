#!/usr/bin/env python3
"""Independent bounded-file verification. Default inert; never executes input."""
import argparse,hashlib,json,pathlib,struct
EXPECTED_BASE='927bf9450f462607435d616c0d2f00884f6689bcd2c395bcc949896ff93c8ee0'
EXPECTED_CANDIDATE='2a0d977055dd6e8e59cbad80f2e3462d6e1e2d6a62d88f18a0753504d60e8495'
OFFSET,LENGTH=1365148,280
sha=lambda b:hashlib.sha256(b).hexdigest()
def verify(base,candidate):
 if sha(base)!=EXPECTED_BASE or sha(candidate)!=EXPECTED_CANDIDATE:raise ValueError('Exact immutable base/candidate required')
 if len(base)!=3841536 or len(candidate)!=len(base):raise ValueError('Size mismatch')
 restored=candidate[:OFFSET]+base[OFFSET:OFFSET+LENGTH]+candidate[OFFSET+LENGTH:]
 if restored!=base:raise ValueError('Changes outside allowed body')
 changed=[i for i,(a,b)in enumerate(zip(base,candidate))if a!=b]
 if len(changed)!=258:raise ValueError('Bounded changed-byte inventory differs')
 if candidate[29116:29120]!=bytes.fromhex('08008052'):raise ValueError('NC changed')
 # Table is final32B of assembled264B, followed by16B NOP padding.
 if struct.unpack_from('<8I',candidate,OFFSET+232)!=(0x1b85400,0x1b85404,0x1b85408,0x1b8540c,0x1b85010,0x1b85014,0x1b8506c,0x1b85070):raise ValueError('Table differs')
 if candidate[OFFSET+264:OFFSET+280]!=bytes.fromhex('1f2003d5')*4:raise ValueError('NOP padding differs')
 return dict(base_sha256=sha(base),candidate_sha256=sha(candidate),bytes=len(candidate),different_bytes=len(changed),all_changes_in_body=True,unchanged_outside_body=True,NC_MOV0_retained=True,runtime_qualified=False)
def main():
 p=argparse.ArgumentParser();p.add_argument('--verify-offline',action='store_true');p.add_argument('--base',type=pathlib.Path);p.add_argument('--candidate',type=pathlib.Path);a=p.parse_args()
 if not a.verify_offline:print('INERT: no files read');return
 print(json.dumps(verify(a.base.read_bytes(),a.candidate.read_bytes())))
if __name__=='__main__':main()
