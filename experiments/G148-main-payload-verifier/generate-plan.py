"""Generate the fixed verifier plan from the final, hash-bound original replay."""
from pathlib import Path
import argparse,hashlib,json
p=argparse.ArgumentParser();w=Path(__file__).resolve().parent
p.add_argument('--replay',type=Path,default=w.parent/'charging-G147/private/main-target-replay-04.json')
p.add_argument('--output',type=Path,default=w/'OpenMainPayloadPlan.h')
a=p.parse_args();assert not a.output.exists();raw=a.replay.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='c92416ad0eec6d8d87dd0d483238472bf5f8a53218911e590c72147e72145236'
j=json.loads(raw);assert j['passed']and j['cases']==8 and j['CPU_pages_touched']==15851
plan=j['complete_target_plan'];assert len(plan)==89
assert sum(r['kind']=='file-copy-model'for r in plan)==54 and sum(r['kind']=='zero-model'for r in plan)==35
assert sum(r['bytes']for r in plan)==64910785
rows=[];last=0
for r in plan:
 assert 0x9ea00000<=r['address']<r['address']+r['bytes']<=0xa3280000 and r['address']>=last
 last=r['address']+r['bytes'];kind=1 if r['kind']=='file-copy-model'else 2
 digest=bytes.fromhex(r['sha256'])if kind==1 else bytes(32);assert len(digest)==32
 rows.append(' {%d,0,%sULL,%sULL,{%s}},'%(kind,hex(r['address']),hex(r['bytes']),','.join(hex(v)for v in digest)))
a.output.write_text('''/* SPDX-License-Identifier: MIT
 * Generated from the exact G147 original-loader replay; do not edit by hand.
 * Only54 copied files and35 zero tails. No BSS-only or alignment-hole reads.
 */
#ifndef OPEN_MAIN_PAYLOAD_PLAN_H
#define OPEN_MAIN_PAYLOAD_PLAN_H
typedef struct {UINT32 Kind,Reserved;UINT64 Base,Bytes;UINT8 Digest[32];} OMP_PLAN;
STATIC CONST OMP_PLAN mMainPlan[89]={
'''+ '\n'.join(rows)+'\n};\n#endif\n')
print(json.dumps({'extents':89,'copied_files':54,'zero_tails':35,'verified_bytes':64910785,'source_report_sha256':hashlib.sha256(raw).hexdigest(),'plan_sha256':hashlib.sha256(a.output.read_bytes()).hexdigest()}))
