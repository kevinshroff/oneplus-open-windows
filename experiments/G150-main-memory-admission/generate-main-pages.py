"""Bind the fixed main page runs to the final original-loader replay."""
from pathlib import Path
import argparse,hashlib,json
p=argparse.ArgumentParser();w=Path(__file__).resolve().parent
p.add_argument('--replay',type=Path,default=w.parent/'charging-G147/private/main-target-replay-04.json')
p.add_argument('--output',type=Path,default=w/'OpenMainAdmissionPlan.h')
a=p.parse_args();assert not a.output.exists();raw=a.replay.read_bytes()
assert hashlib.sha256(raw).hexdigest()=='c92416ad0eec6d8d87dd0d483238472bf5f8a53218911e590c72147e72145236'
j=json.loads(raw);assert j['passed'] and j['cases']==8 and j['CPU_pages_touched']==15851
plan=j['complete_target_plan'];assert len(plan)==89 and sum(r['bytes'] for r in plan)==64910785
assert sum(r['kind']=='file-copy-model' for r in plan)==54 and sum(r['kind']=='zero-model' for r in plan)==35
pages=set();last=0
for r in plan:
 start,end=r['address'],r['address']+r['bytes']
 assert 0x9ea00000<=start<end<=0xa3280000 and start>=last
 last=end;pages.update(range(start&~4095,(end+4095)&~4095,4096))
assert len(pages)==15851
runs=[]
for page in sorted(pages):
 if runs and page==runs[-1][1]:runs[-1][1]+=4096
 else:runs.append([page,page+4096])
assert runs==[[0x9ea00000,0xa1050000],[0xa109c000,0xa2837000]]
rows=[' {%sULL,%sULL},'%(hex(start),hex(end)) for start,end in runs]
a.output.write_text('''/* SPDX-License-Identifier: MIT
 * Generated from G147's hash-bound original-loader writes. Page coverage only:
 * mapping a partially touched page does not permit reading its untouched bytes.
 * No zero-only segment or alignment-hole reads are added by this plan.
 */
#ifndef OPEN_MAIN_ADMISSION_PLAN_H
#define OPEN_MAIN_ADMISSION_PLAN_H
#define MAIN_BASE 0x9ea00000ULL
#define MAIN_BYTES 0x4880000ULL
#define MAIN_CPU_PAGES 15851U
typedef struct {UINT64 Base,End;} OMA_PAGE_RUN;
STATIC CONST OMA_PAGE_RUN mMainPageRuns[2]={
'''+ '\n'.join(rows)+'\n};\n#endif\n')
print(json.dumps({'page_runs':len(runs),'pages':len(pages),'source_report_sha256':hashlib.sha256(raw).hexdigest(),'plan_sha256':hashlib.sha256(a.output.read_bytes()).hexdigest()}))
