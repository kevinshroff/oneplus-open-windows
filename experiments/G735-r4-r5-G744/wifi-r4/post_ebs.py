#!/usr/bin/env python3
"""Offline G738 post-EBS planner/comparator. Never queries or controls a device."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets

HERE = Path(__file__).resolve().parent
IMAGE_SHA = 'db672b1395d890b436af1e511c02f7714e51f99a40a4f4cffab1f7491249719c'
BASE = 0x15000000
BANK_FIELDS = ['Sctlr','Actlr','Tcr2','Ttbr0Lo','Ttbr0Hi','Ttbr1Lo','Ttbr1Hi','Tcr','Contextidr','Mair0','Mair1','Fsr','Cbar','Cba2r']
BANK_OFFSETS = [0,4,0x10,0x20,0x24,0x28,0x2c,0x30,0x34,0x38,0x3c,0x58]
INTENDED = dict.fromkeys(BANK_FIELDS, 0)
INTENDED.update(Sctlr=0xe0, Actlr=3, Cbar=0x1f000, Cba2r=1)

class Invalid(ValueError):
    pass

def need(condition, message):
    if not condition:
        raise Invalid(message)

def integer(d, name):
    need(name in d and type(d[name]) is int and 0 <= d[name] <= 0xffffffffffffffff, f'missing/invalid integer: {name}')
    return d[name]

def exact(d, **values):
    for k, v in values.items():
        need(integer(d, k) == v, f'{k}: expected {v:#x}')

def load_owsi(path):
    data = Path(path).read_bytes()
    if data[:4] == b'OWSI':
        spec = importlib.util.spec_from_file_location('g735r4_owsi', HERE/'parse_owsi.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        report = module.decode(data)
    else:
        report = json.loads(data)
    need(type(report) is dict, 'OWSI must decode to an object')
    return report, hashlib.sha256(data).hexdigest()

def overlap(smr, sid):
    return smr != 0 and (((smr & 0x7fff) ^ sid) & ~((smr >> 16) & 0x7fff) & 0x7fff) == 0

def expected_records(r):
    exact(r, Magic=0x35333747, Version=4, Bytes=1584, Stage=7, Code=0,
          Prepared=1, Writes=31, AttemptedWrites=31, RetainUntilReset=1,
          Id0=0x4c017e69, Id1=0x60000046, NumSmr=105, NumCb=70,
          PageSize=0x1000, Pages=128, Span=0xc6000, CbBase=BASE+0x80000,
          MapCode=0, MapStatus=0, GateCode=0, InventoryCount=105,
          PreflightVerified=1, Revalidations=33, GfsrBefore=0, GfsrAfter=0,
          SidHash=0x15, SidTableAddress=0x1c02054, SidEntry=0x01000100)
    cr0 = integer(r, 'Cr0')
    need(not (cr0 & 1), 'SMMU CLIENTPD must be clear')
    need(not (integer(r, 'ParfCfg') & 1), 'PARF bypass must be clear')
    smr, s2cr = r.get('BeforeSmr'), r.get('BeforeS2cr')
    need(type(smr) is list and type(s2cr) is list and len(smr) == len(s2cr) == 105, 'complete 105-pair initial inventory required')
    need(all(type(v) is int and 0 <= v <= 0xffffffff for v in smr+s2cr), 'invalid inventory word')
    used, free = set(), []
    for n, (a,b) in enumerate(zip(smr,s2cr)):
        need(not overlap(a,0x1400) and not overlap(a,0x1401), f'initial SID overlap in slot {n}')
        if (b >> 16) & 3 == 0:
            need((b & 0xff) < 70, 'initial S2CR bank exceeds reported geometry')
            used.add(b & 0xff)  # includes invalid/staged SMRs
        if a == 0 and b == 0x20000:
            free.append(n)
    need(len(free) >= 2, 'two initial default-FAULT slots required')
    streams = r.get('Stream')
    need(type(streams) is list and len(streams) == 2, 'two stream reports required')
    records = {}
    def add(address, expected, label):
        need(address % 4 == 0 and address not in records, 'overlapping/unaligned derived address')
        need(type(expected) is int and 0 <= expected <= 0xffffffff, f'invalid expected word for {label}')
        records[address] = {'address':f'0x{address:08x}', 'expected':expected, 'field':label}
    add(BASE,cr0,'global.CR0')
    add(BASE+0x20,0x4c017e69,'global.IDR0')
    add(BASE+0x24,0x60000046,'global.IDR1')
    add(BASE+0x48,0,'global.GFSR')
    add(BASE+0x50,integer(r,'Gfsynr0Before'),'global.GFSYNR0')
    add(BASE+0x54,integer(r,'Gfsynr1Before'),'global.GFSYNR1')
    add(0x1c02c00,integer(r,'ParfCfg'),'parf.CFG')
    add(0x1c02054,0x01000100,'parf.SID_ROW_15')
    chosen = set()
    for k, s in enumerate(streams):
        need(type(s) is dict, 'invalid stream report')
        cb = integer(s,'Cb'); slot = integer(s,'Slot'); sid = [0x1401,0x1400][k]
        need(1 <= cb < 70 and cb not in used and cb not in chosen, 'selected bank referenced/duplicate/out of bounds')
        chosen.add(cb)
        exact(s, Sid=sid, Slot=free[k], BeforeValid=1, AfterValid=1, SmrReadValid=1, S2crReadValid=1,
              CbAddress=BASE+0x80000+cb*0x1000, SmrAddress=BASE+0x800+4*slot,
              S2crAddress=BASE+0xc00+4*slot, CbarAddress=BASE+0x1000+4*cb,
              Cba2rAddress=BASE+0x1800+4*cb, Smr=0x80000000|sid, S2cr=cb,
              Sctlr=0xe0, Cbar=0x1f000, Cba2r=1)
        before, after = s.get('Before'), s.get('After')
        need(type(before) is dict and type(after) is dict, 'complete before/after bank snapshots required')
        for field in BANK_FIELDS:
            need(integer(before,field) <= 0xffffffff, f'invalid Before.{field}')
        exact(before,Actlr=3,Fsr=0,Cbar=0,Cba2r=0)
        need(not (integer(before,'Sctlr') & 0x61), 'initial selected bank was not disabled/non-reporting')
        exact(after,**INTENDED)  # never inherit UNKNOWN before attributes
        for field, offset in zip(BANK_FIELDS[:12], BANK_OFFSETS):
            add(BASE+0x80000+cb*0x1000+offset,INTENDED[field],f'SID{sid:04x}.CB{cb}.{field}')
        add(BASE+0x1000+4*cb,0x1f000,f'SID{sid:04x}.CB{cb}.Cbar')
        add(BASE+0x1800+4*cb,1,f'SID{sid:04x}.CB{cb}.Cba2r')
        add(BASE+0x800+4*slot,0x80000000|sid,f'SID{sid:04x}.SMR{slot}')
        add(BASE+0xc00+4*slot,cb,f'SID{sid:04x}.S2CR{slot}')
    need(len(records)==40, 'unexpected snapshot size')
    return [records[a] for a in sorted(records)]

def make_plan(report, digest, image_sha, boot_id, session, capture_id):
    need(image_sha == IMAGE_SHA, 'image SHA does not match pinned G735r4')
    need(type(boot_id) is int and 0 < boot_id < 1000000000, 'invalid supplied BootID')
    need(type(session) is str and re.fullmatch(r'[A-Za-z0-9_-]{8,128}',session), 'invalid supplied session')
    need(type(capture_id) is str and re.fullmatch(r'[0-9a-f]{16,64}',capture_id), 'invalid capture ID')
    records = expected_records(report)
    begin, end = f'G738_POST_EBS_BEGIN_{capture_id}', f'G738_POST_EBS_END_{capture_id}'
    groups = []
    for record in records:
        address = int(record['address'],16)
        if groups and address == groups[-1][-1]+4 and len(groups[-1])<8:
            groups[-1].append(address)
        else:
            groups.append([address])
    commands = [f'.echo {begin}']+[f'!dd [uc] -m {g[0]:x} L{len(g):x}' for g in groups]+[f'.echo {end}']
    return {'schema':'g738-post-ebs-plan/1','owsi_sha256':digest,
            'root_supplied_context':{'image_sha256':image_sha,'boot_id':boot_id,'session':session},
            'capture_id':capture_id,'begin_marker':begin,'end_marker':end,
            'read_bytes':4*len(records),'commands':commands,'expected_records':records}

def parse_snapshot(text, plan):
    lines = text.splitlines()
    begin = [n for n,line in enumerate(lines) if line.strip()==plan['begin_marker']]
    end = [n for n,line in enumerate(lines) if line.strip()==plan['end_marker']]
    need(len(begin)==len(end)==1 and begin[0]<end[0], 'exactly one ordered capture marker pair required')
    expected = {int(r['address'],16) for r in plan['expected_records']}
    seen, errors = {}, []
    for line in lines[begin[0]+1:end[0]]:
        match = re.match(r'^\s*#?([0-9A-Fa-f`]+)\s+(.*?)\s*$',line)
        if not match:
            continue
        address = int(match.group(1).replace('`',''),16)
        tokens = match.group(2).split()
        for n, token in enumerate(tokens):
            at = address+4*n
            if at not in expected:
                errors.append(f'unplanned physical word at 0x{at:08x}')
                continue
            if at in seen:
                errors.append(f'duplicate physical word at 0x{at:08x}')
                continue
            if not re.fullmatch(r'[0-9a-fA-F]{8}',token):
                errors.append(f'unreadable physical word at 0x{at:08x}: {token}')
                continue
            seen[at] = int(token,16)
    return seen, errors

def compare(report, digest, plan, text):
    need(type(plan) is dict, 'plan must be an object')
    context = plan.get('root_supplied_context',{})
    canonical = make_plan(report,digest,context.get('image_sha256'),context.get('boot_id'),context.get('session'),plan.get('capture_id'))
    need(plan == canonical, 'plan differs from regenerated bounded plan/OWSI')
    measured, errors = parse_snapshot(text,plan)
    comparisons = []
    for record in plan['expected_records']:
        at = int(record['address'],16)
        present = at in measured
        actual = measured[at] if present else None
        comparisons.append({**record,'measured':present,'actual':actual,
                            'comparison':'missing' if not present else 'match' if actual==record['expected'] else 'mismatch'})
    passed = not errors and all(r['comparison']=='match' for r in comparisons)
    return {'schema':'root-g738-post-ebs-proof/1','result':'pass' if passed else 'fail',
            'scope':'post-EBS register equality only; no DMA execution or live identity query',
            'root_supplied_context':context,'context_verified_by_helper':False,
            'capture_id':plan['capture_id'],'owsi_sha256':digest,
            'snapshot_sha256':hashlib.sha256(text.encode()).hexdigest(),
            'planned_words':len(comparisons),'measured_words':len(measured),
            'errors':errors,'comparisons':comparisons,
            'remaining_root_preconditions':['Bind this capture to the supplied current BootID/session/image.',
                                            'Independently verify WLAN remains disabled until the authorized DMA attempt.']}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode',required=True)
    plan = sub.add_parser('plan')
    plan.add_argument('--owsi',required=True);plan.add_argument('--image-sha',required=True)
    plan.add_argument('--boot-id',required=True,type=int);plan.add_argument('--session',required=True)
    plan.add_argument('--capture-id',default=None);plan.add_argument('--out',required=True)
    check = sub.add_parser('check')
    check.add_argument('--owsi',required=True);check.add_argument('--plan',required=True)
    check.add_argument('--snapshot',required=True);check.add_argument('--out',required=True)
    args = parser.parse_args()
    try:
        report,digest = load_owsi(args.owsi)
        if args.mode=='plan':
            result = make_plan(report,digest,args.image_sha,args.boot_id,args.session,args.capture_id or secrets.token_hex(12))
        else:
            result = compare(report,digest,json.loads(Path(args.plan).read_text()),Path(args.snapshot).read_text())
        Path(args.out).write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result,indent=2))
        return 0 if args.mode=='plan' or result['result']=='pass' else 1
    except (Invalid,ValueError,KeyError,TypeError,OSError) as error:
        parser.exit(2,f'offline validation failed: {error}\n')

if __name__=='__main__':
    raise SystemExit(main())
