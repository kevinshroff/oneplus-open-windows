"""Extract a complete G25 JSON capture and validate its read-only transcript.

An END marker alone is insufficient: the expected JSON record must be unique,
complete and internally consistent. This collector never submits native work.
"""
from pathlib import Path
import argparse,hashlib,json,re,struct

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--log',required=True,type=Path)
p.add_argument('--marker',required=True)
p.add_argument('--end',required=True)
p.add_argument('--kind',required=True,choices=['inventory','bus1','pmic','smem'])
p.add_argument('--output',required=True,type=Path)
a=p.parse_args();assert not a.output.exists()
s=a.log.read_text(errors='strict');lines=s.splitlines()
assert a.end in lines
hits=[line[len(a.marker)+1:]for line in lines if line.startswith(a.marker+' ')]
assert len(hits)==1
j=json.loads(hits[0])
j['source_log']=a.log.name;j['source_log_sha256']=hashlib.sha256(a.log.read_bytes()).hexdigest()
if a.kind in ['inventory','bus1']:
    assert j['mmio_writes']==j['spmi_commands']==0
    assert j['arbiter_version']==0x70000001 and j['features']==0x80040300 and j['features1']==0x100
    base,bus,count=(0,0,768)if a.kind=='inventory'else(768,1,256)
    assert len(j['map'])==len(j['owner'])==count
    j['map_rows']=[dict(apid=base+i,map=hex(w),ppid=hex((w>>8)&0xfff),irq_owner=bool(w&(1<<24)),owner=j['owner'][i]&7,owner_raw=hex(j['owner'][i]))for i,w in enumerate(j['map'])if w]
    if bus:
        for row in j['map_rows']:row['bus']=bus
    else:
        assert len(j['cmd_db_dwords'])==1536
        assert j['cmd_db_dwords'][:2]==[1,0x0c0330db]
elif a.kind=='pmic':
    assert j['pmic_write_commands']==j['configuration_writes']==0
    commands=[e for e in j['events']if e['kind']=='observer_read_command']
    results=[e for e in j['events']if e['kind']=='pmic_read_result']
    assert len(commands)==j['read_commands']<=24
    targets={t['ppid']:t for t in j['targets']}
    for e in commands:
        t=targets[e['ppid']];assert 0<=t['apid']<768
        assert e['address']==0xc440000+t['apid']*0x20
        assert(e['offset'],e['bytes'])in[(0,8),(8,1),(0x10,1),(0x40,8)]
        assert e['command']==(1<<27)|(e['offset']<<4)|(e['bytes']-1)
    for e in results:
        assert 1<=len(e['bytes'])<=8 and e['status']==1
    assert len(results)<=len(commands)
    begin=a.end[:-4]+'_BEGIN'
    lo=lines.index(begin);hi=lines.index(a.end,lo+1)
    raw=[]
    for line in lines[lo:hi]:
        m=re.fullmatch(r'!ed \[uc\] ([0-9a-fA-F]+) ([0-9a-fA-F]+)\s*',line)
        if m:raw.append(tuple(int(x,16)for x in m.groups()))
    assert raw==[(c['address'],c['command'])for c in commands]
    j['all_logged_MMIO_writes_are_observer_read_commands']=True
    j['raw_observer_write_count']=len(raw)
elif a.kind=='smem':
    assert j['physical_writes']==0 and j['serial_fields_read']is False
    assert len(j['samples'])==2 and j['samples'][0]==j['samples'][1]
    x=j['samples'][0]
    assert x['header']==[0x0089a5a5,408,0,0]
    assert x['core']==[18,519,0x20000]and x['count']==11 and x['array_offset']==0x140
    assert len(x['words'])==22
    raw=struct.pack('<22I',*x['words'])
    j['array_sha256']=hashlib.sha256(raw).hexdigest()
    j['double_read_identical']=True
    j['models']=[dict(index=i,raw_model=hex(x['words'][i*2]),subtype=x['words'][i*2]&0xffff,revision_raw=hex(x['words'][i*2+1]))for i in range(11)]
a.output.write_text(json.dumps(j,indent=2)+'\n')
print(a.kind,a.output.name,'validated')
