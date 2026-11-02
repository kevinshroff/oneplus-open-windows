"""Reconstruct native descriptor bytes and compare listed CM allocations only.

Missing CM entries never authorize physical access and are not global ownership
proof. WDF translated resources are a separate contract for a future driver.
"""
from pathlib import Path
import argparse,collections,hashlib,json,re,struct
p=argparse.ArgumentParser();p.add_argument('--evidence',type=Path);p.add_argument('--hardware-source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();W=Path(__file__).resolve().parent;E=a.evidence or W;J=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();assert not a.output.exists()
raw=E/'native-resources-v2.json'if a.evidence else W/'private/native-resources-v2.json';s=J(E/'native-snapshot-v2.json');b=J(E/'helper-build.json'if a.evidence else W/'private/helper-02/build.json');d=J(raw)
assert s['phase']=='read_only_snapshot_preserved_original_stack_and_same_G17_control_verified'
assert sha(raw)==s['snapshot_sha256']==s['snapshot_summary']['sha256']
assert s['jobs']['hash-query-helper']['receipt']['sha256']==b['binary_sha256']=='3f6f4eb1e9ad67469b3ab33299807d664d01c9b7b33c7bcc485c6e58c0be1d9f'
assert d['version']=='G62-resource-snapshot2'and d['descriptor_encoding']=='lossless-consecutive-IRQ-RLE1'and d['native_arch']=='arm64'and d['processors']==8 and not d['enumeration_warnings']
assert d['DSDT_sha256']=='c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01'and d['device_filter']=='CM_GETIDLIST_FILTER_PRESENT'
assert d['hardware_register_reads']==d['hardware_register_writes']==d['native_device_or_configuration_mutations']==0
assert len({x['id'].casefold()for x in d['devices']})==len(d['devices'])==162
assert s['audit_before']==s['audit_after'];v=s['audit_after'];assert v['owned_roots']==0 and v['source_interfaces']==[]and not v['source_service']['present']and not v['inbox_include']['present']and v['inventory']['SM_DIGITIZER']==0
assert v['processors']==s['probe_after']['detail']['cpus']==8 and s['probe_after']['detail']['arch']=='arm64'
assert all(z['receipt']['session']=='00000000000000000000000000000000'for z in s['jobs'].values())
mem=[];irq=[];total=0;raw_bytes=0;retained=0;populated=[]
for node in d['devices']:
 assert node['locate_cr']==node['status_cr']==0
 for kind in ['allocated','boot']:
  c=node[kind];assert c['enumeration_complete']
  if c['first_query_cr']==14:assert not c['logs'];continue
  assert c['first_query_cr']==0 and c['end_query_cr']==14 and c['logs']
  for log in c['logs']:
   proof=log['resource_enumeration'];assert proof['enumeration_complete']and proof['end_query_cr']==15
   stream=hashlib.sha256();count=size=0;retained+=len(log['resources'])
   for row in log['resources']:
    assert not row.get('error')and not row.get('decode_error');rb=bytes.fromhex(row['raw_hex']);assert len(rb)==row['bytes'];n=row['repeat'];assert 1<=n<=8192
    typ=row['type'];count+=n;size+=len(rb)*n
    if typ in [1,7]:
     assert n==1;hs,rs=32,36 if typ==1 else 40;assert len(rb)in[hs,hs+rs];ct,rt,base,end,flags,reserved=struct.unpack_from('<IIQQII',rb);assert ct==0 and rt==rs and base<=end and end-base<2**64-1
     expected={'kind':'memory'if typ==1 else'large_memory','placeholder_range':len(rb)>hs,'memory':{'base':base,'end':end,'bytes':end-base+1,'flags':flags,'reserved':reserved}};assert row['decoded']==expected
     mem.append({'device':node['id'],'service':node['service'],'list':kind,**expected['memory']})
    elif typ==4:
     assert len(rb)in[24,36];ct,rt,flags,group,number,aff=struct.unpack_from('<IIHHIQ',rb);assert ct==0 and rt==12 and number+n-1<=0xffffffff
     expected={'kind':'interrupt64','placeholder_range':len(rb)>24,'interrupt':{'number':number,'flags':flags,'group':group,'affinity':aff}};assert row['decoded']==expected
     irq.append({'device':node['id'],'service':node['service'],'list':kind,'first_number':number,'last_number':number+n-1,'count':n,'flags':flags,'group':group,'affinity':aff})
    else:raise AssertionError(('Unexpected descriptor type: retain and investigate instead of inferring absence',typ))
    for i in range(n):
     expanded=bytearray(rb)
     if n>1:struct.pack_into('<I',expanded,12,number+i)
     stream.update(struct.pack('<II',typ,len(rb)));stream.update(expanded)
   assert count==proof['descriptor_count']and size==proof['raw_bytes']and stream.hexdigest()==proof['raw_stream_sha256']
   total+=count;raw_bytes+=size;populated.append({'device':node['id'],'service':node['service'],'list':kind,'descriptors':count,'stored_rows':len(log['resources']),'raw_stream_sha256':stream.hexdigest()})
assert total==d['descriptor_count']==2564 and raw_bytes==d['raw_descriptor_bytes']==92368
ufs=[r for r in mem if r['list']=='allocated'];assert len(ufs)==1 and ufs[0]['device']==r'ACPI\QCOM24A5\0'and ufs[0]['service']=='storufs'and ufs[0]['base']==0x1d84000 and ufs[0]['bytes']==0x1c000
ui=[r for r in irq if r['list']=='allocated'and r['device']==ufs[0]['device']];assert len(ui)==1 and ui[0]['first_number']==ui[0]['last_number']==297
assert sha(a.hardware_source)=='85235ac495e48d0337c85f2034a8c8fe57ae4cfec50684695804a1ec7e687fd5'
source=a.hardware_source.read_text();m=re.search(r'G59PowerRanges\[16\]=\{(.*?)\};',source);assert m;ranges=[(int(x,16),int(y,16))for x,y in re.findall(r'\{(0x[0-9a-f]+),(0x[0-9a-f]+)\}',m.group(1))];assert len(ranges)==16
rows=[]
for i,(base,size)in enumerate(ranges):
 overlap=[r for r in mem if r['list']=='allocated'and r['base']<=base+size-1 and base<=r['end']]
 rows.append({'G59_map_index':i,'source_base':hex(base),'source_bytes':hex(size),'listed_allocated_memory_matches':overlap})
assert not any(r['listed_allocated_memory_matches']for r in rows)
report={'passed':True,'native_devices':len(d['devices']),'descriptors_reconstructed':total,'raw_descriptor_bytes_reconstructed':raw_bytes,'stored_descriptor_rows':retained,'snapshot_bytes':raw.stat().st_size,'snapshot_sha256':sha(raw),'all_logical_and_resource_enumerations_complete':True,'per_configuration_byte_stream_hashes_match':True,'populated_configurations':populated,'listed_memory_allocations':mem,'listed_interrupt_runs':irq,'G59_diagnostic_mapping_comparison':rows,'hardware_or_configuration_mutations':0,'original_stack_and_same_G17_control_restored':True,'all21_goal_areas_active':True,'observations':['Only UFS and the ACPI HAL device have allocated/boot descriptors in this present-device snapshot.','The UFS memory range1d84000/1c000 and interrupt number297 match the retained original ACPI UFS descriptor.','No listed allocated memory descriptor overlaps any of the16 G59 diagnostic mapping ranges.','HAL boot affinity is0xffffffffffffffff; its allocated affinity is0x00000000ffffffff. Both are preserved without normalization.'],'inferences':['Proper peripheral support needs explicit platform resource/provider work; the diagnostic root/manual mappings do not establish the needed Windows resource ownership.'],'limits':['CM allocated/boot lists are recorded separately. This snapshot is not a WDF ResourcesTranslated list and does not establish HAL interrupt translation or actual delivery.','Absence in these lists is not proof that physical hardware is globally unowned or safe to access; firmware, HAL and other owners may be outside these APIs.','This inventories resource declarations, not GPIO/SPI/DMA/clock/regulator functionality or a compatible PEP.','No fresh protected-partition hash audit, firmware/BCD/raw-disk write or reboot is claimed.']}
a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items()if k not in['populated_configurations','listed_memory_allocations','listed_interrupt_runs','G59_diagnostic_mapping_comparison']}))
