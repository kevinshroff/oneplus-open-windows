"""Cross-bind the two retained reports from the single G133 temporary boot."""
from pathlib import Path
import hashlib,json,re,struct
w=Path(__file__).resolve().parent;p=w/'private'
load=lambda n:json.loads((p/n).read_text())
o=load('OAPF-native.json');m=load('OPAS-native.json');raw=load('raw-OAPF-native.json')
assert o['ok']and m['ok']and raw['ok']and raw['stable_double_read']
r=o['report'];meta=m['report'];b=(p/'native-OAPF.bin').read_bytes()
assert hashlib.sha256(b).hexdigest()==raw['sha256']==r['table_sha256']
assert len(b)==raw['bytes']==struct.unpack_from('<I',b,4)[0]and sum(b)%256==0
assert all(r[k]for k in ['report_valid','files_verified','reservation_verified','cleanup_complete','kernel_queries_complete','HOB_storage_bounded','SCM_maps_observed'])
assert not any(r[k]for k in ['kernel_memory_eligible','SCM_hook_eligible','DSP_started','display_ownership_qualified'])
assert all(meta[k]for k in ['report_valid','metadata_verified','PIL_code_verified','SCM_code_verified','preflight_ready'])
assert meta['diagnostic_requested_PAS_stages']==0 and meta['images_attempted']==2
assert all(i['metadata_bytes_match']and i['CPU_header_accepted']and i['cleanup_accepted']for i in meta['images'])
t=r['text']
def row(pattern):
 rows=re.findall('^'+pattern+'$',t,re.M);assert len(rows)==1,(pattern,len(rows));return [int(x,16)for x in rows[0]]
hob_base=int(r['HOB_copied_base'],16);hob_limit=int(r['HOB_limit'],16)
phit=row(r'K133_phit type=([0-9]+) length=([0-9]+) memory_bottom=([A-Fa-f0-9]+) free_bottom=([A-Fa-f0-9]+) original_end=([A-Fa-f0-9]+)')
# The first two PHIT fields are decimal in the firmware text.
phit[0]=int(re.search(r'K133_phit type=([0-9]+)',t)[1]);phit[1]=int(re.search(r'K133_phit type=\d+ length=([0-9]+)',t)[1])
assert phit[0]==1 and phit[1]==56 and phit[3]==phit[4]+8
assert phit[4]-phit[2]==r['HOB_walked_bytes']==6384
assert phit[4]<hob_base and hob_base+r['HOB_walked_bytes']+8<=hob_limit
assert r['HOB_count']==122 and r['kernel_image_overlaps']==0
assert 'K133_hob_count=122 walked_bytes=6384 overlaps=1 end=1\n'in t
assert 'K133_hob_alloc base=A8000000 bytes=10000000 type=0 name=00000000-0000-0000-0000-000000000000 static_kernel_bounds=1\n'in t
assert not re.search(r'^K133_hob_fv |^K133_image ',t,re.M)
table=int(r['SCM_table'],16);slot=int(r['SCM_slot'],16)
assert table==int(meta['SCM_image_base'],16)+int(meta['SCM_table_RVA'],16)
assert slot==table+56 and meta['SCM_ABI']=='ARMv8'
gcd=row(r'K133_scm_gcd base=([A-Fa-f0-9]+) bytes=([A-Fa-f0-9]+) type=([0-9]+) cap=([A-Fa-f0-9]+) attr=([A-Fa-f0-9]+)')
efi=row(r'K133_scm_efi base=([A-Fa-f0-9]+) pages=([A-Fa-f0-9]+) type=([0-9]+) attr=([A-Fa-f0-9]+)')
assert gcd[2]==2 and gcd[0]<=slot<=gcd[0]+gcd[1]-8
assert efi[2]==3 and efi[0]<=slot<=efi[0]+efi[1]*4096-8
assert gcd[4]==8 and efi[3]==0x100f
assert not meta['SCM_slot_attributes_known']
result={'passed':True,'native_G133_firmware_boots':1,'OAPF_sha256':r['table_sha256'],'OPAS_sha256':meta['table_sha256'],'copied_HOB_contract_confirmed':True,'HOB_original_memory_bottom':hex(phit[2]),'HOB_original_end':hex(phit[4]),'HOB_original_free_bottom':hex(phit[3]),'HOB_copied_base':hex(hob_base),'HOB_limit':hex(hob_limit),'HOB_count':122,'HOB_walked_bytes':6384,'HOB_end_marker':True,'HOB_target_overlaps':'Exactly the static reserved Kernel allocation; no overlapping FV HOB','loaded_image_count':123,'loaded_image_overlaps':0,'SCM_table_and_slot_cross_bound_to_OPAS':True,'SCM_table':hex(table),'SCM_slot':hex(slot),'SCM_ABI':'ARMv8','SCM_GCD_attributes':hex(gcd[4]),'SCM_EFI_attributes':hex(efi[3]),'actual_CPU_permissions_known':False,'source_files_verified':64,'source_read_calls':577,'source_read_bytes':37158912,'source_denied_writes':0,'source_failures':0,'source_cleanup_verified':True,'native_PAS_requests':0,'native_GLINK_requests':0,'native_charger_configuration_writes':0,'partition_flashes':0,'limits':['A complete published-map/HOB/image inventory is not proof of global DMA or physical display ownership.','Published GCD/EFI attributes do not substitute for a current CPU translation permission query.','No candidate staging RAM access, SCM hook, DSP start or charging result is established.']}
(p/'native-qualification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
