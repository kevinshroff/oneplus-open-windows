"""Correlate the native client PE and REA import inventories before execution."""
from pathlib import Path
import hashlib,json
import pefile
W=Path(__file__).resolve().parent;P=W/'private';b=(P/'G70-client.exe').read_bytes();meta=json.loads((W/'client-link.json').read_text());rea=json.loads((W/'REA-client-imports.json').read_text())
sha=hashlib.sha256(b).hexdigest();assert sha==meta['binary_sha256']==rea['artifact_sha256']and len(b)==meta['bytes']<=49152
pe=pefile.PE(data=b);assert (pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,pe.OPTIONAL_HEADER.MajorSubsystemVersion,pe.OPTIONAL_HEADER.MinorSubsystemVersion)==(6,1,6,2)
assert pe.FILE_HEADER.Machine==0xaa64 and pe.OPTIONAL_HEADER.Magic==0x20b and pe.OPTIONAL_HEADER.Subsystem==3
imports={(dll.dll.decode().upper(),i.name.decode())for dll in pe.DIRECTORY_ENTRY_IMPORT for i in dll.imports};expected={tuple(x['name'].split('::',1))for x in rea['external_symbols']};assert imports==expected
assert {dll for dll,_ in imports}=={'KERNEL32.DLL'}and len(imports)==18
assert not any(name.startswith(('NtWrite','ZwWrite','CreateService','CM_Disable','CM_Enable','SetupDi'))for _,name in imports)
import re
table=bytes(int(x,16)for x in re.findall(r'0x([0-9a-f]{2})',(P/'acpi-01/g70_binding.h').read_text()));assert len(table)==768 and b.count(table)==1
assert pe.OPTIONAL_HEADER.DllCharacteristics&0x140==0x140
assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress and pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
r={'passed':True,'binary_sha256':sha,'bytes':len(b),'native_ARM64_console':True,'CRT_dependency':False,'exact768byte_trial_table_embedded_once':True,'REA_Ghidra_import_inventory_matches_PE':True,'REA_evidence_id':rea['evidence_id'],'imports':[{'DLL':d,'name':n}for d,n in sorted(imports)],'dynamic_lookup':'RtlGetVersion from the already loaded ntdll.dll; actual API behavior requires native execution.','driver_or_native_clock_behavior_qualified':False}
(W/'client-verification.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({k:r[k]for k in ['passed','binary_sha256','bytes','CRT_dependency','REA_Ghidra_import_inventory_matches_PE']}))
