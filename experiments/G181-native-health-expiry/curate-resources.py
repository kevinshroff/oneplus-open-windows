"""Separate observed WinPE resource metadata from proposed ownership work."""
from pathlib import Path
import hashlib,json,re
w=Path(__file__).resolve().parent;p=w/'private';f=p/'resource-inventory.txt';text=f.read_text();assert '[G17 omitted'not in text;nodes=[];memory=[]
for b in text.split('Instance ID:')[1:]:
 lines=b.splitlines();record={'instance':lines[0].strip()}
 for field in ['Device Description','Class Name','Status','Driver Name','Service']:
  m=re.search(r'^'+re.escape(field)+r':\s*(.*)$',b,re.M)
  if m:record[field]=m.group(1).strip()
 ranges=[{'start':int(a,16),'end':int(z,16)}for a,z in re.findall(r'0x([0-9A-Fa-f]+)\s*-\s*0x([0-9A-Fa-f]+)',b)]
 if ranges:record['memory_ranges']=ranges;memory.append(record)
 nodes.append(record)
acpi=[n for n in nodes if n['instance'].startswith('ACPI\\')]
assert {n['instance']for n in acpi}=={r'ACPI\QCOM24A5\0',r'ACPI\SSDE\2&daba3ff&0'}
assert len(memory)==1 and memory[0]['memory_ranges']==[{'start':0x1d84000,'end':0x1d9ffff}]
report={'node_count':len(nodes),'acpi_devices':acpi,'devices_with_reported_memory_resources':memory,'native_inventory_sha256':hashlib.sha256(f.read_bytes()).hexdigest(),'observed':'No battery,gauge-controller,SPMI or GLINK PnP node appears in this connected WinPE inventory. The sole reported device-memory range belongs to UFS.','inference':'A new firmware-described resource owner is needed for these currently laboratory-mapped controllers,or an independently qualified existing platform interface must be found.','limits':['PnP inventory does not account for firmware ownership or direct mappings held by non-PnP drivers.','This WinPE inventory does not establish the normal-Windows driver/resource state.','No resource,firmware,driver or power setting was changed by this enumeration.'],'primary_contracts':['https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax','https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/raw-and-translated-resources','https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/finding-and-mapping-hardware-resources']}
(p/'resource-analysis.json').write_text(json.dumps(report,indent=2)+'\n');print({'nodes':len(nodes),'ACPI_nodes':len(acpi),'memory_resource_devices':len(memory),'resource_change':False})
