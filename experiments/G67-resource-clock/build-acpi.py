"""Append one inert QUP clock component to the exact original AML body."""
from pathlib import Path
import argparse,hashlib,json,re,struct,subprocess
p=argparse.ArgumentParser();p.add_argument('--original',type=Path,required=True);p.add_argument('--source-map',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
sha=lambda b:hashlib.sha256(b).hexdigest();b=a.original.read_bytes();assert len(b)==576 and sha(b)=='c8ef19940f424fce18a6e56580493629accb7c59a9ae495cc42c9445029f3e01'and b[:4]==b'DSDT'and sum(b)%256==0
s=json.loads(a.source_map.read_text());assert s['fixed_trial_pages']==[0x118000,0x123000,0x152000]and s['page_bytes']==4096
asl=r'''DefinitionBlock ("", "SSDT", 2, "OPEN  ", "QCLKG67 ", 1)
{
 Name (G67C, 0x47363743)
 Scope (\_SB) {
  Device (QCLK) {
   Name (_HID, "OPEN0067")
   Name (_UID, Zero)
   Name (_CCA, Zero)
   Name (_DDN, "OnePlus Open QUP1 GCC clock component")
   Method (_STA, 0, NotSerialized) { Return (0x0F) }
   Name (RBUF, ResourceTemplate () {
    Memory32Fixed (ReadWrite, 0x00118000, 0x00001000)
    Memory32Fixed (ReadWrite, 0x00123000, 0x00001000)
    Memory32Fixed (ReadWrite, 0x00152000, 0x00001000)
   })
   Method (_CRS, 0, NotSerialized) { Return (RBUF) }
  }
 }
}
'''
dsl=a.output/'clock.dsl';dsl.write_text(asl);q=subprocess.run(['iasl','-tc',str(dsl)],capture_output=True,text=True);(a.output/'compiler.txt').write_text(q.stdout+q.stderr);assert not q.returncode,(q.stdout,q.stderr)
ssdt=dsl.with_suffix('.aml').read_bytes();assert sum(ssdt)%256==0 and ssdt[:4]==b'SSDT'
table=bytearray(b+ssdt[36:]);struct.pack_into('<I',table,4,len(table));struct.pack_into('<I',table,24,struct.unpack_from('<I',b,24)[0]+67);table[9]=0;table[9]=(-sum(table))&255;assert table[36:576]==b[36:]and sum(table)%256==0
crs=b''.join(bytes.fromhex('86090001')+struct.pack('<II',page,4096)for page in s['fixed_trial_pages'])+bytes([0x79,0]);assert len(crs)==38 and ssdt.count(crs)==1
(a.output/'acpitabl.dat').write_bytes(table);(a.output/'expected-crs.bin').write_bytes(crs)
header='/* Generated exact G67 DSDT. */\nstatic const unsigned char G67ExpectedDsdt[]={\n'+''.join(' '+','.join('0x%02x'%v for v in table[i:i+16])+',\n'for i in range(0,len(table),16))+'};\n';(a.output/'g67_binding.h').write_text(header)
commands='evaluate \\G67C; evaluate \\_SB.QCLK._HID; evaluate \\_SB.QCLK._STA; evaluate \\_SB.QCLK._CCA; evaluate \\_SB.QCLK._CRS';q=subprocess.run(['acpiexec','-b',commands,str(a.output/'acpitabl.dat')],capture_output=True,text=True);evaluation=q.stdout+q.stderr;(a.output/'evaluation.txt').write_text(evaluation);assert not q.returncode and 'ACPI Error'not in evaluation
for name,want in [('G67C',0x47363743),('_SB.QCLK._STA',15),('_SB.QCLK._CCA',0)]:
 section=evaluation.split('Evaluating \\'+name+'\n',1)[1].split('Evaluating ',1)[0];values=re.findall(r'\[Integer\] = ([0-9A-Fa-f]+)',section);assert len(values)==1 and int(values[0],16)==want
assert '[String] Length 08 = "OPEN0067"'in evaluation
section=evaluation.split('Evaluating \\_SB.QCLK._CRS\n',1)[1];parts=[]
for line in section.splitlines():
 m=re.match(r'\s*([0-9A-Fa-f]{4}): (.*?)\s*//',line)
 if m:assert int(m[1],16)==len(parts);parts.extend(bytes.fromhex(m[2]))
assert bytes(parts)==crs and 'No outstanding allocations'in evaluation
out={'phase':'clock_component_ACPI_compiled_and_evaluated_not_deployed','source_DSDT_sha256':sha(b),'trial_DSDT_sha256':sha(table),'trial_bytes':len(table),'all_original_AML_body_bytes_preserved':True,'changed_original_header_offsets':[i for i in range(len(b))if table[i]!=b[i]],'added_hardware_id':'OPEN0067','added_memory_pages':s['fixed_trial_pages'],'page_bytes':4096,'expected_CRS_sha256':sha(crs),'expected_CRS_bytes':38,'evaluated_marker_HID_STA_CCA_and_CRS_match':True,'binding_header_sha256':sha(header.encode()),'source_map_sha256':sha(a.source_map.read_bytes()),'native_operations':0}
(a.output/'build.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out))
