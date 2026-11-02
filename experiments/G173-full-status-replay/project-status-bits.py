"""Project frozen native status through the observed original getter bit basis."""
from pathlib import Path
import argparse,json
a=argparse.ArgumentParser();a.add_argument('--replay',type=Path,required=True);a.add_argument('--rows',type=Path,required=True);args=a.parse_args()
r=json.loads(args.replay.read_text());allrows=r['results'];base=bytes.fromhex(allrows[0]['full_output_hex']);assert base==bytes(40)
basis=[x for x in allrows if x['input_vector_hex']and x['input_vector_hex']!='00'*10];assert len(basis)==80
native=next(x for x in allrows if x['native_bytes_replayed']);regs={}
packet=json.loads(args.rows.read_text())['phases']['during-pulse']['traces']
for item in packet:
 at=int(item['address'].split(':')[1],16)
 for i,v in enumerate(bytes.fromhex(item['value_hex'])):regs[at+i]=v
raw=bytes(regs[0x2606+i]for i in range(10));out=bytearray(40);mapping=[]
for row in basis:
 vec=bytes.fromhex(row['input_vector_hex']);i=next(n for n,x in enumerate(vec)if x);bit=vec[i].bit_length()-1;data=bytes.fromhex(row['full_output_hex'])
 mapping.append({'address':hex(0x2606+i),'input_bit':bit,'output_bytes':{str(j):v for j,v in enumerate(data)if v}})
 if raw[i]&(1<<bit):
  for j,v in enumerate(data):out[j]|=v
assert out.hex()==native['full_output_hex']
ignored=sorted({m['address']for m in mapping if all(not x['output_bytes']for x in mapping if x['address']==m['address'])});assert ignored==['0x260c','0x260d']
result={'passed':True,'cases':r['cases'],'image_sha256':r['image_sha256'],'original_machine_code_executed':True,'native_operations':0,'native_capture_sha256':r['native_raw_sha256'],'raw_status_2606_to_260f':raw.hex(),'native_original_output_40bytes':out.hex(),'bit_basis_projection_matches_original_native_replay':True,'bytes_not_represented_in_this_older_getter':ignored,'native_260d_raw':hex(regs[0x260d]),'nonzero_output_offsets_without_semantic_labels':{str(i):v for i,v in enumerate(out)if i>=4 and v},'field_names_qualified':False,'diagnosed_charging_inhibit':False,'limits':['Original code validates offsets/masks; most field names remain unknown. Do not label every nonzero field a fault.','260C/260D are read but absent from this older status output; native260D=38h is not classified.','The replayed capture has enable bit1 and state7/DISABLED; this does not identify the inhibit.','No extra physical read, charger control, or PMIC configuration.'],'mapping':mapping}
print(json.dumps(result,indent=2))
