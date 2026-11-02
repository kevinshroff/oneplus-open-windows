"""Decode saved native wire buffers with the source-tested portable C decoder."""
import argparse,ctypes,hashlib,json,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--journal',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True);W=Path(__file__).resolve().parent
lib=a.output/'report.dylib';subprocess.run(['clang','-std=c11','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',str(W/'g52_report.c'),'-o',str(lib.resolve())],check=True,capture_output=True,text=True)
fields='Kind Error Flags Count PointType HeaderChecked HeaderValid BodyChecked BodyValid MeaningfulBytes TailBytes ContactMask WithinProvisionalAxes'.split()
class Contact(ctypes.Structure):_fields_=[(n,ctypes.c_uint32)for n in ['Id','X','Y','Major','Minor','Type']]
class Frame(ctypes.Structure):_fields_=[(n,ctypes.c_uint32)for n in fields]+[('Contacts',Contact*10)]
f=ctypes.CDLL(str(lib.resolve())).G52DecodeReport;f.argtypes=[ctypes.POINTER(ctypes.c_uint8),ctypes.c_uint32,ctypes.POINTER(Frame)];f.restype=None
j=json.loads(a.journal.read_text());t=j['trial']['touch'];out={}
for name in ['report','post_report']:
 r=t[name]
 if not r['transport_ok']:out[name]={'transport_ok':False};continue
 n=r['rx_done']-8;raw=bytes(r['wire_RX'][8:8+n]);buf=(ctypes.c_uint8*len(raw)).from_buffer_copy(raw);v=Frame();f(buf,n,ctypes.byref(v));d={k:getattr(v,k)for k in fields};d.update(raw_hex=raw.hex(),contacts=[{k:getattr(v.Contacts[i],k)for k,_ in Contact._fields_}for i in range(v.Count)]if v.Kind==3 else [])
 (a.output/(name+'.bin')).write_bytes(raw);out[name]=d
out.update(trial_sha256=hashlib.sha256(json.dumps(j['trial'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),native_job=j['jobs']['event-ack-trial']['id'],journal_sha256=hashlib.sha256(a.journal.read_bytes()).hexdigest(),decoder_sha256=hashlib.sha256((W/'g52_report.c').read_bytes()).hexdigest(),physical_axis_mapping_qualified=False,live_HID_injection=False)
(a.output/'decoded.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out))
