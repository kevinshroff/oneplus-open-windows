"""Reclaim only exact reconstructible local FAT postimages, never phone bytes."""
from pathlib import Path
import base64,hashlib,json
W=Path(__file__).resolve().parent;P=W/'private';sha=lambda b:hashlib.sha256(b).hexdigest();rows=[]
for tag,fresh in [('G70m','fresh-FAT.json'),('G70r','fresh-maintenance-FAT.json')]:
 src=Path(json.loads((W/fresh).read_text())['file']);x=src.read_bytes();plan=json.loads((P/(tag+'-FAT-onetime.json')).read_text());undo=json.loads((P/(tag+'-FAT-onetime-inverse.json')).read_text());assert sha(x)==plan['before_sha256']==undo['after_sha256'];buf=bytearray(x)
 for c in plan['changes']:
  off=c['offset'];old,new=base64.b64decode(c['before']),base64.b64decode(c['after']);assert len(old)==len(new)==4096 and buf[off:off+4096]==old;buf[off:off+4096]=new
 assert sha(buf)==plan['after_sha256']==undo['before_sha256'];post=P/('userdata-'+tag+'-onetime.img');assert post.stat().st_size==len(buf)and sha(post.read_bytes())==sha(buf)
 for c in undo['changes']:
  off=c['offset'];old,new=base64.b64decode(c['before']),base64.b64decode(c['after']);assert buf[off:off+4096]==old;buf[off:off+4096]=new
 assert bytes(buf)==x;row={'derived_local_postimage':str(post),'bytes_reclaimed':post.stat().st_size,'retained_complete_preimage':str(src),'forward_plan':tag+'-FAT-onetime.json','inverse_plan':tag+'-FAT-onetime-inverse.json','both_directions_reconstructed_exactly':True};post.unlink();rows.append(row)
r={'phone_operations':0,'rows':rows,'bytes_reclaimed':sum(x['bytes_reclaimed']for x in rows)};(W/'derived-reclamation.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))
