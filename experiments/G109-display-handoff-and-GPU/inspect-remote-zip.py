"""Inspect an official public ZIP with bounded, identity-checked HTTP ranges.

Only explicitly selected members are extracted. No installer is executed.
The archive itself is not fully downloaded or assigned an unobserved SHA256.
"""
import argparse,hashlib,io,json,re,urllib.request,zipfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--url',required=True);p.add_argument('--output',type=Path,required=True)
p.add_argument('--member',action='append',default=[])
a=p.parse_args();assert not a.output.exists();a.output.mkdir(parents=True)
with urllib.request.urlopen(urllib.request.Request(a.url,method='HEAD'),timeout=30) as r:
 size=int(r.headers['Content-Length']);etag=r.headers.get('ETag');modified=r.headers.get('Last-Modified')
assert 0<size<2**32
class Remote(io.RawIOBase):
 def __init__(self):self.position=0;self.bytes=0;self.requests=[]
 def seekable(self):return True
 def readable(self):return True
 def tell(self):return self.position
 def seek(self,offset,whence=0):
  pos=offset if whence==0 else self.position+offset if whence==1 else size+offset
  if pos<0 or pos>size:raise ValueError('seek outside fixed archive')
  self.position=pos;return pos
 def read(self,n=-1):
  n=size-self.position if n<0 else min(n,size-self.position)
  if not n:return b''
  if n>32<<20 or self.bytes+n>64<<20:raise ValueError('range inspection byte budget')
  begin=self.position;end=begin+n-1;headers={'Range':f'bytes={begin}-{end}','Accept-Encoding':'identity'}
  if etag:headers['If-Match']=etag
  with urllib.request.urlopen(urllib.request.Request(a.url,headers=headers),timeout=45) as r:
   assert r.status==206 and r.headers.get('Content-Range')==f'bytes {begin}-{end}/{size}'
   if etag and r.headers.get('ETag'):assert r.headers['ETag']==etag
   value=r.read(n+1);assert len(value)==n
  self.position+=n;self.bytes+=n;self.requests.append({'begin':begin,'bytes':n});return value
stream=Remote();members=[]
with zipfile.ZipFile(stream) as archive:
 inventory=[{'name':z.filename,'bytes':z.file_size,'compressed_bytes':z.compress_size,'CRC32':f'{z.CRC:08x}'}for z in archive.infolist()]
 for name in a.member:
  z=archive.getinfo(name);assert not z.is_dir() and z.file_size<=64<<20 and z.compress_size<=32<<20
  value=archive.read(z);assert len(value)==z.file_size
  safe=Path(name).name;assert safe not in ('.','..') and not (a.output/safe).exists()
  (a.output/safe).write_bytes(value);members.append({'name':name,'file':safe,'bytes':len(value),'sha256':hashlib.sha256(value).hexdigest(),'ZIP_CRC_verified':True})
report={'canonical_url':a.url,'archive_bytes':size,'ETag':etag,'Last_Modified':modified,'whole_archive_downloaded':False,
        'whole_archive_sha256_observed':False,'HTTP_bytes_read':stream.bytes,'requests':stream.requests,'inventory':inventory,'members':members}
(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'archive_bytes':size,'HTTP_bytes_read':stream.bytes,'members':members,'inventory':inventory if not a.member else []}))
