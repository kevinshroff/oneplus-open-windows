"""Bounded replay of the REA-decoded model47 R2 getter, with one modeled READ.

This is an interpreter of retained decoded instructions, not execution on a
Hexagon CPU or a complete CPU emulator. Every non-immext instruction must be
in a single-instruction packet, checked against the exact firmware bytes.
"""
from pathlib import Path
import argparse,hashlib,json,random,re,struct
p=argparse.ArgumentParser();p.add_argument('--dossier',type=Path,required=True);p.add_argument('--firmware',type=Path,required=True);p.add_argument('--rows',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
sha=lambda b:hashlib.sha256(b).hexdigest();firmware=a.firmware.read_bytes();assert sha(firmware)=='96dec3f35f9bd2fff7edce48d280d0cefc16e1029f969df8b8a9a41f8c3b5507'
dossier=json.loads(a.dossier.read_text());d=dossier['normalized_result'];assert d['procedure']['address']=='0x600d6960'
assert not d['native_value_flow']['truncated']and d['native_value_flow']['known_omitted_inputs']==d['native_value_flow']['known_omitted_edges']==0
header=struct.unpack_from('<16sHHIIIIIHHHHHH',firmware);rows=[struct.unpack_from('<8I',firmware,header[5]+32*i)for i in range(header[10])]
code={};raw=bytearray()
for line in d['assembly']:
 address,text=line.split(': ',1);address=int(address,16);op,_,args=text.strip().rstrip(',').partition(' ');args=args.strip()
 r=next(r for r in rows if r[2]<=address and address+4<=r[2]+r[4]);at=r[1]+address-r[2];word=firmware[at:at+4];raw.extend(word)
 end=(int.from_bytes(word,'little')>>14)&3;assert end==(1 if op=='immext'else 3),(hex(address),op,end)
 code[address]=(op,args)
assert len(code)==149 and sha(raw)=='26bc8a34387c0b1cc3e84844fb5ee3afcc863b70ed2b90ea986fc51302cedd27'
def split(s):
 out=[];level=0;start=0
 for i,c in enumerate(s):
  if c=='(':level+=1
  elif c==')':level-=1
  elif c==','and level==0:out.append(s[start:i].strip());start=i+1
 out.append(s[start:].strip());return out
def signed(v,n):return v-(1<<n)if v&(1<<(n-1))else v
def execute(frame,chip=7,null=False,read_status=0):
 assert len(frame)==9
 regs={f'R{i}':0 for i in range(32)};regs.update(R0=chip,R1=0 if null else 0x71000000,FP=0x12345678,SP=0x72010000);pred={'P0':False};mem={};calls=[]
 output=0x71000000
 for i in range(32):mem[output+i]=0xa5
 mem[0x6038ba29+chip*0x24]=7
 def get(at,n):
  assert all(at+i in mem for i in range(n)),('uninitialized model read',hex(at),n)
  return sum(mem[at+i]<<(8*i)for i in range(n))
 def put(at,n,v):
  assert 0x7200ff00<=at and at+n<=0x72010010 or output<=at and at+n<=output+20,('unexpected modeled store',hex(at),n)
  for i in range(n):mem[at+i]=(v>>(8*i))&255
 def val(s):
  s=s.strip()
  if s.startswith('#'):return int(s.lstrip('#'),0)&0xffffffff
  if s in regs:return regs[s]
  if s.endswith('.L'):return val(s[:-2])&65535
  pair=re.fullmatch(r'R(\d+)R(\d+)',s)
  if pair:return (regs['R'+pair[1]]<<32)|regs['R'+pair[2]]
  if s.startswith('and('):
   x,y=split(s[4:-1]);return val(x)&val(y)
  raise AssertionError(('unsupported operand',s))
 def setr(s,v):
  pair=re.fullmatch(r'R(\d+)R(\d+)',s)
  if pair:regs['R'+pair[1]]=(v>>32)&0xffffffff;regs['R'+pair[2]]=v&0xffffffff
  else:assert s in regs;regs[s]=v&0xffffffff
 def ea(s):
  m=re.fullmatch(r'\((FP|SP|R\d+)(?:\+(##?-?0x[0-9a-f]+))?\)',s);assert m,s
  return (val(m[1])+(val(m[2])if m[2]else 0))&0xffffffff
 pc=0x600d6960;steps=0;finished=False
 while not finished:
  steps+=1;assert steps<=200
  op,rest=code[pc];args=split(rest)if rest else [];nextpc=pc+4
  if op=='immext':pass
  elif op=='allocframe':
   sp=regs['SP']-8;put(sp,4,regs['FP']);put(sp+4,4,regs['R31']);regs['FP']=sp;regs['SP']=sp-val(args[0])
  elif op=='dealloc_return':
   fp=regs['FP'];regs['FP']=get(fp,4);regs['R31']=get(fp+4,4);regs['SP']=fp+8;finished=True
  elif op=='assign':setr(args[0],val(args[1]))
  elif op=='combine':setr(args[0],(val(args[1])<<32)|val(args[2]))
  elif op.startswith('mem'):
   width={'memb':1,'memub':1,'memh':2,'memuh':2,'memw':4,'memd':8}[op]
   if args[0].startswith('('):put(ea(args[0]),width,val(args[1]))
   else:
    v=get(ea(args[1]),width)
    if op in ['memb','memh']:v=signed(v,width*8)
    setr(args[0],v)
  elif op in ['cmp.eq','cmp.gt']:
   x,y=val(args[1]),val(args[2]);pred[args[0]]=x==y if op=='cmp.eq'else signed(x,32)>signed(y,32)
  elif op=='not':pred[args[0]]=not pred[args[1]]
  elif op=='jump':nextpc=int(args[0],16)
  elif op=='jump.if(P0)':
   if pred['P0']:nextpc=int(args[0],16)
  elif op=='call':
   assert int(args[0],16)==0x6009e110
   assert [regs['R'+str(i)]for i in range(4)]==[0,7,0x2606,9]
   buffer=regs['R4'];calls.append({'bus':0,'SID':7,'address':'0x2606','bytes':9})
   if read_status==0:
    for i,v in enumerate(frame):put(buffer+i,1,v)
   for i in range(6):regs['R'+str(i)]=0xc0de0000+i
   regs['R0']=read_status&0xffffffff
  elif op in ['add','+mpyi','and','or','lsr','asl','lsr|=','asl|=']:
   x,y=val(args[1]),val(args[2]);v={'add':lambda:x+y,'+mpyi':lambda:x*y,'and':lambda:x&y,'or':lambda:x|y,'lsr':lambda:x>>y,'asl':lambda:x<<y,'lsr|=':lambda:val(args[0])|(x>>y),'asl|=':lambda:val(args[0])|(x<<y)}[op]();setr(args[0],v)
  else:raise AssertionError(('unsupported instruction',op,rest))
  pc=nextpc
 assert bytes(mem[output+i]for i in range(20,32))==b'\xa5'*12
 assert regs['SP']==0x72010000 and regs['FP']==0x12345678
 return regs['R0']&65535,bytes(mem[output+i]for i in range(20)),calls
def projection(x):
 return bytes([x[0]&7,x[4]&1,x[4]>>7,(x[0]>>4)&1,(x[0]>>5)&1,(x[2]>>1)&1,(x[2]>>2)&1,(x[2]>>3)&1,(x[2]>>5)&1,x[5],x[8],(x[1]>>3)&1,(x[1]>>2)&1,(x[1]>>1)&1,x[1]&1,(x[1]>>4)&1,(x[4]>>1)&1,(x[1]>>5)&1,x[0]>>7,((x[2]&1)<<7)|((x[3]&2)<<5)|(x[3]&0x20)|((x[3]>>3)&0x10)|(x[3]&8)|(x[4]&4)|((x[2]&0x10)>>3)|(x[2]>>7)])
cases=[bytes(9),b'\xff'*9]
for bit in range(72):cases.append((1<<bit).to_bytes(9,'little'))
for index in range(9):
 for value in range(256):
  x=bytearray(9);x[index]=value;cases.append(bytes(x))
rng=random.Random(175)
for _ in range(256):cases.append(bytes(rng.randrange(256)for _ in range(9)))
for x in cases:
 status,out,calls=execute(x);assert status==0 and out==projection(x)and len(calls)==1
errors=[]
for kw,status,reads in [({'chip':11},0x202,0),({'chip':255},0x202,0),({'null':True},0x202,0),({'read_status':0x123},0x123,1)]:
 result,out,calls=execute(bytes(9),**kw);assert result==status and out==b'\xa5'*20 and len(calls)==reads;errors.append({'input':kw,'status':result,'modeled_READs':len(calls)})
native=[]
for phase in json.loads(a.rows.read_text()):
 traces=phase['traces'];head=next(t for t in traces if t['address']=='SID7:0x2606');tail=next(t for t in traces if t['address']=='SID7:0x260e');x=bytes.fromhex(head['value_hex']+tail['value_hex'])[:9]
 status,out,calls=execute(x);assert status==0 and out==projection(x);native.append({'phase':phase['phase'],'input_2606_through_260e_hex':x.hex(),'decoded_20_bytes_hex':out.hex(),'state':out[0],'packed_field19':out[19],'field18':out[18]})
unused=[]
for index in range(9):
 if all(projection(bytes([0]*index+[v]+[0]*(8-index)))==projection(bytes(9))for v in range(256)):unused.append(hex(0x2606+index))
result={'campaign':'G175','method':'Bounded replay of REA-decoded Hexagon instructions; explicit READ boundary. Not native CPU execution or a complete architecture emulator.','evidence_id':dossier['evidence_id'],'dossier_sha256':sha(a.dossier.read_bytes()),'original_function_sha256':sha(raw),'instruction_count':len(code),'non_immext_packets_individually_terminated':True,'successful_projection_cases':len(cases),'failure_cases':errors,'native_frozen_inputs':native,'input_bytes_unused_by_this_getter':unused,'unsigned_shift_check':'Original memub+lsr at600d6b48..54 produces field18=1 for inputbit7, despite misleading signed-char pseudocode.','limits':['The READ callback and SID table byte are modeled, not live execution.','Static model47 table/initializer are native-consistent; actual live callback pointer is not captured.','Packed-field meanings remain unknown; nonzero does not automatically mean a fault.','No new native READ,configuration,enable,reset,PAS or partition action.']}
a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
