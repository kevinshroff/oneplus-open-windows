"""Decode only actual standalone callback markers and bounded counter reads."""
import re

def decode_trace(text):
 lines=text.splitlines();markers=['G66_D0EXIT_STATE','G66_RELEASE_STATE','G66_PREPARE_STATE','G66_PREPARE_SUCCESS','G66_D0ENTRY_STATE']
 starts=[(i,l.strip())for i,l in enumerate(lines)if l.strip()in markers]
 assert [n for _,n in starts]==markers,'Exactly one ordered release/reacquire sequence required'
 expected=[[1,0,1,1,0,1],[1,1,1,1,0,0],[1,0,0,0,0,1],None,[1,0,1,0,1,1]]
 result=[]
 for k,(index,name)in enumerate(starts):
  end=starts[k+1][0]if k+1<len(starts)else len(lines);part='\n'.join(lines[index+1:end])
  status=None
  if name!='G66_PREPARE_STATE':
   m=re.search(r'(?m)^x0=([0-9a-fA-F`]+)\s*$',part);assert m and int(m[1].replace('`',''),16)==0,'Callback success return must be observed';status=0
  counters=None;context=None
  if expected[k]is not None:
   reg='x20'if name=='G66_PREPARE_STATE'else'x19';m=re.search(r'(?m)^'+reg+r'=([0-9a-fA-F`]+)\s*$',part);assert m
   context=int(m[1].replace('`',''),16);values=[]
   for line in part.splitlines():
    m=re.match(r'^\s*([0-9a-fA-F`]+)\s+((?:[0-9a-fA-F]{8}(?:\s+|$)){1,4})',line)
    if not m:continue
    address=int(m[1].replace('`',''),16);assert address==context+0x60+len(values)*4,'Counter address continuity'
    values.extend(int(x,16)for x in m[2].split())
   assert values==expected[k],'Actual native counters disagree with lifecycle transition';counters=values
  result.append({'event':name,'success_return':status,'context_address':hex(context)if context else None,'counter_words':counters})
 return result
