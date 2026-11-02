"""Conservative source write-target audit: all module sites, including fallback paths.
Finite symbolic/array/helper argument domains are explicitly checked; unknown sinks/expressions fail.
This establishes source target exclusion, not hardware/provider implementation behavior.
"""
from pathlib import Path
import re,json,hashlib
r=Path(__file__).resolve().parent
pkg=r/'firmware/G290Pkg'
def clean(s):
 return re.sub(r'//[^\n]*|/\*.*?\*/',lambda m:'\n'*m.group().count('\n'),s,flags=re.S)
def array(s,name):
 m=re.search(r'\b'+name+r'\s*\[[^]]*\]\s*=\s*\{([^}]+)\}',s);assert m,name
 def number(e):return sum(int(re.sub(r'[uUlL]+$','',v.strip()),0) for v in e.split('+'))
 return [number(x) for x in m[1].split(',')]
def calls(s,name):
 for m in re.finditer(r'\b'+name+r'\s*\(',s):
  a=m.end();level=1;i=a
  while level:
   level+=(s[i]=='(')-(s[i]==')');i+=1
  body=s[a:i-1];level=0;first=''
  for c in body:
   if c==',' and level==0:break
   first+=c;level+=(c=='(')-(c==')')
  yield m.start(),first.strip(),body

def audit(s):
 t=clean(s);pa=array(t,'mPa');order=array(t,'ClockOrder');leaf=array(t,'mLeaf');off=array(t,'off')
 assert pa==[0x171004,0x3d99108,0x3d9953c,0x171010,0x171018,0x3d9911c,0x3d97000]
 assert order==[6,3,4,5] and 2 not in order
 assert leaf==[0x171154,0x171010,0x3d9911c,0x3d99148]
 assert off==[0x3d9913c,0x3d99144,0x3d990bc]
 rcg=[int(x,16) for x in re.findall(r'G721RcgProgram\((0x[0-9a-fA-F]+)',t)]
 branch=[int(x,16) for x in re.findall(r'G721BranchOn\((0x[0-9a-fA-F]+)',t)]
 assert rcg==[0x3d993ec,0x3d99474] and branch==[0x3d99148]
 symbols={m[1]:int(m[2],16) for m in re.finditer(r'#define\s+(\w+)\s+(0x[0-9a-fA-F]+)[uU]?',t)}
 known={'mLeaf[i]':leaf,'off[i]':off,'mPa[0]':[pa[0]],'mPa[1]':[pa[1]],'mPa[i]':[pa[x] for x in order],'cmdPa':rcg,'cmdPa+4':[x+4 for x in rcg],'pa':branch}
 sinks=set(re.findall(r'\b((?:Mmio|Io)(?:Write|And|Or|AndThenOr)\w*|WRITE_REGISTER_\w+)\s*\(',t));assert sinks=={'MmioWrite32'},sinks
 sites=[]
 for pos,expr,body in calls(t,'MmioWrite32'):
  key=re.sub(r'\(\s*UINTN\s*\)','',expr);key=re.sub(r'\s+','',key)
  while key.startswith('(') and key.endswith(')'):key=key[1:-1]
  if re.fullmatch(r'0x[0-9a-fA-F]+[uU]?',key):values=[int(key.rstrip('uU'),16)]
  elif key in symbols:values=[symbols[key]]
  else:assert key in known,('unresolved write target',expr);values=known[key]
  forbidden=[v for v in values if v in [0x3d9905c,0x3d99060,0x3d9953c] or 0xc300000<=v<0xc301000 or 0x408000<=v<0x409000]
  assert not forbidden,('forbidden GX/HWCTRL/QMP write',expr,[hex(x) for x in forbidden])
  sites.append({'line':t[:pos].count('\n')+1,'expression':expr,'possible_addresses':[hex(v) for v in values]})
 assert len(sites)==35,len(sites)
 # Provider requests are finite CX/MXA/MXC names only; no GX lookup/probe/message sender.
 assert re.findall(r'"(/[^"\n]+)"',t)==['/vcs/vdd_cx','/vcs/vdd_mxa','/vcs/vdd_cx','/vcs/vdd_mxa','/vcs/vdd_mxc']
 assert not any(x in t for x in ['voltage_class','gfxNames','GX_GDSCR','0x03d7c340','0x0c300','0x0040800c'])
 methods=re.findall(r'->(\w+)\s*\(',t)
 allowed={'LocateProtocol','GetClockID','EnableClock','IsClockEnabled','RaiseTPL','RestoreTPL','SetClockFreqHz','GetClockPowerDomainID','EnableClockPowerDomain','Query','Available','Create','Request','Stall','SetMemorySpaceAttributes','GetMemorySpaceDescriptor','AddMemorySpace','InstallAcpiTable'}
 assert set(methods)<=allowed,set(methods)-allowed
 protocol=[{'line':t[:m.start()].count('\n')+1,'method':m[1]} for m in re.finditer(r'->(EnableClock|SetClockFreqHz|EnableClockPowerDomain|Request|Create)\s*\(',t)]
 return sites,protocol
s=(pkg/'G290GpuPower.c').read_text();sites,protocol=audit(s)
# Regression: original r1 macro-symbol GX write MUST be rejected, not missed by literal grep.
try:audit((r.parent/'firmware/G290Pkg/G290GpuPower.c').read_text())
except AssertionError as e:
 assert 'forbidden GX/HWCTRL/QMP write' in str(e),str(e)
 regression=str(e)
else:raise AssertionError('r1 hidden GX_GDSCR write incorrectly passed')
# Regression: array-based HWCTRL access MUST reject even without a literal sink address.
bad=s.replace('ClockOrder[4]={6,3,4,5}','ClockOrder[4]={2,3,4,5}')
try:audit(bad)
except AssertionError:pass
else:raise AssertionError('HWCTRL array mutation incorrectly passed')
# Other linked source/headers must contain no additional MMIO/control sink.
other=[]
for p in sorted(pkg.iterdir()):
 if p.suffix in ['.c','.h'] and p.name!='G290GpuPower.c':
  text=clean(p.read_text());found=re.findall(r'\b((?:Mmio|Io)(?:Write|And|Or|AndThenOr)\w*|WRITE_REGISTER_\w+)\s*\(',text)
  assert not found,(p,found);other.append(p.name)
report={'scope':'all source write sites incl fallback; finite symbol/array/helper domains; external protocol internals not re-proven','source_sha256':hashlib.sha256(s.encode()).hexdigest(),'MMIO_write_sites':sites,'protocol_mutation_calls':protocol,'other_module_sources_headers_without_control_sinks':other,'GX_GDSCR_CFG_writes':0,'HWCTRL_writes':0,'QMP_message_writes':0,'r1_symbol_hidden_GX_write_regression_rejected':regression,'array_HWCTRL_mutation_rejected':True,'NPA_resources':['/vcs/vdd_cx','/vcs/vdd_mxa','/vcs/vdd_mxc'],'clock_protocol_resources':['gcc_gpu_gpll0_clk_src','G530-bound hub id0x1014a','gpu_cc_cx_gdsc'],'coldGXoff_claim':False}
(r/'evidence').mkdir(exist_ok=True);(r/'evidence/WRITE-TARGET-AUDIT.json').write_text(json.dumps(report,indent=2)+'\n');print('PASS: all',len(sites),'MMIO sites resolved; forbidden targets absent; hidden-symbol/array regressions reject')
