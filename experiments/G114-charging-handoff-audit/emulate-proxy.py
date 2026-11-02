"""Run the installed PIL proxy with modeled NPA/UEFI/config boundaries only."""
from pathlib import Path
import argparse,json,hashlib,struct,sys
import pefile
from unicorn import Uc,UC_ARCH_ARM64,UC_MODE_ARM,UC_HOOK_CODE
from unicorn.arm64_const import *
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--image',type=Path,required=True);p.add_argument('--boot-fdt',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();raw=a.image.read_bytes();assert hashlib.sha256(raw).hexdigest()=='45a4016c31bfe32bc6a7420ad63119ffa1bc1015cd168e4616e847ed077b0d13';image=pefile.PE(data=raw).get_memory_mapped_image()
from fdtree import Fdt
f=Fdt.read(a.boot_fdt);node='/soc/pil/pil_proxy_vote/pil_proxy_vote_1';assert f.cells(node,'subsys_id')==[1]and f.strings(node,'client_name')==['PIL_ADSP']and f.cells(node,'flag')==[3,3]
ARENA,END=0x30000000,0x10000000;rows=[];NOTFOUND=0x800000000000000e
regs=[UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5]
def run(entry,action=0,flags=(3,3),existing=True,ssr=False,delay=0,missing=False,regfail=False):
 u=Uc(UC_ARCH_ARM64,UC_MODE_ARM);u.mem_map(0,(len(image)+4095)&~4095);u.mem_write(0,image);u.mem_map(ARENA,0x10000);u.mem_map(END,0x1000);u.reg_write(UC_ARM64_REG_CPACR_EL1,3<<20);cfg=ARENA+0x1000;bs=ARENA+0x7000;proto=ARENA+0x8000;events=[];registry={};next_node=ARENA+0xb000;next_handle=ARENA+0xa000;tick=100;last_event=ARENA+0xd000
 def q(at,v):u.mem_write(at,struct.pack('<Q',v))
 def d(at,v):u.mem_write(at,struct.pack('<I',v))
 def readq(at):return struct.unpack('<Q',u.mem_read(at,8))[0]
 def string(at):
  b=bytearray()
  for i in range(256):
   c=u.mem_read(at+i,1)[0]
   if not c:return b.decode()
   b.append(c)
  raise AssertionError('string bounds')
 def text(at,s):u.mem_write(at,s.encode()+b'\0')
 def ret(v=0):u.reg_write(UC_ARM64_REG_X0,v);u.reg_write(UC_ARM64_REG_PC,u.reg_read(UC_ARM64_REG_LR))
 client=ARENA+0x6000;text(client,'PIL_ADSP');q(cfg+8,client);d(cfg,1);rails=f.strings(node,'rail_names');levels=f.cells(node,'rail_voltage_levels');d(cfg+0x10,len(rails));q(cfg+0x18,ARENA+0x6100);q(cfg+0x20,ARENA+0x6200)
 resource_names=[]
 for i,name in enumerate(rails):
  at=ARENA+0x6700+0x80*i;text(at,name);q(ARENA+0x6100+8*i,at);d(ARENA+0x6200+4*i,levels[i]);resource_names.append(at)
 icb=ARENA+0x6300;text(icb,f.strings(node,'icb_name')[0]);resource_names.append(icb);q(cfg+0x28,icb);d(cfg+0x30,1);q(cfg+0x38,ARENA+0x6400);q(cfg+0x40,ARENA+0x6500);u.mem_write(ARENA+0x6400,struct.pack('<2I',*f.cells(node,'icb_arb_master_slave')));u.mem_write(ARENA+0x6500,struct.pack('<I',4)+b'\0'*4+struct.pack('<4I',*f.cells(node,'icb_arb_request_data')));d(cfg+0x48,2);q(cfg+0x50,ARENA+0x6600);u.mem_write(ARENA+0x6600,struct.pack('<2I',*flags));d(cfg+0x58,0)
 q(0xc698,bs);d(0xc168,int(ssr));d(0xc294,0);d(0xc290,delay)
 for off,func in [(0x50,0xe000),(0x58,0xe004),(0x70,0xe008),(0x140,0xe00c)]:q(bs+off,ARENA+func)
 q(proto+0x10,ARENA+0xe010)
 if existing:
  for i,at in enumerate(resource_names):
   obj=next_node;next_node+=0x80;q(obj+16,client);q(obj+24,at);q(obj+32,next_handle);next_handle+=0x100;registry[string(at)]=obj
 def hook(cpu,pc,size,user):
  nonlocal next_node,next_handle,tick
  z=[u.reg_read(r)for r in regs]
  if pc==0x1b84:assert z[0]==1;events.append({'config_lookup':1});ret(cfg)
  elif pc==0x26a8:assert string(z[0])=='PIL_ADSP';ret(0 if missing else registry.get(string(z[1]),0))
  elif pc==0x79b8:
   events.append({'create':string(z[0]),'client':string(z[1]),'type':hex(z[2])});v=next_handle;next_handle+=0x100;ret(0 if regfail else v)
  elif pc==0x2f3c:assert z[0]==40;v=next_node;next_node+=0x80;ret(v)
  elif pc==0x2a34:assert z[0]==0xc1f0;registry[string(readq(z[1]+24))]=z[1];ret()
  elif pc==0x2c74:
   name=string(readq(z[0]+24));assert registry[name]==z[0];del registry[name];events.append({'remove_client':name});ret()
  elif pc==0x3064:ret()
  elif pc==0x7ad0:events.append({'scalar_request':hex(z[0]),'level':z[1]});ret()
  elif pc==0x7b48:events.append({'vector_request':hex(z[0]),'elements':z[1]});ret()
  elif pc==0x7bc8:events.append({'complete_request':hex(z[0])});ret()
  elif pc==0x7a68:events.append({'destroy_client':hex(z[0])});ret()
  elif pc==0x88b8:tick+=100;ret(tick)
  elif pc==0x2794:events.append({'duration_conversion_modeled':z[0]});ret(z[0])
  elif pc==0x439c:events.append({'log':string(z[1])});ret()
  elif pc==0x4498:raise AssertionError('unexpected firmware assertion')
  elif pc==0x4338:events.append({'config_get':string(z[0])});ret(NOTFOUND)
  elif pc==ARENA+0xe000:
   assert z[:4]==[0x80000200,8,0x14a0,cfg];q(z[4],last_event);events.append({'create_timer':hex(z[2]),'context_matches':True});ret()
  elif pc==ARENA+0xe004:assert z[:2]==[last_event,2];events.append({'relative_timer_100ns':z[2]});ret()
  elif pc==ARENA+0xe008:assert z[0]==last_event;events.append({'close_event':True});ret()
  elif pc==ARENA+0xe00c:
   assert z[0]==0xc108;q(z[2],proto if ssr else 0);events.append({'locate_SSR':ssr});ret(0 if ssr else NOTFOUND)
  elif pc==ARENA+0xe010:assert string(z[0])=='proxy_unvote'and z[1]==1;events.append({'SSR_callback_registered':True,'entry':hex(readq(z[2])),'context':readq(z[2]+8)==cfg});ret()
 u.hook_add(UC_HOOK_CODE,hook)
 def invoke(start,args):
  u.reg_write(UC_ARM64_REG_SP,ARENA+0xf000);u.reg_write(UC_ARM64_REG_LR,END)
  for r,v in zip(regs,args):u.reg_write(r,v)
  u.emu_start(start,END,count=200000);assert u.reg_read(UC_ARM64_REG_PC)==END;return u.reg_read(UC_ARM64_REG_X0)
 if entry=='vote':status=invoke(0x2308,[cfg,action]);assert status==(0x8000000000000003 if regfail and flags[action]&1 else 0)
 elif entry=='unvote':status=invoke(0x2508,[cfg,action]);assert status==0
 elif entry=='dispatch':
  status=invoke(0x154c,[action,1]);assert status==0
 elif entry=='sequence':
  status=invoke(0x154c,[1,1]);assert status==0;status=invoke(0x154c,[2,1]);assert status==0
  if ssr:status=invoke(0x14f4,[4,cfg])
  else:status=invoke(0x14a0,[last_event,cfg])
 elif entry=='timer_callback':status=invoke(0x14a0,[last_event,cfg])
 elif entry=='SSR_callback':status=invoke(0x14f4,[action,cfg]);assert status==0
 else:raise AssertionError('entry')
 scalar=[e for e in events if 'scalar_request'in e];complete=[e for e in events if 'complete_request'in e];timers=[e for e in events if 'relative_timer_100ns'in e]
 if entry=='vote':assert len(scalar)==(0 if regfail or not flags[action]&1 else 2)
 if entry in ['unvote','timer_callback']or(entry=='SSR_callback'and action==4):assert len(complete)==(3 if flags[0 if entry!='unvote'else action]&2 else 0)
 if entry=='dispatch'and action==2:assert timers==([]if flags[0]&16 else[{'relative_timer_100ns':(delay or 6000000)*10000}])
 if entry=='sequence':assert len(complete)==3 and len(scalar)==2 and len(timers)==(0 if ssr else 1)
 if entry=='SSR_callback'and action!=4:assert not complete
 rows.append({'entry':entry,'action':action,'flags':list(flags),'preexisting_clients':existing,'SSR_available':ssr,'delay_override_ms':delay,'create_failure':regfail,'status':hex(status),'events':events,'native_operations':0})
for flags in [(0,0),(1,1),(2,2),(3,3)]:run('vote',flags=flags);run('unvote',flags=flags)
run('vote',existing=False);run('vote',existing=False,regfail=True)
run('timer_callback');run('SSR_callback',4);run('SSR_callback',3)
for action in [0,1,8,16]:run('dispatch',action=action)
run('dispatch',action=1,ssr=True);run('dispatch',action=2);run('dispatch',action=2,delay=1500)
run('dispatch',action=2,flags=(19,3));run('sequence',ssr=True);run('sequence',existing=False)
x={'passed':True,'cases':len(rows),'image_sha256':hashlib.sha256(raw).hexdigest(),'native_boot_fdt_sha256':hashlib.sha256(a.boot_fdt.read_bytes()).hexdigest(),'native_config_node':node,'original_vote_unvote_dispatch_and_callbacks_executed':True,'native_operations':0,'models':['configuration lookup using actual saved boot values','NPA client lookup/create/request/complete/destroy and list allocation','UEFI locate/register/timer/close services','logging and performance tick conversion'],'limits':['The installed proxy manages rail/ICB request lifetimes; these tested paths do not issue a DSP-stop or charger command.','Configured membership and a successful controlled replay do not establish native firmware dispatch or current DSP state.','Timer6000000ms is a fallback under modeled absent SSR/config; no claim that it ran on the phone.','No change to unvote policy,rails,clocks,firmware or Windows is justified by this model alone.'],'results':rows};a.output.write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({k:v for k,v in x.items()if k not in ['models','limits','results']}))
