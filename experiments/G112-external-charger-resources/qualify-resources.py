"""Derive the external charger resource candidates from retained pinned source."""
from pathlib import Path
import json,sys,re,hashlib
w=Path(__file__).resolve().parent;root=w.parent
sys.path.insert(0,str(root/'maintenance-G18/fdt-analysis'));from fdtree import Fdt
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
gcc=root/'maintenance-G18/bus-G24/private/gcc-kalama.c';text=gcc.read_text();pins=root/'maintenance-G18/gpio-G20/private/pinctrl-kalama.c';pt=pins.read_text()
def block(name):
 m=re.search(r'static struct \w+ '+re.escape(name)+r' = \{(.*?)\n\};',text,re.S);assert m,name;return m[1]
def val(s,key):
 m=re.search(r'\.'+key+r'\s*=\s*(0x[0-9a-fA-F]+)',s);assert m,key;return int(m[1],16)
s5=block('gcc_qupv3_i2c_s5_clk');rcg=block('gcc_qupv3_i2c_s5_clk_src');core=block('gcc_qupv3_i2c_core_clk');ahb=block('gcc_qupv3_i2c_s_ahb_clk')
assert val(s5,'halt_reg')==0x17090 and val(s5,'enable_reg')==0x52008 and re.search(r'enable_mask\s*=\s*BIT\(15\)',s5)
assert val(rcg,'cmd_rcgr')==0x17094
assert val(core,'halt_reg')==0x23144 and val(core,'enable_reg')==0x52008 and re.search(r'enable_mask\s*=\s*BIT\(8\)',core)
assert val(ahb,'halt_reg')==0x23140 and val(ahb,'enable_reg')==0x52008 and re.search(r'enable_mask\s*=\s*BIT\(7\)',ahb)
for pin in [6,7]:assert re.search(r'PINGROUP\('+str(pin)+r', i2chub0_se5_l'+str(pin-6)+r',',pt)
rows=[]
for name in ['kalama-candidate-1-first.dtb','kalama-candidate-2-first.dtb']:
 p=root/'maintenance-G18/fdt-analysis/private'/name;f=Fdt.read(p);ph=f.phandles();bus='/soc/qcom,qupv3_i2c_geni_se@9c0000/i2c@994000';child=bus+'/sc8547-charger@6F';slave='/soc/qcom,qupv3_2_geni_se@8c0000/i2c@880000/sc8547-charger-slave@6F'
 assert f.cells(bus,'reg')==[0x994000,0x4000]and 'qcom,i2c-hub'in f.nodes[bus]
 assert f.cells(child,'reg')==[0x6f,0]and f.strings(child,'compatible')==['oplus,sc8547a-ufcs']
 assert f.cells(slave,'reg')==[0x6f,0]and f.strings(slave,'compatible')==['sc,sc8547-slave']
 active=[]
 for h in f.cells(bus,'pinctrl-0'):
  base=ph[h];active.append({'pins':f.strings(base+'/mux','pins'),'function':f.strings(base+'/mux','function')})
 assert active==[{'pins':['gpio6'],'function':['i2chub0_se5_l0']},{'pins':['gpio7'],'function':['i2chub0_se5_l1']}]
 rows.append({'file':str(p),'sha256':sha(p),'main_bus':bus,'main_chip':child,'slave_chip':slave,'active_pins':active})
x={'passed':True,'scope':'source-derived candidates,not proof of populated/selected Android hardware','native_operations':0,'two_candidates_agree':True,'main_resource':{'base':'0x994000','wrapper':'0x9c0000','root':'0x117094','clock_enable':'0x117090','vote':'0x152008','SE_vote_mask':'0x8000','core_mask':'0x100','AHB_mask':'0x80','core_cbcr':'0x123144','AHB_cbcr':'0x123140','pins':[6,7],'mux':1},'source_sha256':{str(p):sha(p)for p in [gcc,pins]},'candidates':rows,'next':'Native readonly clock/pin/controller evidence; then qualify fixed read transport only if resources are usable.'}
(w/'private/resource-qualification.json').write_text(json.dumps(x,indent=2)+'\n');print(json.dumps({k:v for k,v in x.items()if k!='candidates'}))
