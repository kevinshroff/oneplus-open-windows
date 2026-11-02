"""Bind the QUP1 clock subranges to both stock candidates and pinned source."""
from pathlib import Path
import argparse,hashlib,json,re,sys
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--clock-ids',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists()
B=a.inputs;sys.path.insert(0,str(B/'fdt-analysis'));from fdtree import Fdt
sha=lambda b:hashlib.sha256(b).hexdigest()
gcc=(B/'bus-G24/private/gcc-kalama.c').read_bytes();assert sha(gcc)=='bd4305c0cc23883666ecb2079e9f34a992dad39a788157c7ca891d896be1f699'
ids=a.clock_ids.read_bytes();assert sha(ids)=='8ed4e7420cf1defc22a69097ca24d2d4662fae375035b007a8355934bd98b826'
text=gcc.decode();rows=[]
for name,macro,number,bit,halt in [('gcc_qupv3_wrap_1_m_ahb_clk','GCC_QUPV3_WRAP_1_M_AHB_CLK',127,20,0x2327c),('gcc_qupv3_wrap_1_s_ahb_clk','GCC_QUPV3_WRAP_1_S_AHB_CLK',128,21,0x23280),('gcc_qupv3_wrap1_s4_clk','GCC_QUPV3_WRAP1_S4_CLK',101,26,0x184e4)]:
 body=re.search(r'static struct clk_branch '+name+r' = \{(.*?)\n\};',text,re.S).group(1)
 assert int(re.search(r'\.halt_reg = (0x[0-9a-f]+)',body)[1],16)==halt
 assert int(re.search(r'\.enable_reg = (0x[0-9a-f]+)',body)[1],16)==0x52008
 assert int(re.search(r'\.enable_mask = BIT\((\d+)\)',body)[1])==bit
 assert int(re.search(rb'#define\s+'+macro.encode()+rb'\s+(\d+)',ids)[1])==number
 assert '['+macro+'] = &'+name+'.clkr'in text
 rows.append({'name':name,'FDT_clock_id':number,'vote_register':0x152008,'vote_bit':bit,'halt_register':0x100000+halt})
rcg=re.search(r'static struct clk_rcg2 gcc_qupv3_wrap1_s4_clk_src = \{(.*?)\n\};',text,re.S)[1];assert '.cmd_rcgr = 0x184f0'in rcg
candidates=[]
for number,want in [(1,'e894b0002340de8ff9bfd6610b14d900381a714c43b7ad7d9e31d72e599c4da0'),(2,'eab22c1f46ec2c4f2b64c4141f2526c0467743b9ee9339816d697e0bf4052184')]:
 path=B/f'fdt-analysis/private/kalama-candidate-{number}-last.dtb';assert sha(path.read_bytes())==want;t=Fdt.read(path);provider='/soc/clock-controller@100000';wrapper='/soc/qcom,qupv3_1_geni_se@ac0000';spi=wrapper+'/spi@a90000'
 assert t.cells(provider,'reg')==[0x100000,0x1f4200]
 assert t.strings(provider,'compatible')==[('qcom,kalama-gcc-v2'if number==1 else'qcom,kalama-gcc'),'syscon']
 clocks=t.cells(wrapper,'clocks');se=t.cells(spi,'clocks');ph=t.phandles();assert t.strings(wrapper,'clock-names')==['m-ahb','s-ahb']and clocks[1::2]==[127,128]and se[1:]==[101]and all(ph[h]==provider for h in [clocks[0],clocks[2],se[0]])
 candidates.append({'sha256':want,'GCC_reg':t.cells(provider,'reg'),'GCC_compatible':t.strings(provider,'compatible'),'wrapper_clock_ids':clocks[1::2],'engine_clock_id':se[1]})
out={'kernel_commit':'c87f74901db572a762241d6dfcacc42dbdd9f798','gcc_source_sha256':sha(gcc),'clock_ids_source_sha256':sha(ids),'source_URLs':['https://github.com/OnePlusOSS/android_kernel_oneplus_sm8550/blob/c87f74901db572a762241d6dfcacc42dbdd9f798/drivers/clk/qcom/gcc-kalama.c','https://github.com/OnePlusOSS/android_kernel_oneplus_sm8550/blob/c87f74901db572a762241d6dfcacc42dbdd9f798/include/dt-bindings/clock/qcom%2Cgcc-kalama.h'],'candidates':candidates,'clocks':rows,'fixed_trial_pages':[0x118000,0x123000,0x152000],'page_bytes':4096,'root_CMD_CFG':[0x1184f0,0x1184f4],'enable_order':['m-ahb','s-ahb','se-clk'],'disable_order':['se-clk','s-ahb','m-ahb'],'inference':'Trial ACPI resources are constructed from these source-backed GCC subranges. PnP allocation and native clock behavior still require separate capture. Candidate agreement does not prove active Android DTBO selection.','rate_or_regulator_changes':False,'native_operations':0}
a.output.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out))
