"""Bind source-derived clock/configuration decisions to pinned retained inputs."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,re
p=argparse.ArgumentParser();p.add_argument('--inputs',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();W=Path(__file__).resolve().parent;G=a.inputs
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def required(path,digest):assert sha(path)==digest;return path.read_text()
rpm=required(W/'private/clk-rpmh.c','190b02992a3062063018ed794a04a9056ed71718b03e90a95dfcb9cc114aac44')
assert 'DEFINE_CLK_RPMH_ARC(kalama, xo_pad, xo_pad_ao, "xo.lvl", 0x03, 2);'in rpm
assert 'DEFINE_CLK_RPMH_FIXED(kalama, bi_tcxo, bi_tcxo_ao, xo_pad, xo_pad_ao, 2);'in rpm
assert 'return prate / r->div;'in rpm and '[RPMH_CXO_CLK]          = &kalama_bi_tcxo.hw'in rpm
rcg=required(W/'private/clk-rcg2.c','ce642f39b41b2343db307433c53fb283d41ed0b55e2a2e7259d416386f168b2c')
for token in ['#define SE_CMD_DFSR_OFFSET 0x14','#define SE_PERF_DFSR(level) (0x1c + 0x4 * (level))','#define SE_PERF_M_DFSR(level) (0x5c + 0x4 * (level))','#define SE_PERF_N_DFSR(level) (0x9c + 0x4 * (level))']:
 assert ' '.join(token.split()) in ' '.join(rcg.split()),token
assert 'Rate changes with consumer writing a register in' in rcg and '* their own I/O region' in rcg
clk=required(G/'bus-G24/private/gcc-kalama.c','bd4305c0cc23883666ecb2079e9f34a992dad39a788157c7ca891d896be1f699')
assert '.cmd_rcgr = 0x184f0,'in clk and 'DEFINE_RCG_DFS(gcc_qupv3_wrap1_s4_clk_src)'in clk
assert 'F(19200000, P_BI_TCXO, 1, 0, 0)'in clk
spi=required(G/'bus-G24/private/spi-msm-geni.c','5d574192c20dfd944565fb093ba5bab5afc958897909aea8b3ca80624204a0a0')
se=required(G/'bus-G24/private/qcom-geni-se.c','5427c8482061e5b7025a86a87c9e6b0627b4d441e5d87e35b3fad7832d5c330b')
assert 'm_clk_cfg |= ((div << CLK_DIV_SHFT) | SER_CLK_EN);'in spi
headers=required(G/'bus-G24/private/qcom-geni-se.h','07435926cc9beb4e1ede96cc7a48e486e5f7006f133f012ac37f08b8b6cf7e05')
assert re.search(r'#define\s+CLK_DIV_SHFT\s+4',headers) and re.search(r'#define\s+SER_CLK_EN\s+BIT\(0\)',headers)
decoder=G/'fdt-analysis/fdtree.py';spec=importlib.util.spec_from_file_location('g37fdt',decoder);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
binding=json.loads((G/'spi-G27/source-binding.json').read_text());rows=[]
for c in binding['candidates']:
 d=G/('fdt-analysis/private/kalama-candidate-%d-first.dtb'%c['candidate']);assert sha(d)==c['sha256'];f=mod.Fdt.read(d);ph=f.phandles()
 assert f.cells('/soc/clocks/xo_board','clock-frequency')==[76800000]
 gcc='/soc/clock-controller@100000';assert f.strings(gcc,'clock-names')[0]=='bi_tcxo'
 provider=ph[f.cells(gcc,'clocks')[0]];assert f.strings(provider,'compatible')==['qcom,kalama-rpmh-clk']and f.cells(gcc,'clocks')[1]==0
 rows.append({'candidate':c['candidate'],'sha256':sha(d),'board_XO_Hz':76800000,'GCC_parent_provider':provider,'bi_tcxo_index':0})
previous=G/'fault-G36/native-qualification.json';n=json.loads(previous.read_text());assert n['phase']=='unloaded_service_and_endpoint_absent_control8CPUs'
assert n['spi']['restored']==1 and n['spi']['clock_before']==n['spi']['clock_after']and n['spi']['pins_before']==n['spi']['pins_after']
paths={'clk-rpmh.c':W/'private/clk-rpmh.c','clk-rcg2.c':W/'private/clk-rcg2.c','gcc-kalama.c':G/'bus-G24/private/gcc-kalama.c','spi-msm-geni.c':G/'bus-G24/private/spi-msm-geni.c','qcom-geni-se.c':G/'bus-G24/private/qcom-geni-se.c','qcom-geni-se.h':G/'bus-G24/private/qcom-geni-se.h','G27_geni_fifo.c':G/'spi-G27/geni_fifo.c','G36_native':previous,'FDT_decoder':decoder}
r={'passed':True,'source_sha256':{k:sha(v)for k,v in paths.items()},'stock_candidates':rows,'bi_tcxo_Hz':76800000//2//2,'divisor':20,'SPI_Hz':960000,'serial_M_clock_config':'0x141','native_selection_policy':'If DFS enabled, require its current index agrees with GENI and select an actual source0/mode0/HID0-or1 performance entry. If disabled, require source0/mode0/HID0-or1 active root CFG. Never write GCC rate/DFS tables.','native_full_undo_required':True,'configuration_field_count':24,'max_engine_write_attempts':48,'max_clock_pad_write_attempts':14,'only_new_write_range':'fixed 24 configuration registers at primary GENI 0xa90000','SPI_command_FIFO_IRQ_clear_supply_reset_writes':0,'limits':['Candidate DTB selection does not establish touch controller identity or Android overlay selection.','Source clock arithmetic is conditional on native register guards. Actual bus waveform/touch identification remains unqualified.','No final PnP/resource owner or power-management lifecycle is provided.']}
a.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps({'passed':True,'SPI_Hz':r['SPI_Hz'],'clock_candidates':len(rows)}))
