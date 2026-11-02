"""Verify both pinned stock candidates before declaring the pilot resources."""
from pathlib import Path
import argparse,hashlib,json,sys
p=argparse.ArgumentParser();p.add_argument('--fdtree-source',type=Path,required=True);p.add_argument('--tree1',type=Path,required=True);p.add_argument('--tree2',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();assert not a.output.exists();sys.path.insert(0,str(a.fdtree_source.parent));from fdtree import Fdt
expected=['e894b0002340de8ff9bfd6610b14d900381a714c43b7ad7d9e31d72e599c4da0','eab22c1f46ec2c4f2b64c4141f2526c0467743b9ee9339816d697e0bf4052184'];rows=[];wrapper='/soc/qcom,qupv3_1_geni_se@ac0000';bus=wrapper+'/spi@a90000'
for path,want in zip([a.tree1,a.tree2],expected):
 b=path.read_bytes();assert hashlib.sha256(b).hexdigest()==want;t=Fdt.read(path);assert t.cells(bus,'reg')==[0xa90000,0x4000]and t.cells(bus,'interrupts')==[0,357,4]and'dma-coherent'in t.nodes[wrapper]
 rows.append({'candidate_sha256':want,'path':bus,'reg':t.cells(bus,'reg'),'interrupts':t.cells(bus,'interrupts'),'wrapper_path':wrapper,'wrapper_dma_coherent_property_present':True,'spi_compatible':t.strings(bus,'compatible'),'spi_status':t.strings(bus,'status')})
v={'sources':rows,'pilot_memory_base':0xa90000,'pilot_memory_bytes':0x4000,'pilot_ACPI_interrupt':389,'interrupt_derivation':'stock GIC SPI357 +32 as used in priorG24; actual Windows translation/delivery is not yet qualified','pilot_CCA':1,'CCA_basis':'both source wrappers explicitly declare dma-coherent; native DMA functionality/coherency is not qualified','fdtree_source_sha256':hashlib.sha256(a.fdtree_source.read_bytes()).hexdigest(),'native_operations':0};a.output.write_text(json.dumps(v,indent=2)+'\n');print(json.dumps(v))
