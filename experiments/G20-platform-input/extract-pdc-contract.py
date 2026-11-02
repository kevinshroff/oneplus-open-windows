"""Correlate retained REA evidence with pinned vendor wake maps; no native register writes."""
from pathlib import Path
import hashlib,json,re,uuid
W=Path(__file__).resolve().parent;Q=json.loads((W/'PDC-REA-queries.json').read_text());E={x['key']:x['evidence'] for x in Q};artifact=W.parent/'inbox-driver-evidence/qcgpio_i.sys'
assert hashlib.sha256(artifact.read_bytes()).hexdigest()=='3e048697237caf5752e7c1ef40015989339bbed0d22717451ae60187f8d50700'
pin=W/'private/pinctrl-kalama.c';assert hashlib.sha256(pin.read_bytes()).hexdigest()=='fd48c2e5f669c9f3304074b42578e5b6a498ca303855eb0c1d6d47e17d0785ac';s=pin.read_text()
raw=E['gpio_pdc_layout0']['normalized_result'];assert raw['complete'] and raw['returned_bytes']==16
pdc_uuid=str(uuid.UUID(bytes_le=bytes.fromhex(raw['bytes_hex'])))
assert pdc_uuid=='921b0fd4-567c-43a0-bb14-2648f7b2a18c'
assert E['gpio_pdc_query_constants']['normalized_result']['bytes_hex'].startswith('04c03200')
asm=E['gpio_pdc_registry_asm']['normalized_result']['instructions']
for text in ['strh w8, [x19]','strh w8, [x19, #0x2]','str w8, [x19, #0x4]','mov x8, #0x30','mov w8, #0x2']:
 assert any(text in line for line in asm),text
primary=E['gpio_primary5_asm']['normalized_result']['instructions'];assert '0x1400033b4: mov w8, #0x5' in primary
for name,receipt in [('qcom-pdc.c','PDC-source-receipt.json'),('irq-gic-v3.c','GIC-source-receipt.json')]:
 assert hashlib.sha256((W/'private'/name).read_bytes()).hexdigest()==json.loads((W/receipt).read_text())['sha256']
for e in E.values():
 assert e['subject']['digest']['sha256']=='3e048697237caf5752e7c1ef40015989339bbed0d22717451ae60187f8d50700'
pdc_source=(W/'private/qcom-pdc.c').read_text();gic_source=(W/'private/irq-gic-v3.c').read_text()
assert '#define IRQ_ENABLE_BANK\t\t0x10' in pdc_source and '#define IRQ_i_CFG\t\t0x110' in pdc_source
assert 'parent_fwspec.param[0]    = 0;' in pdc_source and '*hwirq = fwspec->param[1] + 32;' in gic_source
stock=json.loads((W.parent/'fdt-analysis/touch-platform-resources.json').read_text())
models=[]
for c in stock['candidates']:
 providers=[p for p in c['platform_providers'] if 'qcom,pdc' in p['resources'].get('compatible',[])];assert len(providers)==1
 p=providers[0];ranges=p['resources']['qcom,pdc-ranges'];assert len(ranges)%3==0
 regions=[tuple(ranges[i:i+3]) for i in range(0,len(ranges),3)]
 name='kalama_pdc_map_v2' if c['base_index']==1 else 'kalama_pdc_map'
 m=re.search(r'static const struct msm_gpio_wakeirq_map '+name+r'\[\] = \{(.*?)\n\};',s,re.S);assert m
 entries=[tuple(map(int,x)) for x in re.findall(r'\{\s*(\d+)\s*,\s*(\d+)\s*\}',m[1])]
 assert len(entries)==93 and len({a for a,b in entries})==len({b for a,b in entries})==93
 rows=[]
 for gpio,pdc in entries:
  hits=[parent+pdc-base for base,parent,n in regions if base<=pdc<base+n];assert len(hits)==1
  spi=hits[0];rows.append({'TLMM_pin':gpio,'PDC_input':pdc,'parent_GIC_SPI':spi,'derived_GIC_INTID_SPI_plus32':spi+32})
 assert len({x['derived_GIC_INTID_SPI_plus32'] for x in rows})==93
 models.append({'base_index':c['base_index'],'merged_dtb_sha256':c['merged_sha256'],'pdc_resource':p['resources'],'source_map':name,'rows':rows,'touch_rows':[r for r in rows if r['TLMM_pin'] in [25,174]],'classification':'source-derived; not a working Windows resource assignment'})
assert models[0]['touch_rows']==models[1]['touch_rows']
r={'artifact_sha256':hashlib.sha256(artifact.read_bytes()).hexdigest(),'scope':'compiled queries/package consumers and source-derived IRQ mapping; no controller installation or MMIO write',
 'primary_TLMM_additional_query':{'selector':5,'return':'scalar flags at context+0x28','observed_bit0_consumer':'permits clearing direct-connect mask in layout1; enabling does not test this flag','query_VA':'0x140003348','consumer_VA':'0x140003f68'},
 'PDC_DSM':{'UUID':pdc_uuid,'UUID_bytes_VA':'0x14000c3a8','revision':0,'IOCTL':'0x32c004','WDF_index':186,'same_four_argument_shape_as_primary':True,'failure_bugcheck':'0x14e, parameter1=1; do not probe with incomplete methods',
 'selector1':'PDC layout mode 0,1,2; other values fail initialization',
 'selector2':'top-level sequence of packages; each package contains three integer arguments: PDC input(u16), TLMM pin(u16; ffff means absent in observed consumer), system interrupt(u32)',
 'selector2_record_bytes':48,'selector2_field_offsets':{'PDC_input':'0x0','TLMM_pin':'0x2','system_interrupt':'0x4','assigned_virtual_pin':'0x8','enable_bank_mapping':'0x10','special_legacy_enable_mapping':'0x18','config_mapping':'0x20'},
 'virtual_pin_assignment':'after (direct_TLMM_count>>6)+1 summary interrupt resources, match package system_interrupt to the translated interrupt resource; assign interrupt-resource ordinal*64; this differs from a TLMM pin number',
 'mode0_queries_in_order':[6,7,8,9,10,11,3,4,5],'mode1_queries_in_order':[3,4,5],'mode2_queries_in_order':[4,5],
 'scalar_destinations':{'6':'d670: mapped secondary base','7':'d674: secondary mapping size','8':'d678','9':'d67c','10':'d680','11':'d684','3':'d68c: enable-bank base; address=base+4*(PDC_input>>5)','4':'d688: config base; address=base+4*PDC_input','5':'five packed nibbles copied to d690,d694,d698,d69c,d6a0; mode1 copies only four'},
 'compiled_trigger_encodings':{'level_low':0,'level_high':4,'falling_edge':2,'rising_edge':6,'dual_edge':7,'invalid':3},
 'unresolved':['Which PDC layout mode and all packed nibble meanings fit this board; not inferred from SoC revision.','Mode2 secure/config transport and mode0 secondary transport requirements.','Complete primary38/42 scalar values, including reserved/unmatched fields.','Actual Windows resource assignment, wake behavior and interrupt delivery remain untested.']},
 'source_correlations':{'PDC_enable_offset':'0x10','PDC_config_offset':'0x110','ordinary_source_PDC_base':'0xb220000','ordinary_source_enable_base':'0xb220010','ordinary_source_config_base':'0xb220110','Windows_mode_selection':'not yet selected from these correlations'},
 'stock_models':models,'evidence_ids':{k:v['evidence_id'] for k,v in E.items() if v},'raw_writes':0}
(W/'PDC-contract.json').write_text(json.dumps(r,indent=2)+'\n')
print('Primary query5 and distinct PDC UUID decoded; both93-entry source maps reconcile with five PDC ranges.')
print('Touch source-derived translations:',models[0]['touch_rows'])
