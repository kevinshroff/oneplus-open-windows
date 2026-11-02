"""Decode only the bounded, repeated native TLMM reads using pinned vendor definitions."""
from pathlib import Path
import hashlib
import importlib.util
import json
import re

W = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('physical', W.parent/'platform-snapshot/decode-physical.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
source = W/'private/pinctrl-kalama.c'
s = source.read_text()
macro = s[s.index('#define PINGROUP('):s.index('#define SDC_QDSD_PINGROUP')]
bits = {name: int(re.search(r'\.'+name+r'\s*=\s*(\d+)', macro)[1])
        for name in ['mux_bit','pull_bit','drv_bit','oe_bit','in_bit','out_bit',
                     'egpio_enable','egpio_present','intr_enable_bit','intr_status_bit',
                     'intr_target_bit','intr_target_kpss_val','intr_raw_status_bit',
                     'intr_polarity_bit','intr_detection_bit','intr_detection_width']}
assert '#define REG_BASE 0x100000' in s and '#define REG_SIZE 0x1000' in s
pre = json.loads((W/'GPIO-read-preflight.json').read_text())
assert pre['source_sha256'] == hashlib.sha256(source.read_bytes()).hexdigest()
pins = {x['pin']: x for x in pre['pins']}
result = []
logs = {}
for tag, group in [('G20_GPIO0',[10,24,25,174]),('G20_GPIO1',[44,45,46,47,64,65,66,67])]:
    log, (a,b) = m.latest(tag)
    logs[log.name] = hashlib.sha256(log.read_bytes()).hexdigest()
    for pin in group:
        address = int(pins[pin]['config_address'],16)
        raw = m.read(a,address,16)
        assert raw == m.read(b,address,16)
        ctl,io,irq,status = [a[address+4*i] for i in range(4)]
        fields = {
            'mux_selector': (ctl>>bits['mux_bit'])&15,
            'pull_raw': (ctl>>bits['pull_bit'])&3,
            'drive_strength_raw': (ctl>>bits['drv_bit'])&7,
            'output_enabled': bool(ctl&(1<<bits['oe_bit'])),
            'egpio_present': bool(ctl&(1<<bits['egpio_present'])),
            'egpio_enabled': bool(ctl&(1<<bits['egpio_enable'])),
            'input_level': (io>>bits['in_bit'])&1,
            'output_latch': (io>>bits['out_bit'])&1,
            'interrupt_enabled': bool(irq&(1<<bits['intr_enable_bit'])),
            'interrupt_polarity_raw': (irq>>bits['intr_polarity_bit'])&1,
            'interrupt_detection_raw': (irq>>bits['intr_detection_bit'])&((1<<bits['intr_detection_width'])-1),
            'interrupt_raw_status_enabled': bool(irq&(1<<bits['intr_raw_status_bit'])),
            'interrupt_target_raw': (irq>>bits['intr_target_bit'])&7,
            'interrupt_status': (status>>bits['intr_status_bit'])&1,
        }
        item = {'pin':pin,'address':hex(address),'raw':{'control':hex(ctl),'inout':hex(io),'interrupt_config':hex(irq),'interrupt_status':hex(status)},'repeat_identical':True,'decoded':fields}
        if pin in [44,45,46,47,64,65,66,67]:
            body = re.search(r'\['+str(pin)+r'\]\s*=\s*PINGROUP\((.*?)\),',s,re.S)[1]
            args = [x.strip() for x in body.split(',')]
            wanted = ('qup1_se4_l'+str(pin-44)) if pin<64 else ('qup2_se2_l'+str(pin-64))
            assert args[1] == wanted
            item['SPI_function'] = wanted
            item['SPI_function_selector_from_source'] = 1
        result.append(item)
probe = json.loads((W/'post-GPIO-read-probe.json').read_text())
assert probe['status']=='ok' and probe['session']==pre['phone_session']
out = {'source_logs':logs,'source_sha256':pre['source_sha256'],'source_bit_definitions':bits,'pins':result,
       'post_read_probe':{'job':probe['id'],'session':probe['session'],'cpus':probe['detail']['cpus']},
       'target_register_writes':0,'target_firmware_GPT_boot_b_writes':0,
       'limits':['Raw digital state only; no analog rail measurement or SPI transaction.','Primary reset pin24 is output-enabled with low latch; no reset pulse was applied.','All eight SPI pins have selector0; source QUP functions require selector1.','GPIO10 is input-mode; this alone does not prove either touch controller lacks power.','EGPIO flags retain their source-defined names; ownership/security behavior is not inferred.']}
(W/'native-GPIO-result.json').write_text(json.dumps(out,indent=2)+'\n')
print('Verified repeated reads of12 pins/48 registers and post-read control')
