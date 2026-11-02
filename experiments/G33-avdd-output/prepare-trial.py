"""Validate saved native prerequisites and generate one bounded enable trial.

No native commands are executed. Supply messages are confined to RPMh enable;
only primary GPIO10 output/direction and original-state restore are added.
Reset24 stays asserted. The direct SPMI write channel is never accessed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--inputs', type=Path, required=True)
p.add_argument('--work', type=Path, default=Path(__file__).resolve().parent)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--nonce', help='Saved nonce for offline reproduction only')
a = p.parse_args()
assert not a.output.exists()
W = a.work
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
raw_path = W / 'private/baseline-debug.txt'
capture = json.loads((W / 'baseline-capture.json').read_text())
assert sha(raw_path) == capture['receipt']['sha256']
raw = raw_path.read_text(errors='replace').replace('\r\n', '\n')
part = raw[raw.rindex('\nG33_BASELINE_BEGIN\n'):raw.rindex('\nG33_BASELINE_END\n')]
def result(marker):
    rows = [json.loads(x[len(marker):]) for x in part.splitlines() if x.startswith(marker)]
    assert len(rows) == 1
    return rows[0]
hdr = result('G29_RSC_HEADERS_JSON ')
rsc = result('G29_RSC_SHADOW_JSON ')
pmic = result('G30_PMIC_OBSERVER_JSON ')
assert hdr['success'] and hdr['MMIO_writes'] == 0 and len(hdr['headers']) == 8
assert hdr['irq'] == {'RSC_DRV_IRQ_ENABLE': 1, 'RSC_DRV_IRQ_STATUS': 0}
assert all(x['RSC_DRV_STATUS'] == 1 and x['RSC_DRV_CONTROL'] == x['RSC_DRV_CMD_ENABLE'] == 0 for x in hdr['headers'])
assert rsc['success'] and rsc['MMIO_writes'] == 0 and len(rsc['reads']) == 17
previous = json.loads((a.inputs / 'rpmh-G30/native-post-queries-shadow.json').read_text())
assert rsc['values'] == previous['native_result']['values']
post_g31 = json.loads((a.inputs / 'rpmh-G31/external-restoration.json').read_text())
assert post_g31['full_RSC_shadow_matches_pretrial'] and post_g31['all8_TCS_idle_disabled']
assert post_g31['PMIC_cfg'] == [8,7,0,0,7,7,0,0] and post_g31['PMIC_status'] == 3 and post_g31['pins'] == [1,0,0x201,0]
live = json.loads((W / 'live-preflight.json').read_text())
assert live['phone']['receipt']['session'] == previous['phone_session'] and live['phone']['receipt']['detail']['cpus'] == 8
assert capture['receipt']['session'] == live['host']['receipt']['session']
assert pmic['read_commands'] == 5 and pmic['pmic_write_commands'] == pmic['configuration_writes'] == 0
assert len(pmic['targets']) == 3 and all(not t['error'] for t in pmic['targets'])
ldo, = [t for t in pmic['targets'] if t['ppid'] == 0x1c4]
assert ldo['identity'] == [0, 4, 1, 1, 4, 0xab, 0, 0]
assert ldo['configuration'] == [8, 7, 0, 0, 7, 7, 0, 0] and ldo['status'] == [3]
pins = []
gpio_guards = {}
for address in [0xf10a000, 0xf118000, 0xf119000]:
    matches = re.findall(r'^\s*#\s*' + format(address, 'x') + r'\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s+([0-9a-fA-F]{8})\s*$', part, re.M)
    assert len(matches) == 1
    words = [int(x,16) for x in matches[0]]
    assert words[2] & 1 == 0 and words[3] == 0, 'GPIO IRQ is enabled or latched'
    if address != 0xf119000: pins += words[:2]
    gpio_guards[str(address+8)] = words[2]
    gpio_guards[str(address+12)] = words[3]
    if address == 0xf119000:
        gpio_guards[str(address)] = words[0]
        irq25_initial_input = words[1]
assert pins == [1, 0, 0x201, 0]
observed = json.loads((a.inputs / 'rpmh-G32/trial/native-result.json').read_text())
assert observed['restored'] and not observed['needs_recovery']
assert observed['enabled_pmic']['configuration'] == [8,7,8,7,7,7,128,0] and observed['enabled_pmic']['status'] == 0x87
nonce = a.nonce if a.nonce else secrets.token_hex(8)
assert re.fullmatch('[a-f0-9]{16}', nonce)
binding = {'nonce': nonce, 'phone_session': previous['phone_session'], 'rsc': rsc['values'],
           'pmic': {'identity': ldo['identity'], 'configuration': ldo['configuration'], 'status': ldo['status'][0]},
           'pins': pins, 'native_baseline_sha256': sha(raw_path),
           'expected_client_votes': {'voltage': 1800, 'mode': 7, 'enable': 0},
           'gpio_guards': gpio_guards, 'observed_on_cfg': observed['enabled_pmic']['configuration'],
           'irq25_initial_input': irq25_initial_input,
           'only_GPIO_write_addresses': ['0xf10a000','0xf10a004'],
           'reset24_must_remain_asserted': True,
           'resource_masks': {'voltage': 0x1fff, 'mode': 7, 'enable': 1},
           'observed_high_response_bit': '0x80000000; meaning unproven; retain raw and decode field'}
shadow = json.loads((a.inputs / 'rpmh-G29/shadow-plan.json').read_text())
addresses = {k: int(v, 16) for k, v in shadow['fields'].items()}
assert addresses.keys() == binding['rsc'].keys()
ready_path = a.inputs / 'rpmh-G31/ready-emulation.json'
ready = json.loads(ready_path.read_text())
assert ready['passed'] == 17 and 'status bit7 for model73' in ready['result']
source_validation_path = W / 'source-validation.json'
source_validation = json.loads(source_validation_path.read_text())
assert source_validation['passed'] and source_validation['cases'] == 56 and source_validation['unchanged_source_functions'] == 4
body_path = Path(__file__).resolve().parent / 'trial-template.js'
body = body_path.read_text()
for forbidden in ['0xc7b7000', '0xc7b7008', '0xb000000']:
    assert forbidden not in body
assert 'WRITE_ENABLE",0x40804,1,' in body and 'WRITE_ENABLE",0x40804,0,' in body
prefix = '"use strict";\nvar G33_BINDING=' + json.dumps(binding, separators=(',', ':')) + ';\n'
prefix += 'var G33_RSC_ADDR=' + json.dumps(addresses, separators=(',', ':')) + ';\n'
prefix += 'Object.freeze(G33_BINDING.rsc);Object.freeze(G33_BINDING.pmic.identity);Object.freeze(G33_BINDING.pmic.configuration);Object.freeze(G33_BINDING.pmic);Object.freeze(G33_BINDING.pins);Object.freeze(G33_BINDING.gpio_guards);Object.freeze(G33_BINDING.observed_on_cfg);Object.freeze(G33_BINDING);Object.freeze(G33_RSC_ADDR);\n'
a.output.mkdir(parents=True)
source = a.output / 'G33-avdd-output.js'
source.write_text(prefix + body)
(a.output / 'binding.json').write_text(json.dumps(binding, indent=2) + '\n')
(a.output / 'source-proof.json').write_text(json.dumps({
    'source_sha256': sha(source), 'template_sha256': sha(body_path),
    'raw_native_baseline_sha256': sha(raw_path), 'ready_emulation_sha256': sha(ready_path),
    'G31_external_restoration_sha256': sha(a.inputs / 'rpmh-G31/external-restoration.json'),
    'G31_native_result_sha256': sha(a.inputs / 'rpmh-G31/trial/native-result.json'),
    'G31_documented_response_masks_sha256': sha(a.inputs / 'rpmh-G31/response-mask-analysis.json'),
    'G32_actual_on_state_sha256': sha(a.inputs / 'rpmh-G32/trial/native-result.json'),
    'pinctrl_kalama_sha256': sha(a.inputs / 'gpio-G20/private/pinctrl-kalama.c'),
    'pinctrl_common_sha256': sha(a.inputs / 'gpio-G20/private/pinctrl-msm.c'),
    'touch_common_sha256': sha(a.inputs / 'touch-G25/private/touchpanel_common_driver.c'),
    'source_validation_sha256': sha(source_validation_path),
    'source_validation_recipe_sha256': sha(W / 'validate-gpio-source.py'),
    'G30_prior_shadow_sha256': sha(a.inputs / 'rpmh-G30/native-post-queries-shadow.json'),
    'G28_platform_binding_sha256': sha(a.inputs / 'touch-G28/RPMh-platform-binding.json'),
    'RSC_address_plan_sha256': sha(a.inputs / 'rpmh-G29/shadow-plan.json'),
    'G29_original_HAL_validation_sha256': sha(a.inputs / 'rpmh-G29/HAL-emulation.json'),
    'source_RSC_read_and_reclaim_parent': 'G29/G30 native READ implementation',
    'write_encoding_basis': 'G29 original RpmhDxe SetupDrv2Tcs kind1 uses MSGID10108/address40804; downstream regulator enable data1/release0',
    'only_supply_write_address': '0x40804', 'max_enable_messages': 1, 'max_release_messages': 1,
    'voltage_mode_pinmux_reset_clock_GIC_or_raw_partition_writes_permitted': 0
    ,'GPIO10_direction_output_and_original_direction_restore_only': True
}, indent=2) + '\n')
(a.output / 'native-headers-baseline.json').write_text(json.dumps(hdr, indent=2) + '\n')
(a.output / 'native-shadow-baseline.json').write_text(json.dumps(rsc, indent=2) + '\n')
(a.output / 'native-PMIC-baseline.json').write_text(json.dumps(pmic, indent=2) + '\n')
print(json.dumps({'source_sha256': sha(source), 'nonce': nonce, 'only_supply_write_address': '0x40804'}))
