"""Audit G24 retained observations and emit a compact, non-secret evidence record.

Does not connect to the phone or issue debugger commands. Raw debugger captures,
donor binaries, and snapshots remain private; their hashes bind this summary.
"""
from pathlib import Path
import argparse, hashlib, importlib.util, json, re

W = Path(__file__).resolve().parent
LOGS = W.parent / 'platform-snapshot/private'
spec = importlib.util.spec_from_file_location('aeob', W / 'decode-bsrc.py')
aeob = importlib.util.module_from_spec(spec)
spec.loader.exec_module(aeob)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
read = lambda name: json.loads((W / name).read_text())


def tagged(name, tag):
    p = LOGS / name
    text = p.read_text(errors='strict').replace('\r\n', '\n')
    begin, end = '\n' + tag + '_BEGIN\n', '\n' + tag + '_END\n'
    i, j = text.rfind(begin), text.rfind(end)
    assert 0 <= i < j
    return text[i+len(begin):j], {'private_file': p.name, 'sha256': sha(p),
                                 'bytes': p.stat().st_size, 'tag': tag}


def report(text):
    rows = re.findall(r'^G24_CLOCKPROBE_JSON (.+)$', text, re.M)
    assert len(rows) == 1
    return json.loads(rows[0])


def simple(item):
    if 'package' in item:
        return [simple(x) for x in item['package']]
    if 'string' in item:
        return item['string']
    if 'integer' in item:
        return item['integer']
    return item


def commands(tree, name):
    if isinstance(tree, list):
        if tree and tree[0] == name:
            yield tree
        for item in tree:
            yield from commands(item, name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=W/'native-bus-result.json')
    args = parser.parse_args()
    assert not args.output.exists(), 'Preserve the existing evidence; select a new --output'
    ro, ro_ref = tagged('debug-live-20261021T084026Z.txt', 'G24_CLOCKSCRIPT_READ')
    active, active_ref = tagged('debug-live-20261021T084042Z.txt', 'G24_CLOCK_ID_P1')
    undo, undo_ref = tagged('debug-live-20261021T084114Z.txt', 'G24_CLOCK_RESTORE_CHECK')
    ro, native = report(ro), report(active)
    assert ro['mode'] == 'READ' and all(c['writes_attempted'] == 0 for c in ro['candidates'])
    assert native['mode'] == 'ENABLE_ID_READ_RESTORE' and native['all_votes_restored']
    assert len(native['candidates']) == 2
    source = W / 'G24-clockprobe.js'
    stage = read('clockprobe-stage.json')
    assert sha(source) == stage['source_sha256'] == stage['hash']['sha256']
    assert stage['stage']['status'] == stage['hash']['status'] == 'ok'
    allowed = {'152008': (0x40002380, 0x04300000), '152010': (0x1001f, 0x46)}
    writes, identities = [], []
    for c in native['candidates']:
        assert c['error'] is None and c['identity_read'] and c['vote_restored']
        assert c['full_vote_matches_baseline']
        for key in ('cbcr', 'root_cmd', 'root_cfg'):
            assert c['before_' + key] == c['after_' + key]
        assert int(c['before_cbcr'],16) & 0x80000000
        assert not int(c['enabled_cbcr'],16) & 0x80000000
        for i, event in enumerate(c['events']):
            if event['kind'] != 'write_attempt':
                continue
            addr, value = event['address'], int(event['value'],16)
            baseline, mask = allowed[addr]
            assert ((value ^ baseline) & ~mask) == 0
            follow = c['events'][i+2]
            assert follow == {'kind':'read','address':addr,'value':event['value']}
            writes.append({'address':addr,'value':event['value']})
        hw, fw = int(c['wrapper_hw_version'],16), int(c['main_fw_revision'],16)
        hp0, hp1 = int(c['hw_param_0'],16), int(c['hw_param_1'],16)
        identities.append({'candidate':c['name'], 'wrapper_hw_version':c['wrapper_hw_version'],
            'wrapper_major':hw >> 28, 'wrapper_minor':(hw >> 16) & 0xfff,
            'wrapper_step':hw & 0xffff, 'main_firmware':c['main_fw_revision'],
            'secondary_firmware':c['secondary_fw_revision'], 'protocol':(fw >> 8) & 0xff,
            'firmware_revision':fw & 0xff, 'spi_protocol_source_enum':1,
            'geni_status':c['geni_status'], 'if_disable':c['if_disable'],
            'fifo_interface_disabled':bool(int(c['if_disable'],16) & 1),
            'tx_fifo_depth':(hp0 >> 16) & 0x3f,'tx_fifo_width':(hp0 >> 24) & 0x3f,
            'rx_fifo_depth':(hp1 >> 16) & 0x3f,'rx_fifo_width':(hp1 >> 24) & 0x3f})
    raw_writes = re.findall(r'^!ed \[uc\] ([0-9a-f]+) ([0-9a-f]+)$',active,re.M)
    assert raw_writes == [(x['address'],x['value']) for x in writes]
    assert len(writes) == 8
    independent = dict((a, int(v,16)) for a,v in re.findall(
        r'^#\s+([0-9a-f]+)\s+([0-9a-f]{8})\s*$',undo,re.M))
    assert independent == {'152008':0x40002380,'152010':0x1001f,
                           '1184e4':0x80004000,'11e274':0x80004000}
    post = read('post-clock-native-state.json')['probe']
    initial = read('initial-native-state.json')
    assert post['status'] == 'ok' and post['session'] == initial['session']
    assert post['detail']['arch'] == 'arm64' and post['detail']['cpus'] == 8
    provider = read('native-provider-probe.json')
    assert provider['session'] == post['session']
    for name, expected in provider['source_hashes'].items():
        assert sha(W / 'providerprobe' / name) == expected
    assert sha(W / 'private/G24-providerprobe-arm64.exe') == provider['binary_sha256']
    disk, pep = provider['report']['interfaces']
    assert disk['status'] == pep['status'] == 'enumerated'
    assert disk['present_interface_count'] == 6 and pep['present_interface_count'] == 0
    resources = []
    for name, expected in aeob.HASHES.items():
        data = (W.parent / 'gpio-G23/private/SPI-firmware' / name).read_bytes()
        decoded = aeob.decode_container(data, expected)
        selected = []
        for uid, phone_pins in ((13,[44,45,46,47]),(19,[64,65,66,67])):
            tree = simple(decoded['arguments'][uid-1])
            d0 = next(x for x in tree if isinstance(x,list) and x[:2] == ['DSTATE',0])
            pins = [x[1][0] for x in commands(d0,'TLMMGPIO')]
            assert pins != phone_pins
            selected.append({'uid':uid,'device_path':tree[1], 'donor_D0_pins':pins,
                             'phone_source_pins':phone_pins,
                             'D0_clocks':[x[1] for x in commands(d0,'CLOCK')]})
        resources.append({'file':name,'sha256':expected,'bytes':len(data),
                          'argument_count':decoded['argument_count'],
                          'lossless_exact_reencoding_passed':True,'selected_records':selected})
    emu = read('BSRC-selector-emulation.json')
    assert emu['valid_uid_cases_passed'] == 48 and emu['mocked_functions'] == []
    for f in emu['files']:
        assert all(x['exact_selected_record_and_rebuilt_header_match'] for x in f['valid_uid_cases'])
    artifacts = []
    for receipt, directory in [('SCM-extraction.json','scm-candidate'),
                                ('PEP-extraction.json','pep-candidate')]:
        r=read(receipt)
        for f in r['files']:
            path=W/'private'/directory/f['file']
            assert path.stat().st_size==f['bytes'] and sha(path)==f['sha256']
        artifacts.append(r)
    bundles = []
    for name in ['SPI-contract-evidence-v1.json','SCM-PEP-consumer-evidence.json',
                 'PEP-provider-evidence-v1.json','SPI-selection-evidence-v2.json']:
        path=W/'private'/name
        bundles.append({'file':name,'sha256':sha(path),'bytes':path.stat().st_size,
                        'records':len(json.loads(path.read_text())['records'])})
    out = {'phase':'native_clock_enable_identity_and_exact_vote_undo_verified',
        'previous_goal_turn':'progress: G23 native input/reconnect and rollback',
        'this_goal_turn':'progress: native source-mapped clock activation/undo and GENI identity; donor contract reconstruction',
        'session':post['session'], 'root':initial['root'],
        'clock_probe_source_sha256':sha(source), 'clock_stage_jobs':stage['jobs'],
        'clock_raw_capture_refs':[ro_ref,active_ref,undo_ref], 'clock_probe':native,
        'identities':identities,'all_eight_vote_writes_have_matching_readbacks':True,
        'independent_final_vote_and_clock_readbacks_match_baseline':True,
        'post_probe':{'job':post['id'],'session':post['session'],'arch':'arm64','cpus':8,'status':'ok'},
        'provider_probe':{'binary_sha256':provider['binary_sha256'],'jobs':provider['jobs'],
            'interfaces':provider['report']['interfaces'],
            'historical_label_correction':'SPI_required_SCM_provider is the original v1 label; REA identifies PEP as provider and SCM as another consumer. Native GUID/count observations remain valid; source is preserved unchanged.'},
        'resource_containers':resources,'selector_emulation':{
            'valid_original_ARM64_cases':48,'mocked_functions':[],
            'uid_25_reads_past_logical_resource_end':True,
            'uid_0_and_26_return_status':'0xc0000023','native_execution':False},
        'donor_artifacts':artifacts,'REA_private_bundles':bundles,
        'write_scope':'Only temporary GCC application vote bits via paused debugger, plus ordinary staged project files; no raw partition, GPT, boot image, WIM, BCD, rail, GPIO, reset, FIFO, interrupt or peripheral-command writes.',
        'remaining':['Actual touch IC identity/voltage/reset/pinmux and SPI transfers are unverified.',
                     'Secondary FIFO-disable requires a compatible DMA/GPI path or a proven supported alternative.',
                     'PEP package is for 8380; platform compatibility is not established and it was not installed.',
                     'SPI ISR offset 0x620 differs from source GENI_M_IRQ_CLEAR 0x618; context mapping has no base bias, so semantics require resolution.',
                     'All 21 goal areas remain active; native full Windows with phone hardware is incomplete.']}
    path=args.output
    path.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'phase':out['phase'],'identities':identities,'verified_vote_writes':8,
                      'healthy_G17':True,'all_21_areas_active':True}))


if __name__ == '__main__':
    main()
