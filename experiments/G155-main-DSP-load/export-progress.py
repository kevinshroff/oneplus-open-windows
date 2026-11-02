"""Export owned source and bounded native evidence. Never copy OEM PEs or keys."""
from pathlib import Path
import datetime
import hashlib
import json
import shutil

w = Path(__file__).resolve().parent
p = w / 'private'
r = Path('/path/to/user/Documents/GitHub/oneplusopen-win11')
x = r / 'experiments/G155-main-DSP-load'
e = r / 'evidence/G155'
x.mkdir(exist_ok=False)
e.mkdir(exist_ok=False)
sha = lambda f: hashlib.sha256(f.read_bytes()).hexdigest()
load = lambda f: json.loads(f.read_text())
write = lambda f, data: f.write_text(json.dumps(data, indent=2) + '\n')
native = load(p / 'native-analysis.json')
assert native['native_authority'] and native['capture_consistent'] and native['observed_main_public_load']
assert native['report']['phase'] == [3, 3] and native['report']['fault'] == 0
assert not native['report']['fatal_restore'] and native['report']['main_payload']['Complete']

for f in w.iterdir():
    if f.is_file() and f.suffix in ['.py', '.c', '.h', '.inf', '.ps1']:
        shutil.copy2(f, x / f.name)
shutil.copytree(p / 'candidate-source', x / 'firmware-source')
shutil.copytree(w / 'report-reader', x / 'report-reader',
                ignore=shutil.ignore_patterns('*.exe', '__pycache__', '.DS_Store'))
expected = load(p / 'candidate-source-hashes.json')
assert {str(f.relative_to(x / 'firmware-source')): sha(f)
        for f in (x / 'firmware-source').rglob('*') if f.is_file()} == expected
reader = load(p / 'reader-verification.json')
for name, digest in reader['source_sha256'].items():
    assert sha(x / 'report-reader' / name) == digest
for name in ['candidate-source-hashes.json', 'source-integration.json', 'image-audit.json',
             'inline-AT-audit.json', 'linked-main-read-audit.json',
             'linked-orchestration-audit.json', 'linked-sink-audit.json',
             'DTB-callback-audit.json', 'qualification-tests.json',
             'analysis-guard-tests.json', 'release-guard-tests.json',
             'reader-verification.json', 'preflight-test-results.json',
             'native-analysis.json', 'DSP-native.json', 'OPAS-native.json',
             'raw-OAPF-native.json', 'PIL-native.json', 'native-collection-jobs.json',
             'G155-boot-intent.json', 'G155-boot-result.json', 'stage-native-result.json',
             'release-package.json', 'G154-restoration-receipt-after-G155.json']:
    shutil.copy2(p / name, e / name)
for name in ['native-OADP.bin', 'native-OSER.bin', 'native-OPAS.bin',
             'native-OAPF.bin', 'native-OPIL.bin']:
    shutil.copy2(p / name, e / name)
shutil.copy2(p / 'adapter-model-01/tests.json', e / 'adapter-model.json')
shutil.copy2(p / 'release/G155-release.json', e / 'release-manifest.json')

(x / 'README.txt').write_text('''G155: native original main-DSP load after scalar DTB correction
25 October 2026 UTC

Actual native result

One temporary boot completes both original public PIL requests: DTB36 followed
by main image1. All six INIT/MEM_SETUP/AUTH secure calls enter and return with
original API status0/results[1,0]. Public DTB and main results are0/success.
The diagnostic intentionally stops with EFI_ABORTED after phase[3,3], fault0.
Both temporary hooks restore. No PAS retry/shutdown or partition flash occurs.

The main verifier checks64,910,785 bytes in89 extents:54 files and35 zero tails.
All hashes/tails pass, including finite checks before/after reads. Copy attempts1,
refresh attempts2/accepted2; final source/file/memory/cleanup checks pass for all
64 source files. Untouched regions are not invented as zero. These finite CPU,
reservation and display checks do not establish global DMA ownership or a
production power lease. PRE/POST callback return values are not directly captured.

The five actual OADP/OSER/OPAS/OAPF/OPIL tables cross-bind and independently decode.
Their raw bytes and bounded decoded results are in evidence/G155. This proves
the observed public-load sequence. It does not alone qualify sustained DSP
execution, GLINK readiness, a charger reply, battery percentage or charging.
G156 separately inspects the resulting shared memory on this same live boot.

Source/build and validation

The37-file G151 candidate changes only four files: native-proven G153 scalar
OpenDtbAdmission.c, removal of explicit BaseCryptLib dependency, campaign/table
identity in OpenGuardedAdsp.c and OpenAdspPreflight.c. Main copy/admission/verifier
logic is unchanged. Source integration and all hashes accompany the export.
Outer identities are G155DSP1/G155SIP1/rev155; body ABIs deliberately remain
G151DSP1/9080 and G151LOG1/v2/304. The preserved DTB check component logs G153.

The pinned Colima checkout68ae12fafdcd873240d8635afecac542c2c4c563 builds121
validated images. The compact4MiB FD fits; FVMAIN has only2104 bytes free.
215 FFS files compare with native G153:212 identical; intended BDS, its container
and a CodeView-only identity/checksum account for the remainder. Linked audits
are complete, superseding image-audit's contemporaneous pending wording.

Checks:96 actual-C adapter cases;34 filesystem facade;171 reader leaves and192
actual-C wire fixtures;15 native-prerequisite cases;99 analysis refusal cases;
three package refusals;24 compiled AT sequences;167 linked main read/owner cases;
22 linked orchestration cases;three compiled scalar DTB hashing slices; six
compiled serial Read/Poll leaf cases. Unchanged component suites are reused only
with exact source hashes. Modeled/replayed boundaries remain explicit in each
report and are separate from native evidence. The reader natively refuses G153.
Windows parses all seven generated PS scripts/templates after substitution.

Software fastboot and recovery

The qualified G154 one-shot helper enters stock bootloader fastboot from WinPE.
A prepared watcher launches this exact image only after fresh serial/product/
mode/slot checks, replacing the debug listener with a triggerless auto-continue
instance. Both temporary boot acceptance and a fresh G155 WinPE command session
are observed. This is the second native software-fastboot entry; no human cue.

The original Windows loader SHA is freshly rechecked after G155 and matches.
G154.STATUS phase4 can be retained from the previous cycle: it is not a nonce
proof of the latest reset. Arm/observed fastboot/accepted boot/new session and
fresh loader re-hash establish this complete loop. The lost reboot reply is
previous_session_unknown, never replayed. The EEM repair retains host2.2/16 and
debug4.1/16, with4.1 SkipAsSource, restoring signed control without losing KD.

Reproduction and limits

The37-file firmware-source is the complete owned candidate overlay, not all
baseline firmware. Scripts are deliberate laboratory entry points tied to the
retained workspace, original OEM files, exact prior source manifests and native
G153 evidence. Existing intent files prohibit replay; historical stage/build
snapshots describing zero native boots are pre-action records. Current status
is evidence/G155/status.json. Never rerun the consumed launcher/build installer.

Rebuild the ARM64 reader with CGO_ENABLED=0 GOOS=windows GOARCH=arm64, go build
-trimpath -buildvcs=false in report-reader. Retain its deterministic build ID;
removing it changes the executable identity. Test with go test.
The native reader identity is in reader-verification.json. Complete private
REA snapshots, OEM PEs, payloads, FD/boot images, signed helpers, keys and debug
credentials are not redistributed here. Working installed touch,300%,Never,
certificate, GPT/BCD and WinPE recovery remain. All six full goal areas remain
incomplete. No modem_a/D: write, direct barred MMIO, or charging setter occurs.
''')
status = {'campaign': 'G155', 'state': 'native-main-public-load-succeeded',
          'native_boots': 1, 'partition_flashes': 0, 'PAS_calls_entered': 6,
          'PAS_calls_returned': 6, 'phase': [3, 3], 'fault': 0,
          'public_DTB_success': True, 'public_main_success': True,
          'main_verified_bytes': 64910785, 'main_extents': 89,
          'hooks_restored': True, 'five_table_cross_binding': True,
          'software_fastboot_entries_total': 2,
          'fresh_original_Windows_loader_hash_verified_after_G155': True,
          'DSP_running_qualified': False, 'GLINK_ready_qualified': False,
          'charging_qualified': False, 'all_six_goal_areas_complete': False,
          'next': 'G156 same-boot passive SMEM capture, then qualified AP GLINK handshake',
          'historical_snapshot_note': 'Build/release/stage artifacts retain their pre-action counts; this status is current.'}
write(e / 'status.json', status)

w156 = w.parent / 'charging-G156'
p156 = w156 / 'private'
x156 = r / 'experiments/G156-post-load-SMEM'
e156 = r / 'evidence/G156'
x156.mkdir(exist_ok=False)
e156.mkdir(exist_ok=False)
shutil.copytree(w156 / 'manager', x156 / 'manager')
for name in ['run-passive.py', 'inspect-capture.py']:
    shutil.copy2(w156 / name, x156 / name)
passive = load(p156 / 'passive-analysis.json')
assert passive['observer_retired_and_independently_absent']
assert passive['native_R2_matches_offline_decode'] and passive['ADSP_RX_FIFO_480_present']
for name in ['prepared.json', 'intent-stage.json', 'intent-capture.json',
             'intent-retire.json', 'load-receipt.json', 'status-receipt.json',
             'capture-receipt.json', 'unload-receipt.json', 'absence-receipt.json',
             'decoded-native-r2.json', 'passive-analysis.json']:
    shutil.copy2(p156 / name, e156 / name)
(x156 / 'README.txt').write_text('''G156: passive SMEM observation after native G155 main load
25 October2026 UTC, same G155 WinPE boot

Observed result

One500.2966ms capture reads2,326,528 physical bytes through ten read-only maps.
The AP/ADSP heap now contains11 items, including the previously absent DSP RX
FIFO480 and SMP2P443. The descriptor words are[0,0,0,8,0,0,0,0]. Source-bound
ring interpretation: AP TX head/tail0; DSP TX head8/tail0. Its eight pending
bytes0000010007000000 decode as GLINK VERSION, version1, advertised features7.
The host has not sent a frame. SMP2P443 has local PID2/remote0/features1/flags0
and zero valid entries; no ready bit or charger property is invented.

Only item634 changes between samples: four bytes differ in its200-byte value.
The other four captured regions are identical. This is actual temporal activity,
not R1's old comparison-boundary error. R2 runs natively for the first time and
matches an independent offline decode of the same full-file SHA. The global
heap has24 items. Complete inventories and cross-boot G135 differences are in
evidence/G156/passive-analysis.json; cross-boot changes are not causal isolation.
The32KiB retained firmware log supplies no relevant ADSP/PIL/SMC error line and
is not assumed to be the active logging sink.

Scope and retirement

The exact native-qualified G135 signed kernel observer is reused unchanged.
Only the manager's current reader name/hash and G155 OADP hash binding change;
the fixed service and RAM driver path remain OpenG135/G135-signed.sys. It checks
the exact current native load report before load/status/unload. Native load and
STATUS report zero maps/attempts before the single nonce-bound capture. Raw data
is retrieved and hash-verified before unload; a separate query proves absence.
Signed remote control remains responsive. No SCM/PAS/GLINK request, physical
write, FIFO-index update, reset, partition/BCD/firmware install or key test occurs.
Only global and AP/ADSP partitions are read; other private heaps are excluded.

Source and reproduction

Kernel/client source and existing models are in G135-passive-WinPE-state; exact
signed sys SHAa357a234505ec3a8d3c2c55bed4de02f2847485206a874668c9a1d2f84e85ee6.
The corrected R2 client SHA is39dbde9b004ede149e8a280e10795d3b0ce8788aeda5ff95e36cf05be0484dd3.
Build manager from the two manager/ Go files for Windows ARM64, CGO disabled,
-trimpath -buildvcs=false -ldflags=-buildid=. prepared.json binds the result.
The laboratory orchestrator requires the retained workspace and original native
G155 session/report. Its intents are consumed: never replay an uncertain job.

inspect-capture.py reuses corrected G135 Go decoding and previously validated
G108 item-format functions without executing that script's setup. It checks
both snapshots independently, allows actual changes and uses retained SMEM/
GLINK source definitions for the frame/ring interpretation. Full raw heaps,
logs, signed binaries and keys remain private. Only bounded inventories, hashes,
counter/frame metadata and receipts are exported. Current source and all driver
guards remain finite diagnostics, not a production PnP/resource owner.

Next implement an AP GLINK transport with explicit ownership and validated
descriptor/FIFO/barrier/doorbell handling. First negotiate the captured version;
then a strictly validated charger-property request/reply. Advertisement and
short shared-memory activity alone do not qualify sustained DSP execution,
GLINK end-to-end operation or real charging. All six goal areas remain active.
''')
write(e156 / 'status.json', {
    'campaign': 'G156', 'state': 'native-DSP-GLINK-advertisement-observed',
    'native_captures': 1, 'kernel_unchanged_from_G135': True,
    'corrected_R2_client_executed_natively': True,
    'physical_writes': 0, 'PAS_calls': 0, 'GLINK_requests': 0,
    'RX_FIFO_480_present': True, 'pending_DSP_frame': 'VERSION v1/features7',
    'host_TX_empty': True, 'SMP2P_ready_bit_observed': False,
    'AP_ADSP_changed_item_between_samples': 634,
    'observer_retired_and_independently_absent': True,
    'GLINK_ready_qualified': False, 'charging_qualified': False,
    'next': 'Qualified AP transport version handshake; no native writer yet.'})
for campaign, out in [('G155', x), ('G156', x156)]:
    manifest = {str(f.relative_to(out)): sha(f) for f in sorted(out.rglob('*')) if f.is_file()}
    write(r / 'evidence' / campaign / 'export-source-hashes.json', manifest)
print(json.dumps({'G155_exported_sources': len(list(x.rglob('*'))),
                  'G156_exported_sources': len(list(x156.rglob('*'))),
                  'native_main_load_success': True, 'native_DSP_version_frame': True}, indent=2))
