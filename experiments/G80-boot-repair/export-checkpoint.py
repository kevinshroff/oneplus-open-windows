from pathlib import Path
import shutil,json,hashlib
W=Path(__file__).resolve().parents[1];repo=Path('/path/to/user/Documents/GitHub/oneplusopen-win11');out=repo/'experiments/G80-boot-repair';e=repo/'evidence/G80';out.mkdir(exist_ok=True);e.mkdir(exist_ok=True)
for p in (W/'scripts').iterdir():
 if p.is_file() and p.name!='recovery-functions.inc':shutil.copy2(p,out/p.name)
p=out/'scsi-prefix';p.mkdir(exist_ok=True)
for f in (W/'scripts/scsi-prefix').iterdir():
 if f.is_file():shutil.copy2(f,p/f.name)
shutil.copy2(W/'private/G80-pinned-plan.bin',out/'G80-pinned-plan.bin')
for name in ['fat-plan-preparation.json','bcd-semantic-audit.json','fat-files.json','gpt-plan-proof.json','firmware-source-changes.json','firmware-apply.json','firmware-undo.json','firmware-normal.json','native-qualification.json','sha256-native-vectors.json','msd-write-exit-evidence.json','persistent-boot-reference.json','boot-a-normal-plan.json','updater-native-inspect.json','host-assembly.json','debug-listener.json','debug-verified.json','debug-verified-r2.json','debug-firewall-inspect.json','debug-verified-r3.json','current-usb-and-kd.json','pe-helper-build.json','release.json','release-staged.json','package-transfer-limit.json','launch-ready.json','temporary-boot.json','native-enumeration.json','native-enumeration-2.json','first-write.json','first-write-proof.json']:
 p=W/'captures'/name
 if p.exists():shutil.copy2(p,e/name)
extra_names=['range-00052.json','range-04129.json','range-08142.json','apply-state.json','prefix-native-proof.json','commit-dispatch.json','commit-marker.json','handoff-reentry-diagnosis.json','normal-launch-ready.json','normal-temporary-boot.json','PE-probe.json','PE-readonly-baseline.json','PE-ESP-inspection.json','PE-BCD-selection.json','PE-BCD-sysstore-test.json','normal-boot-install-preflight.json','normal-boot-install.json','normal-boot-journal.json','normal-boot-post-boot_a.json','normal-boot-post-boot_b.json','normal-boot-install-proof.json','boot-before-transfer.json','native-files-setup-manifest.json','native-files-software-manifest.json','native-gpt-capture.json','native-gpt-proof.json','BCD-before-system-marker.json','BCD-system-marker-trial.json','BCD-marker-trial-proof.json','BCD-system-marker-native.json','BCD-system-marker-native-r2.json','BCD-marker-native-semantics.json','native-setup-replayed-copies.json','native-setup-replayed-copies-r2.json','native-setup-replayed-copies-r3.json','cold-boot-preflight.json','cold-boot-dispatch.json','cold-boot-new-session.json','cold-boot-system-store.json','native-outcome.json']
for name in extra_names:
 p=W/'captures'/name
 if p.exists():shutil.copy2(p,e/name)
(out/'README.txt').write_text((W/'scripts/README-G80.txt').read_text()+"\n\n"+(W/'scripts/NATIVE-OUTCOME.txt').read_text())
print('G80 source and sanitized preparation/native evidence exported')
