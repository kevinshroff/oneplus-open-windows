"""Create the G128 candidate from the retained, native-qualified G119 source."""
from pathlib import Path
import hashlib,json,shutil

w=Path(__file__).resolve().parent
base=w.parent/'charging-G119/private/candidate-source'
out=w/'private/candidate-source'
assert not out.exists()
shutil.copytree(base,out)
lib=out/'Platforms/AndromedaPkg/Library/DeviceBootManagerLib'
sha=lambda b:hashlib.sha256(b).hexdigest()
def edit(path,old,new):
    p=out/path;t=p.read_text();assert t.count(old)==1,(p,old)
    p.write_text(t.replace(old,new))
for name in ['OpenPilMetadataProbe.c','OpenPilMetadataProbe.h']:
    shutil.copyfile(w/name,lib/name)
shutil.copyfile(w/'private/bindings-01/OpenPilMetadataBindings.h',lib/'OpenPilMetadataBindings.h')
prefix=Path('Platforms/AndromedaPkg/Library/DeviceBootManagerLib')
edit(prefix/'DeviceBootManagerLib.inf','  OpenAdspPreflight.c\n','  OpenAdspPreflight.c\n  OpenPilMetadataProbe.c\n')
edit(prefix/'DeviceBootManagerLib.inf','  gEfiLoadedImageProtocolGuid\n','  gEfiLoadedImageProtocolGuid\n  gEfiMemoryAttributeProtocolGuid\n')
edit(prefix/'DeviceBootManagerLib.c',
     '        (FixedPcdGet32 (PcdOpenBringupMode) != 15)) {',
     '        (FixedPcdGet32 (PcdOpenBringupMode) != 15) &&\n        (FixedPcdGet32 (PcdOpenBringupMode) != 16)) {')
edit(prefix/'OpenBringupDiagnostics.c',
     'if (FixedPcdGet32 (PcdOpenBringupMode) == 15) {',
     'if (FixedPcdGet32 (PcdOpenBringupMode) == 15 || FixedPcdGet32 (PcdOpenBringupMode) == 16) {')
edit('Platforms/KailuaPkg/Device/oneplus-open/PcdsFixedAtBuild.dsc.inc',
     'PcdOpenBringupMode|15','PcdOpenBringupMode|16')
edit(prefix/'OpenAdspPreflight.c','#include "OpenSha256.h"',
     '#include "OpenSha256.h"\n#include "OpenPilMetadataProbe.h"')
edit(prefix/'OpenAdspPreflight.c',
     '  BOOLEAN Installed = FALSE, Connected = FALSE, Keep = FALSE;',
     '  BOOLEAN Installed = FALSE, Connected = FALSE, Keep = FALSE, ProbeCalled = FALSE;')
edit(prefix/'OpenAdspPreflight.c',
     '  Cleanup = CheckMetadata (V, Scratch, Check);\n  Report ("metadata_after status=%r\\n", Cleanup);',
     '''  // The original metadata helper resolves adsp_ro synchronously. Keep the
  // verified read-only facade connected through this call and its cleanup.
  { EFI_STATUS ProbeStatus = OpenRunPilMetadataProbe (
      MemoryStatus == EFI_SUCCESS && Status == EFI_SUCCESS && FilesStatus == EFI_SUCCESS &&
      V->Ro.DeniedWrites == 0 && V->Ro.Failures == 0 &&
      V->RequestedBytes <= READ_LIMIT - 1024*1024);
    ProbeCalled = TRUE;
    Report ("G128_metadata_publication status=%r\\n", ProbeStatus); }
  Cleanup = CheckMetadata (V, Scratch, Check);
  Report ("metadata_after status=%r\\n", Cleanup);''')
edit(prefix/'OpenAdspPreflight.c','Done:\n  if (Connected) {',
     '''Done:
  if (!ProbeCalled) {
    EFI_STATUS ProbeStatus = OpenRunPilMetadataProbe (FALSE);
    Report ("G128_inspection_publication status=%r\\n", ProbeStatus);
  }
  if (Connected) {''')
files={str(p.relative_to(out)):sha(p.read_bytes())for p in sorted(out.rglob('*'))if p.is_file()}
assert len(files)==12
(w/'private/candidate-source-hashes.json').write_text(json.dumps(files,indent=2)+'\n')
print(json.dumps({'files':len(files),'mode':16,'native_phone_operations':0,'DSP_start_requests':0}))
