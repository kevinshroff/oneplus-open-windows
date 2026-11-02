"""Prepare a separate G155-derived image, adding only supplementary ACPI publication."""
from pathlib import Path
import hashlib,json,shutil
w=Path(__file__).resolve().parent;p=w/'private';o=p/'firmware-source';old=w.parent/'charging-G155';assert not o.exists()
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
prior=json.loads((old/'private/candidate-source-hashes.json').read_text());s=old/'private/candidate-source'
assert {str(f.relative_to(s)):sha(f)for f in s.rglob('*')if f.is_file()}==prior
shutil.copytree(s,o)
lib=o/'Platforms/AndromedaPkg/Library/DeviceBootManagerLib'
b=(p/'verify-01/OPRES182.aml').read_bytes();assert len(b)==376 and sum(b)%256==0
(lib/'OpenPlatformResourcesAml.h').write_text('/* Generated from the verified G182 supplementary SSDT. */\nstatic CONST UINT8 mPlatformResources[] = {\n'+''.join(' '+','.join('0x%02x'%x for x in b[i:i+16])+',\n'for i in range(0,len(b),16))+'};\n')
(lib/'OpenPlatformResources.c').write_text('''/* Supplemental resource description only: no hardware or partition writes. */
#include <Uefi.h>
#include <Protocol/AcpiTable.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include "OpenPlatformResourcesAml.h"
VOID OpenPublishPlatformResources(VOID)
{
 STATIC BOOLEAN Attempted = FALSE;
 EFI_ACPI_TABLE_PROTOCOL *Acpi;
 EFI_STATUS Status;
 VOID *Copy;
 UINTN Key = 0, I;
 UINT8 Sum = 0;
 if (Attempted) { return; }
 Attempted = TRUE;
 for (I = 0; I < sizeof(mPlatformResources); I++) { Sum = (UINT8)(Sum + mPlatformResources[I]); }
 if (Sum != 0 || sizeof(mPlatformResources) != 376) { return; }
 Status = gBS->LocateProtocol(&gEfiAcpiTableProtocolGuid, NULL, (VOID **)&Acpi);
 if (EFI_ERROR(Status)) { return; }
 Copy = AllocateCopyPool(sizeof(mPlatformResources), mPlatformResources);
 if (Copy == NULL) { return; }
 Status = Acpi->InstallAcpiTable(Acpi, Copy, sizeof(mPlatformResources), &Key);
 FreePool(Copy);
 DEBUG((DEBUG_INFO, "G182 supplementary resources status=%r bytes=376 producer_qualified=0\\n", Status));
}
''')
f=lib/'DeviceBootManagerLib.inf';text=f.read_text();assert text.count('  DeviceBootManagerLib.c\n')==1;f.write_text(text.replace('  DeviceBootManagerLib.c\n','  DeviceBootManagerLib.c\n  OpenPlatformResources.c\n'))
f=lib/'DeviceBootManagerLib.c';text=f.read_text();needle='  MsBootOptionsLibRegisterDefaultBootOptions ();';assert text.count(needle)==1;f.write_text(text.replace('VOID OpenBringupDiagnostics (VOID);','VOID OpenBringupDiagnostics (VOID);\nVOID OpenPublishPlatformResources (VOID);').replace(needle,'  OpenPublishPlatformResources ();\n'+needle))
manifest={str(f.relative_to(o)):sha(f)for f in o.rglob('*')if f.is_file()}
changed={n for n,h in prior.items()if manifest[n]!=h};assert {Path(n).name for n in changed}=={'DeviceBootManagerLib.inf','DeviceBootManagerLib.c'}
assert {Path(n).name for n in manifest.keys()-prior.keys()}=={'OpenPlatformResources.c','OpenPlatformResourcesAml.h'}
(p/'firmware-source.json').write_text(json.dumps({'prior':prior,'candidate':manifest,'changed':sorted(changed),'added':sorted(manifest.keys()-prior.keys()),'AML_sha256':hashlib.sha256(b).hexdigest(),'native_operations':0},indent=2)+'\n')
print({'unchanged_G155_sources':len(prior)-len(changed),'modified':len(changed),'added':2,'native_phone_operations':0})
