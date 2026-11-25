# OnePlus Open — Adreno 740 Option 2 boot init (SYSTEM, at startup).
# Starts OpenSmmuD0 + topazgpu_opt2 (WDDM display+render KMD) so DWM and D3D11 apps run on the Adreno 740
# through ogpu_d3d10.dll. Crash guard: an unfinished previous start or a DWM crash loop disables the GPU path
# (C:\topaz\gpu.disable) and the desktop stays on Microsoft Basic Display. Delete gpu.disable to re-arm.
$ErrorActionPreference = "Continue"
$dir = "C:\topaz"; $log = "$dir\boot.log"; $pending = "$dir\gpu.boot.pending"; $disable = "$dir\gpu.disable"
function Log($m) { "$(Get-Date -f s) $m" | Out-File -Append -Encoding ascii $log }
$svc = "HKLM:\SYSTEM\CurrentControlSet\Services"
function Disarm { Set-ItemProperty "$svc\OpenSmmuD0" Start 4 -Type DWord; Set-ItemProperty "$svc\OpenGpuStart" Start 4 -Type DWord }
Disarm   # never let PnP start the GPU on its own at a later boot
# The system partition is small (~22 GB): drop dxgkrnl live dumps (1.7 GB each) left by earlier sessions.
Get-ChildItem C:\Windows\LiveKernelReports -Recurse -File -Filter *.dmp -EA SilentlyContinue |
    ForEach-Object { Log "removing live dump  ( MB)"; Remove-Item $_.FullName -Force -EA SilentlyContinue }
if (Test-Path $disable) { Log "gpu.disable present - staying on Basic Display"; exit 0 }
if (Test-Path $pending) {
    Log "previous GPU start never completed - disabling GPU path (delete $disable to re-arm)"
    Move-Item $pending $disable -Force; exit 0
}
Set-Content $pending (Get-Date -f s)
Start-Sleep -Seconds 8
if (Test-Path C:\TopazGpuW.log) { Move-Item C:\TopazGpuW.log C:\TopazGpuW.prev.log -Force }
Set-ItemProperty "$svc\OpenSmmuD0" Start 3 -Type DWord
Set-ItemProperty "$svc\OpenGpuStart" ImagePath "\SystemRoot\System32\drivers\topazgpu_opt2.sys" -Type ExpandString
Set-ItemProperty "$svc\OpenGpuStart" Start 3 -Type DWord
pnputil.exe /remove-device "ACPI\OPEN0182\1" | Out-Null
pnputil.exe /scan-devices | Out-Null
Start-Sleep -Seconds 15
Disarm
$dev = Get-PnpDevice -InstanceId 'ACPI\OPEN0515\0' -EA SilentlyContinue
Log "OPEN0515 status $($dev.Status); OpenGpuStart $((Get-Service OpenGpuStart).Status)"
$t0 = Get-Date
Start-Sleep -Seconds 45
$exits = (Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Dwminit'; StartTime=$t0} -EA SilentlyContinue | Measure-Object).Count
if ($exits -ge 3) {
    Log "DWM exited $exits times after GPU start - disabling GPU path and rebooting to Basic Display"
    Move-Item $pending $disable -Force
    shutdown.exe /r /t 10 /c "Adreno 740 GPU path disabled after DWM failures"
    exit 1
}
Remove-Item $pending -Force
Log "GPU start OK (DWM exits $exits)"
