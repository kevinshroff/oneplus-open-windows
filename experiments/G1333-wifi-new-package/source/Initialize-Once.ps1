# Task-owned matched package operation. Default inert. No old driver RVAs/observer.
param([switch]$ExecuteRootReviewedTask,[string]$Review,[string]$ReviewSha256)
$ErrorActionPreference='Stop';$global:ProgressPreference='SilentlyContinue'
if(!$ExecuteRootReviewedTask){'INERT: no install/init/scan/native calls';return}
if((Get-FileHash $Review).Hash.ToLowerInvariant() -cne $ReviewSha256){throw 'Exact reviewed future task required'}
$j=Get-Content $Review -Raw|ConvertFrom-Json
if($j.schema -cne 'G1333-matched4478-once-review/1' -or $j.accepted_matched_package_selection_init_scan -cne $true -or $j.accepted_future_Start4_fence -cne $true -or $j.accepted_copy_install_new_signed_package -cne $true){throw 'Inert/unaccepted task'}
foreach($name in @('SingleInfSelector.cs','ScanAndCache.cs','Policy.ps1','Initialize-Once.ps1','Launch-FutureTask.ps1','Native-Compile-Only.ps1')){if($j.source_sha256.$name -cnotmatch '^[0-9a-f]{64}$'){throw 'Required exact source binding absent'}}
$sourcePins=Join-Path $PSScriptRoot 'SOURCE-PINS.json';if((Get-FileHash $sourcePins).Hash.ToLowerInvariant() -cne $j.source_pins_sha256){throw 'Exact frozen source/package pins changed'}
$expected=Get-Content $sourcePins -Raw|ConvertFrom-Json
foreach($f in $expected.matched_package_files.PSObject.Properties){if($j.package_sha256.($f.Name) -cne $f.Value){throw 'Complete matched package manifest differs'}}
foreach($f in $expected.generic_runtime_files.PSObject.Properties){if($j.installed_member_sha256.($f.Name) -cne $f.Value){throw 'Matched generic runtime manifest differs'}}
foreach($f in $j.source_sha256.PSObject.Properties){if([IO.Path]::GetFileName($f.Name) -cne $f.Name -or (Get-FileHash (Join-Path $PSScriptRoot $f.Name)).Hash.ToLowerInvariant() -cne $f.Value){throw 'Source changed'}}
. (Join-Path $PSScriptRoot 'Policy.ps1')
Assert-FreshNormal $j
$compile=Get-Content (Join-Path $PSScriptRoot 'native-compile-result.json') -Raw|ConvertFrom-Json
Need ((Hash (Join-Path $PSScriptRoot 'native-compile-result.json')) -ceq $j.native_compile_result_sha256 -and $compile.native_CS_compiled -eq 2 -and $compile.device_calls -eq 0 -and $compile.runtime_approval -ceq $false) 'Actual native compile/layout/default-inert qualification required'
foreach($f in $j.source_sha256.PSObject.Properties){Need ($compile.source_sha256.($f.Name) -ceq $f.Value) 'Native source qualification does not cover these exact bytes'}
Need ($compile.default_inert_scripts -eq 2 -and $compile.flag_policy_test_pass -ceq $true) 'Native flag/default-inert qualification missing'
Need ($j.root_qualifies_actual_no_old_or_new_WLAN_loaded -ceq $true -and $j.root_qualifies_no_old_breakpoints_or_observer -ceq $true) 'Actual fresh module absence and ordinary debugger prerequisite'
foreach($name in @('OpenGpuStart','OpenSmmuD0','qcwlan')){Need ((Get-ItemProperty ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$name)).Start -eq 4 -and [string](Get-Service $name).Status -ceq 'Stopped') ('Initial startup fence changed '+$name)}
Need ([string](Get-Service OpenG184).Status -ceq 'Running') 'Parent must be admitted running before task'
foreach($f in $j.package_sha256.PSObject.Properties){Need ([IO.Path]::GetFileName($f.Name) -ceq $f.Name -and (Hash (Join-Path $j.package_directory $f.Name)) -ceq $f.Value) ('Matched member changed '+$f.Name)}
Need ((Get-AuthenticodeSignature (Join-Path $j.package_directory 'qcwlanhmt8380.sys')).Status -eq 'Valid' -and (Get-AuthenticodeSignature (Join-Path $j.package_directory 'qcwlanhmt8380.cat')).Status -eq 'Valid') 'Exact signed source SYS/CAT required'
Need ((Hash (Join-Path $j.package_directory 'qcwlanhmt8380.inf')) -ceq '3141acb9146b3dcff0a01f09a5b4abc6cd8c272725f30c6e997d3c6a415d3bbb') 'Exact new INF required'
$marker=Join-Path $PSScriptRoot ('G1333-Boot-'+$j.BootId+'-matched4478.once.json')
function Journal([string]$kind,[int]$installs,[int]$scans){$o=[ordered]@{schema='matched4478-caller-journal/1';kind=$kind;BootId=$j.BootId;phone_session=$j.phone_session;root_nonce=$j.root_nonce;phone_utc=[DateTimeOffset]::UtcNow.ToString('o');install_callsite_attempts=$installs;explicit_scan_callsite_attempts=$scans;callee_entry_not_independently_observed=$true};New-Json (Join-Path $PSScriptRoot ('caller-'+$kind+'.json')) $o}
function New-Json([string]$path,$value){$raw=[Text.Encoding]::UTF8.GetBytes(($value|ConvertTo-Json -Depth 12 -Compress)+"`n");$f=[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough);try{$f.Write($raw,0,$raw.Length);$f.Flush($true)}finally{$f.Dispose()}}
New-Json $marker ([ordered]@{BootId=$j.BootId;review_sha256=$ReviewSha256;install_calls_max=1;explicit_scan_calls_max=1;cached_list_queries_max=1;connect_requests=0;automatic_retry=$false})
$n=$null;$before=$null;$after=$null;$binding=$null;$install=$null;$scan=$null;$cache=$null;$selection=$null;$stage=$null;$installedFiles=$null;$errorText=$null;$fence=$null
try{
 $before=Read-Policy $j.instance_id;Need $before.expected_policy_matches 'Current typed policy/ASPM0 guard changed';Journal 'before-selection' 0 0
 Add-Type -TypeDefinition (Get-Content (Join-Path $PSScriptRoot 'SingleInfSelector.cs') -Raw)
 Add-Type -TypeDefinition (Get-Content (Join-Path $PSScriptRoot 'ScanAndCache.cs') -Raw)
 # Do NOT enable the old service before selecting the new INF. DiInstallDevice
 # is the one selected package copy/install/init; no extra start/restart call.
 $stage=[Matched4478Selector]::StagePackageOnce([string](Join-Path $j.package_directory 'qcwlanhmt8380.inf'));New-Json (Join-Path $PSScriptRoot 'package-stage-return.json') $stage
 $n=[Matched4478Selector]::new([string]$j.instance_id,[string]$stage.driverStoreInf)
 $selection=[pscustomobject]@{version=('{0:x16}' -f $n.Version);Inf=$n.SelectedDetail.InfFile;InfSHA256=$n.InfSha256;section=$n.SelectedDetail.Section;resolvedSection=$n.ResolvedSection;Flags=$n.Parameters.Flags;FlagsEx=$n.Parameters.FlagsEx;DriverPath=$n.Parameters.DriverPath}
 New-Json (Join-Path $PSScriptRoot 'selection-diagnostics.json') ([pscustomobject]@{actualDetailInf=$n.ActualDetailInfPath;detailInfSHA256=$n.InfSha256;normalizedDetailInf=$n.NormalizedDetailInfPath;normalizedExpectedInf=$n.NormalizedExpectedInfPath;normalizedDetailSHA256=$n.NormalizedDetailInfSHA256;candidateError=$n.CandidateError;version=$selection.version;section=$selection.section;resolvedSection=$selection.resolvedSection})
 Need ([string]::IsNullOrEmpty($n.CandidateError)) ([string]$n.CandidateError)
 Journal 'invoke-once-callsite-begin' 1 0;$install=$n.InvokeOnce();Journal 'invoke-once-return' 1 0
 New-Json (Join-Path $PSScriptRoot 'driver-return.json') $install
 Need ($install.success -ceq $true -and $install.calls -eq 1 -and $install.NeedReboot -ceq $false) 'Install failed/reboot required; stop further actions, no retry/reboot'
 $binding=Read-Binding $j.instance_id;$after=Read-Policy $j.instance_id;Need $after.expected_policy_matches 'Installation changed policy/ASPM0; recorded, no restoration or further actions'
 Need ($binding.InfSHA256 -ceq '3141acb9146b3dcff0a01f09a5b4abc6cd8c272725f30c6e997d3c6a415d3bbb' -and $binding.version -ceq '1.0.4478.2200' -and $binding.image_sha256 -ceq 'f59d9e98bb736ccd78aa4ebd569616456fa0f09bf345a7b1002b0105693aeeef' -and $binding.serviceState -ceq 'Running') 'Actual new package binding/state differs'
 $installedFiles=[ordered]@{};$runtimeDirectory=Split-Path -Parent $binding.image
 foreach($f in $j.installed_member_sha256.PSObject.Properties){Need ([IO.Path]::GetFileName($f.Name) -ceq $f.Name) 'Runtime member path refused';$path=Join-Path $runtimeDirectory $f.Name;$actual=Hash $path;$installedFiles[$f.Name]=$actual;Need ($actual -ceq $f.Value) ('Matched installed SYS/FW/BDF member differs '+$f.Name)}
 $adapters=@(Get-CimInstance Win32_NetworkAdapter|Where-Object {$_.PNPDeviceID -ieq $j.instance_id -and $_.GUID});Need ($adapters.Count -eq 1) 'One actual postinstall interface GUID mapped to exact PCI instance required';$guid=[guid]$adapters[0].GUID
 Journal 'explicit-scan-callsite-begin' 1 1;$scan=[G1333ScanAndCache]::ScanOnce($guid)
 # One cached available-list query, zero additional active scans. SSIDs remain private.
 $cache=[G1333ScanAndCache]::CachedList($guid)
} catch{$errorText=$_.Exception.Message}
finally{
 if($null -ne $n){$n.Dispose()}
 try{& sc.exe config qcwlan start= disabled|Out-Null;Need ($LASTEXITCODE -eq 0 -and (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\qcwlan').Start -eq 4) 'Future Start4 fence failed';$fence=[pscustomobject]@{Start=4;State=[string](Get-Service qcwlan).Status;stop_calls=0}}catch{$fence=[pscustomobject]@{error=$_.Exception.Message}}
 New-Json (Join-Path $PSScriptRoot 'outcome.json') ([ordered]@{schema='matched4478-one-init-one-scan-outcome/1';BootId=$j.BootId;phone_session=$j.phone_session;root_nonce=$j.root_nonce;driverReturn=$install;packageStage=$stage;selectedDriver=$selection;policyBefore=$before;policyAfter=$after;bindingAfter=$binding;installedRuntimeFileHashes=$installedFiles;RAM_firmware_cache_hash_verified=$false;scan=$scan;cachedNetworks=$cache;error=$errorText;futureFence=$fence;native_init_calls_max=1;explicit_scan_calls_max=1;extra_diagnostic_API_calls=0;full_ETW_started=$false;old_SYS_breakpoints_or_offsets_used=$false;automatic_reboot=$false;connect_requests=0})
}
if($null -ne $errorText -or $null -ne $fence.error){exit 1}
