# Registers one task; never starts it directly or calls a driver/WLAN API.
param([switch]$RegisterRootReviewedFutureTask,[string]$Review,[string]$ReviewSha256,[string]$FutureStartUtc)
$ErrorActionPreference='Stop'
if(!$RegisterRootReviewedFutureTask){'INERT: no task registration or device access';return}
if((Get-FileHash $Review).Hash.ToLowerInvariant() -cne $ReviewSha256){throw 'Exact reviewed settings required'}
$j=Get-Content $Review -Raw|ConvertFrom-Json
if($j.accepted_matched_package_selection_init_scan -cne $true -or $j.accepted_future_Start4_fence -cne $true -or $j.accepted_copy_install_new_signed_package -cne $true){throw 'Inert task selection'}
foreach($name in @('SingleInfSelector.cs','ScanAndCache.cs','Policy.ps1','Initialize-Once.ps1','Launch-FutureTask.ps1','Native-Compile-Only.ps1')){if($j.source_sha256.$name -cnotmatch '^[0-9a-f]{64}$'){throw 'Required exact source binding absent'}}
$sourcePins=Join-Path $PSScriptRoot 'SOURCE-PINS.json';if((Get-FileHash $sourcePins).Hash.ToLowerInvariant() -cne $j.source_pins_sha256){throw 'Exact frozen source/package pins changed'}
$expected=Get-Content $sourcePins -Raw|ConvertFrom-Json
foreach($f in $expected.matched_package_files.PSObject.Properties){if($j.package_sha256.($f.Name) -cne $f.Value){throw 'Complete matched package manifest differs'}}
foreach($f in $expected.generic_runtime_files.PSObject.Properties){if($j.installed_member_sha256.($f.Name) -cne $f.Value){throw 'Matched generic runtime manifest differs'}}
foreach($f in $j.source_sha256.PSObject.Properties){if([IO.Path]::GetFileName($f.Name) -cne $f.Name -or (Get-FileHash (Join-Path $PSScriptRoot $f.Name)).Hash.ToLowerInvariant() -cne $f.Value){throw 'Source changed'}}
. (Join-Path $PSScriptRoot 'Policy.ps1');Assert-FreshNormal $j
$compilePath=Join-Path $PSScriptRoot 'native-compile-result.json';$compile=Get-Content $compilePath -Raw|ConvertFrom-Json
Need ((Hash $compilePath) -ceq $j.native_compile_result_sha256 -and $compile.native_CS_compiled -eq 2 -and $compile.default_inert_scripts -eq 2 -and $compile.flag_policy_test_pass -ceq $true -and $compile.device_calls -eq 0) 'Native source/flag/default-inert qualification required before registration'
Need ($j.root_qualifies_actual_no_old_or_new_WLAN_loaded -ceq $true -and $j.root_qualifies_no_old_breakpoints_or_observer -ceq $true) 'Root actual fresh module/debugger admission required'
foreach($name in @('OpenGpuStart','OpenSmmuD0','qcwlan')){Need ((Get-ItemProperty ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$name)).Start -eq 4 -and [string](Get-Service $name).Status -ceq 'Stopped') 'Future task requires disabled/stopped initial state'}
$policy=Read-Policy $j.instance_id;Need $policy.expected_policy_matches 'Current typed policy/ASPM0 changed'
$when=[DateTimeOffset]::Parse($FutureStartUtc);$delay=($when-[DateTimeOffset]::UtcNow).TotalSeconds;Need ($delay -ge 30 -and $delay -le 120) 'Future task trigger must be30..120seconds away'
$name='Open-WiFi4478-Boot'+[string]$j.BootId;if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Preserve existing task; no replay'}
$script=Join-Path $PSScriptRoot 'Initialize-Once.ps1';if($Review.Contains('"') -or $script.Contains('"')){throw 'Quote in selected path refused'}
$marker=Join-Path $PSScriptRoot ('future-task-Boot'+$j.BootId+'.once.json');$f=[IO.File]::Open($marker,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read);try{$raw=[Text.Encoding]::UTF8.GetBytes(($j.root_nonce+"`n"+$ReviewSha256));$f.Write($raw,0,$raw.Length);$f.Flush($true)}finally{$f.Dispose()}
$action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$script+'" -ExecuteRootReviewedTask -Review "'+$Review+'" -ReviewSha256 '+$ReviewSha256)
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries;$settings.AllowHardTerminate=$false
$trigger=New-ScheduledTaskTrigger -Once -At $when.LocalDateTime
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -ErrorAction Stop|Out-Null
[pscustomobject]@{BootId=$j.BootId;phone_session=$j.phone_session;task=$name;registered=$true;task_start_calls=0;driver_calls=0;scan_calls=0;future_start_utc=$when.ToUniversalTime().ToString('o');hard_terminate_allowed=$false}|ConvertTo-Json -Compress
