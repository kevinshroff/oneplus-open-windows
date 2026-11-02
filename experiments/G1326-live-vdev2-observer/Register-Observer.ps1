# HOST ONLY. Registers one independent observer task; never starts it or touches a debugger.
param([switch]$RegisterReviewedObserver,[string]$Review,[string]$ReviewSha256)
$ErrorActionPreference='Stop'
if(!$RegisterReviewedObserver){'INERT: no task registration';return}
if((Get-FileHash -LiteralPath $Review -Algorithm SHA256).Hash.ToLowerInvariant() -cne $ReviewSha256){throw 'Exact reviewed settings required'}
$j=Get-Content -LiteralPath $Review -Raw|ConvertFrom-Json
if($j.schema -cne 'wifi-live-vdev2-local-observer/1' -or $j.accepted_local_observer_operation -cne $true){throw 'Inert or wrong observer selection'}
$observer=Join-Path $PSScriptRoot 'Observer.ps1'
if((Get-FileHash -LiteralPath $observer -Algorithm SHA256).Hash.ToLowerInvariant() -cne $j.observer_source_sha256){throw 'Observer source changed'}
if($Review.Contains('"') -or $observer.Contains('"')){throw 'Unsupported quote in selected path'}
$name='WiFi-LiveVdev2-Observer-Boot'+[string]$j.BootId
if(Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue){throw 'Existing observer task preserved; no replacement/retry'}
$who=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$action=New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$observer+'" -ExecuteReviewedObserver -Review "'+$Review+'" -ReviewSha256 '+$ReviewSha256)
$principal=New-ScheduledTaskPrincipal -UserId $who -LogonType Interactive -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$settings.AllowHardTerminate=$false
Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Settings $settings -ErrorAction Stop|Out-Null
[pscustomobject]@{task=$name;registered=$true;task_start_calls=0;debugger_calls=0;native_observer_calls=0;root_must_start_only_at_owned_qualified_module_load_hold=$true}|ConvertTo-Json -Compress
