# HOST OR TARGET SOURCE QUALIFICATION ONLY. No constructor, selection, driver/API calls.
param([switch]$CompileReviewedSource,[string]$SourcePinsSha256)
$ErrorActionPreference='Stop'
if(!$CompileReviewedSource){'INERT: no compilation or native calls';return}
$p=Join-Path $PSScriptRoot 'SOURCE-PINS.json'
if((Get-FileHash $p).Hash.ToLowerInvariant() -cne $SourcePinsSha256){throw 'Exact root-reviewed source pins required'}
$m=Get-Content $p -Raw|ConvertFrom-Json
foreach($f in $m.sources.PSObject.Properties){if([IO.Path]::GetFileName($f.Name) -cne $f.Name -or (Get-FileHash (Join-Path $PSScriptRoot $f.Name)).Hash.ToLowerInvariant() -cne $f.Value){throw 'Frozen source member changed'}}
foreach($n in @('SingleInfSelector.cs','ScanAndCache.cs')){if((Get-FileHash (Join-Path $PSScriptRoot $n)).Hash.ToLowerInvariant() -cne $m.sources.$n){throw 'Source changed'};Add-Type -TypeDefinition (Get-Content (Join-Path $PSScriptRoot $n) -Raw)}
$parsed=@();foreach($n in @('Initialize-Once.ps1','Launch-FutureTask.ps1','Policy.ps1')){$t=$null;$e=$null;$null=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $n),[ref]$t,[ref]$e);if($e.Count){throw ('Native PS parse failed '+$n)};$parsed+=,$n}
foreach($n in @('Initialize-Once.ps1','Launch-FutureTask.ps1')){$out=[string](& (Join-Path $PSScriptRoot $n)|Out-String);if($out -notlike 'INERT:*'){throw 'Default script not inert'}}
$flags=[Matched4478Selector]::SelectionFlags([uint32]0x01800000);$flagsEx=[Matched4478Selector]::SelectionFlagsEx([uint32]0x04000000);if($flags -ne [uint32]0x00810000 -or $flagsEx -ne [uint32]0x00000800){throw 'Single-INF/copy-enabled/installed-only-cleared policy failed'}
$selector=[Matched4478Selector]::LayoutOnly();$scan=[G1333ScanAndCache]::LayoutOnly()
if($selector.pointer_bytes -ne 8 -or $selector.DEV_bytes -ne 32 -or $selector.PARAMS_bytes -ne 584 -or $selector.DRIVER_bytes -ne 1568 -or $selector.DETAIL_bytes -ne 1584 -or $scan.notification_bytes -ne 40 -or $scan.cached_network_bytes -ne 628){throw 'Native64 layouts differ'}
[pscustomobject]@{schema='G1333-matched4478-source-native-compile/1';native_CS_compiled=2;native_PS_parsed=$parsed;default_inert_scripts=2;source_sha256=$m.sources;flag_policy_test_pass=$true;selector_layout=$selector;scan_layout=$scan;constructors_invoked=0;SetupAPI_calls=0;driver_install_calls=0;WLAN_calls=0;device_calls=0;runtime_approval=$false;live_new_package_qualification=$false}|ConvertTo-Json -Depth 6 -Compress
