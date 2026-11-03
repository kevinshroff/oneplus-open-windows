# Default inert. Root supplies actual fresh epoch, signed-image and qualification evidence.
param([switch]$ExecuteRootReviewedQuery,[string]$Review,[string]$ReviewSha256)
$ErrorActionPreference='Stop'
if(!$ExecuteRootReviewedQuery){'INERT: no device open or driver queries';return}
function Need($x,$m){if(!$x){throw $m}}
function Hash($p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
Need ((Hash $Review) -ceq $ReviewSha256) 'Exact review required';$j=Get-Content $Review -Raw|ConvertFrom-Json
Need ($j.schema -ceq 'G1340-native-CE-getter-review/1' -and $j.accept_query_once -ceq $true -and $j.root_current_same_session -ceq $true -and $j.root_loaded_getter_identity_and_no_unload -ceq $true -and $j.root_signed_payload_independently_verified -ceq $true -and $j.BootId -gt 171 -and $j.phone_session -cmatch '^[0-9a-f]{32}$' -and $j.root_nonce -cmatch '^[0-9a-f]{32}$') 'Fresh explicitly reviewed getter operation required'
Need ($j.query_mode -ceq 'statusHP-first-only' -or ($j.query_mode -ceq 'first-four-status-first' -and $j.accept_first_four -ceq $true)) 'Only selected first query or bounded first four permitted'
foreach($n in @('CeGetter.cs','Query-Once.ps1','Native-Compile-Only.ps1')){Need ((Hash (Join-Path $PSScriptRoot $n)) -ceq $j.source_sha256.$n) 'Exact reviewed source changed'}
foreach($n in @('signed-content-review.json','native-compile-result.json')){Need ((Hash (Join-Path $PSScriptRoot $n)) -ceq $j.receipt_sha256.$n) 'Exact actual qualification receipt required'}
$c=Get-Content (Join-Path $PSScriptRoot 'native-compile-result.json') -Raw|ConvertFrom-Json;Need ($c.codec_pass -ceq $true -and $c.device_calls -eq 0 -and $c.default_inert -ceq $true -and $c.runtime_approval -ceq $false -and $c.source_sha256.'CeGetter.cs' -ceq $j.source_sha256.'CeGetter.cs' -and $c.source_sha256.'Query-Once.ps1' -ceq $j.source_sha256.'Query-Once.ps1') 'Native exact-source qualification required'
$s=Get-Content (Join-Path $PSScriptRoot 'signed-content-review.json') -Raw|ConvertFrom-Json;Need ($s.signed_sha256 -ceq $j.signed_driver_sha256 -and $s.unsigned_sha256 -ceq '2a0d977055dd6e8e59cbad80f2e3462d6e1e2d6a62d88f18a0753504d60e8495' -and $s.unsigned_payload_unchanged -ceq $true -and $s.cms_RSA_SHA256_math -ceq $true -and $s.signed_content_digest_matches_PE -ceq $true -and $s.existing_project_signer -ceq $true) 'Actual independently verified signed getter required'
foreach($n in @('OpenGpuStart','OpenSmmuD0')){Need ((Get-ItemProperty ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$n)).Start -eq 4 -and [string](Get-Service $n).Status -ceq 'Stopped') 'GPU and broker remain stopped/disabled'}
$v=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\OpenGpuStart';foreach($n in @('BootstrapOnce','CpInitFenceOnce','ScmApertureOnce')){Need ($v.$n -eq 0) 'GPU once flags armed'}
Need ([string](Get-Service OpenG184).Status -ceq 'Running' -and $j.root_broker_flags_zero -ceq $true) 'Admitted parent/broker flags required'
$dev=@(Get-PnpDevice -PresentOnly|Where-Object {$_.InstanceId -like 'PCI\VEN_17CB&DEV_1107*'});Need ($dev.Count -eq 1 -and $dev[0].InstanceId -ceq $j.instance_id) 'Exact current WLAN PCI instance required'
Need ((Get-PnpDeviceProperty -InstanceId $j.instance_id -KeyName 'DEVPKEY_Device_Service').Data -ceq 'qcwlan' -and (Get-PnpDeviceProperty -InstanceId $j.instance_id -KeyName 'DEVPKEY_Device_DriverVersion').Data -ceq '1.0.4478.2200') 'Exact PCI service/version binding required'
$dir=[IO.Path]::GetFullPath($j.output_directory);Need (!(Test-Path $dir)) 'Preserve existing output/nonce; no replay';$null=New-Item -ItemType Directory -Path $dir
# All runtime guards precede the first device open. Directory creation is the one-attempt marker.
Add-Type -TypeDefinition (Get-Content (Join-Path $PSScriptRoot 'CeGetter.cs') -Raw)
$r=$null;$errorText=$null
try{$r=[G1340CeGetter]::Once($true,[uint32]$j.BootId,[string]$j.signed_driver_sha256,[string]$j.selected_runtime_image,($j.query_mode -ceq 'first-four-status-first'))}catch{$errorText=$_.Exception.Message}
$o=[ordered]@{schema='G1340-native-getter-outcome/1';BootId=$j.BootId;phone_session=$j.phone_session;root_nonce=$j.root_nonce;review_sha256=$ReviewSha256;result=$r;error=$errorText;init_calls=0;WLAN_scan_calls=0;profile_writes=0;automatic_retry=$false;effective_cache_policy_verified=$false}
$raw=[Text.Encoding]::UTF8.GetBytes(($o|ConvertTo-Json -Depth 12 -Compress)+"`n");$f=[IO.File]::Open((Join-Path $dir 'outcome.json'),[IO.FileMode]::CreateNew);try{$f.Write($raw,0,$raw.Length);$f.Flush($true)}finally{$f.Dispose()}
$o|ConvertTo-Json -Depth 12 -Compress
