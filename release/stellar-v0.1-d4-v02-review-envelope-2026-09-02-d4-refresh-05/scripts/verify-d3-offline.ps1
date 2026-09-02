[CmdletBinding()]
param([string]$EvidenceDirectory=(Join-Path $PSScriptRoot '..\..\evidence\d3-v02-build'))
$ErrorActionPreference='Stop'
function Get-Sha256Hex([string]$LiteralPath){
  $stream=[IO.File]::Open($LiteralPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
  $sha=[Security.Cryptography.SHA256]::Create()
  try { return [Convert]::ToHexString($sha.ComputeHash($stream)).ToLowerInvariant() }
  finally { $sha.Dispose(); $stream.Dispose() }
}
$vswhere="${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if(-not(Test-Path -LiteralPath $vswhere)){throw 'T7D_D3_MSVC_NOT_FOUND'}
$install=& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$devcmd=Join-Path $install 'Common7\Tools\VsDevCmd.bat'
$source=Resolve-Path (Join-Path $PSScriptRoot '..\src')
$resolvedEvidence=[IO.Path]::GetFullPath($EvidenceDirectory)
New-Item -ItemType Directory -Path $resolvedEvidence -Force|Out-Null
$generatedDirectories=@('pass-1','pass-2','reproducible-path','linked-services')
foreach($generatedName in $generatedDirectories){
  if([IO.Path]::GetFileName($generatedName)-ne $generatedName){throw 'T7D_D3_INVALID_GENERATED_DIRECTORY'}
  $generatedPath=[IO.Path]::GetFullPath((Join-Path $resolvedEvidence $generatedName))
  $evidencePrefix=$resolvedEvidence.TrimEnd([IO.Path]::DirectorySeparatorChar)+[IO.Path]::DirectorySeparatorChar
  if(-not $generatedPath.StartsWith($evidencePrefix,[StringComparison]::OrdinalIgnoreCase)){throw 'T7D_D3_GENERATED_DIRECTORY_ESCAPE'}
  if(Test-Path -LiteralPath $generatedPath){Remove-Item -LiteralPath $generatedPath -Recurse -Force}
}
$sources=@('canonical_json.cpp','custodian_gateway_policy.cpp','custodian_request_signer_registry.cpp','lab_gateway_bridge.cpp','protected_installed_artifact.cpp','key_custody.cpp','durable_state.cpp','gateway_pipe_client.cpp','scm_readiness.cpp','provision_keys.cpp','startup_gate_sequence.cpp')
$buildHashes=@()
$repro=Join-Path $resolvedEvidence 'reproducible-path'
New-Item -ItemType Directory -Path $repro -Force|Out-Null
foreach($pass in 1,2){
  $out=Join-Path $resolvedEvidence "pass-$pass"
  New-Item -ItemType Directory -Path $out -Force|Out-Null
  Get-ChildItem -LiteralPath $repro -Filter *.obj -ErrorAction SilentlyContinue|Remove-Item -Force
  foreach($name in $sources){
    $input=Join-Path $source $name;$object=Join-Path $repro ($name -replace '\.cpp$','.obj')
    $command='"'+$devcmd+'" -arch=x64 -host_arch=x64 >nul && cl.exe /nologo /std:c++20 /W4 /WX /EHsc /guard:cf /DUNICODE /D_UNICODE /Brepro /c "'+$input+'" /Fo"'+$object+'"'
    cmd.exe /d /s /c $command
    if($LASTEXITCODE){throw "T7D_D3_BUILD_FAILED: $name"}
  }
  $hashes=@{};Get-ChildItem -LiteralPath $repro -Filter *.obj|Sort-Object Name|ForEach-Object{$hashes[$_.Name]=Get-Sha256Hex $_.FullName;Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $out $_.Name) -Force}
  $buildHashes+=,$hashes
}
foreach($name in $buildHashes[0].Keys){if($buildHashes[0][$name] -ne $buildHashes[1][$name]){throw "T7D_D3_BREPRO_MISMATCH: $name"}}
$selfTest=Join-Path $repro 'canonical-json-selftest.exe'
$selfSource=Join-Path $source 'canonical_json_selftest.cpp';$parserSource=Join-Path $source 'canonical_json.cpp'
$command='"'+$devcmd+'" -arch=x64 -host_arch=x64 >nul && cl.exe /nologo /std:c++20 /W4 /WX /EHsc /guard:cf /DUNICODE /D_UNICODE /Brepro /Fo"'+$repro+'\\" "'+$parserSource+'" "'+$selfSource+'" /link /OUT:"'+$selfTest+'" /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /CETCOMPAT'
cmd.exe /d /s /c $command;if($LASTEXITCODE){throw 'T7D_D3_CANONICAL_JSON_SELFTEST_BUILD_FAILED'}
& $selfTest;if($LASTEXITCODE){throw "T7D_D3_CANONICAL_JSON_SELFTEST_FAILED: $LASTEXITCODE"}
$durableTest=Join-Path $repro 'durable-state-selftest.exe';$durableSource=Join-Path $source 'durable_state.cpp';$durableTestSource=Join-Path $source 'durable_state_selftest.cpp';$gatewaySource=Join-Path $source 'gateway_pipe_client.cpp';$runtimeSource=Join-Path $source 'service_runtime.cpp';$commonSource=Join-Path $source 'service_common.cpp'
$predicateSource=Join-Path $source 'startup_gate_sequence.cpp'
$command='"'+$devcmd+'" -arch=x64 -host_arch=x64 >nul && cl.exe /nologo /std:c++20 /W4 /WX /EHsc /guard:cf /DUNICODE /D_UNICODE /Brepro /Fo"'+$repro+'\\" "'+$parserSource+'" "'+$durableSource+'" "'+$gatewaySource+'" "'+$runtimeSource+'" "'+$commonSource+'" "'+$predicateSource+'" "'+$durableTestSource+'" /link /OUT:"'+$durableTest+'" /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /CETCOMPAT'
cmd.exe /d /s /c $command;if($LASTEXITCODE){throw 'T7D_D3_DURABLE_SELFTEST_BUILD_FAILED'}
& $durableTest;if($LASTEXITCODE){throw "T7D_D3_DURABLE_SELFTEST_FAILED: $LASTEXITCODE"}
$harnesses=@('gateway_protocol_selftest','custodian_gateway_policy_selftest','custodian_issuance_contract_selftest','lab_gateway_bridge_selftest','protected_installed_artifact_selftest','key_custody_selftest','scm_predicate_selftest','startup_gate_selftest')
$harnessResults=[ordered]@{}
foreach($harness in $harnesses){$exe=Join-Path $repro "$harness.exe";$main=Join-Path $source "$harness.cpp";$deps=switch($harness){'gateway_protocol_selftest' {@('gateway_pipe_client.cpp','canonical_json.cpp','durable_state.cpp','service_runtime.cpp','service_common.cpp','startup_gate_sequence.cpp')};'custodian_gateway_policy_selftest' {@('custodian_gateway_policy.cpp','canonical_json.cpp','service_runtime.cpp','service_common.cpp','startup_gate_sequence.cpp')};'custodian_issuance_contract_selftest' {@('canonical_json.cpp','custodian_request_signer_registry.cpp')};'lab_gateway_bridge_selftest' {@('lab_gateway_bridge.cpp','canonical_json.cpp')};'protected_installed_artifact_selftest' {@('protected_installed_artifact.cpp','canonical_json.cpp')};'key_custody_selftest' {@('key_custody.cpp')};'scm_predicate_selftest' {@('scm_readiness.cpp')};default {@('startup_gate_sequence.cpp')}};$inputs=@($deps|ForEach-Object{'"'+(Join-Path $source $_)+'"'});$inputs+='"'+$main+'"';$command='"'+$devcmd+'" -arch=x64 -host_arch=x64 >nul && cl.exe /nologo /std:c++20 /W4 /WX /EHsc /guard:cf /DUNICODE /D_UNICODE /Brepro /Fo"'+$repro+'\\" '+($inputs -join ' ')+' /link /OUT:"'+$exe+'" /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /CETCOMPAT';cmd.exe /d /s /c $command;if($LASTEXITCODE){throw "T7D_D3_HARNESS_BUILD_FAILED: $harness"};& $exe;if($LASTEXITCODE){throw "T7D_D3_HARNESS_FAILED: $harness ($LASTEXITCODE)"};$harnessResults[$harness]='passed'}
$serviceOut=Join-Path $resolvedEvidence 'linked-services';New-Item -ItemType Directory -Path $serviceOut -Force|Out-Null
$serviceHashes=@();foreach($pass in 1,2){& (Join-Path $PSScriptRoot 'build-services.ps1') -OutputDirectory $serviceOut;$hashes=@{};Get-ChildItem -LiteralPath $serviceOut -Filter *.exe|Sort-Object Name|ForEach-Object{$hashes[$_.Name]=Get-Sha256Hex $_.FullName};$serviceHashes+=,$hashes}
foreach($name in $serviceHashes[0].Keys){if($serviceHashes[0][$name] -ne $serviceHashes[1][$name]){throw "T7D_D3_LINKED_BREPRO_MISMATCH: $name"}}
$retainedOutputHashes=[ordered]@{}
foreach($generatedName in $generatedDirectories){
  $generatedPath=Join-Path $resolvedEvidence $generatedName
  Get-ChildItem -LiteralPath $generatedPath -File -Recurse|Sort-Object FullName|ForEach-Object{
    $relative=[IO.Path]::GetRelativePath($resolvedEvidence,$_.FullName).Replace('\','/')
    $retainedOutputHashes[$relative]=Get-Sha256Hex $_.FullName
  }
}
$sourceHashes=@{};Get-ChildItem -LiteralPath $source -File|Where-Object{$_.Extension -in '.cpp','.h'}|Sort-Object Name|ForEach-Object{$sourceHashes[$_.Name]=Get-Sha256Hex $_.FullName}
$repoRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\..\..\..'))
$authorityFiles=[ordered]@{serviceContractAdapter='native/stellar/v0_1/service/service-contract-adapter.ts';brokerReceiptSchema='native/stellar/v0_1/schemas/stellar-t7c-broker-receipt-v0.1.schema.json';journalSchema='native/stellar/v0_1/schemas/stellar-replay-journal-record-v0.2.schema.json';journalDoctrine='docs/STELLAR_WINDOWS_X64_V0_1_DURABLE_JOURNAL_V0_2.md';d3CompletionDoctrine='docs/STELLAR_WINDOWS_X64_V0_1_T7D_D3_OFFLINE_COMPLETION.md'}
$authorityHashes=[ordered]@{};foreach($name in $authorityFiles.Keys){$authorityHashes[$name]=Get-Sha256Hex (Join-Path $repoRoot $authorityFiles[$name])}
$evidence=[ordered]@{schema='stellar.t7d-d3-offline-build/v0.2';observedAt=(Get-Date).ToUniversalTime().ToString('o');canonicalEvidencePath='native/stellar/v0_1/evidence/d3-v02-build/t7d-d3-offline-build.json';compiler='MSVC';flags=@('/std:c++20','/W4','/WX','/Brepro');sourceHashes=$sourceHashes;authorityFiles=$authorityFiles;authorityHashes=$authorityHashes;twoBuildHashes=$buildHashes[0];twoBuildLinkedServiceHashes=$serviceHashes[0];retainedOutputHashes=$retainedOutputHashes;reproducible=$true;journalFormat='stellar.replay-journal-record/v0.2';brokerReceiptFormat='stellar-broker-receipt-envelope-v0.1';nativeCanonicalJsonSelfTest='passed';nativeDurableSelfTest='passed';productionPathHarnesses=$harnessResults;multiprocessWorkers=12;exactlyOneReservation=$true;exactlyOneDispatchAuthorization=$true;dispatchCallbackInvocations=1;reservedMeansNoExternalDispatch=$true;brokerReceiptEs256RegistryVerification='passed';byteIdenticalPriorReceipt='passed';restartIdempotency='passed';rotateThenLaterRevokeRestart='passed';wrongOldSignerRefusal='passed';validCrashNewRecovery='passed';staleInvalidNewCleanup='passed';truncationRefusal='passed';corruptJournalSignatureRefusal='passed';permanentRefusalQuarantine='passed';powerLossOrKillInjectionPerformed=$false;installationPerformed=$false;keyCreationPerformed=$false;serviceMutationPerformed=$false;s7001='CLOSED'}
$json=$evidence|ConvertTo-Json -Depth 8 -Compress
$path=Join-Path $resolvedEvidence 't7d-d3-offline-build.json'
[IO.File]::WriteAllText($path,$json,[Text.UTF8Encoding]::new($false))
Write-Output $path
