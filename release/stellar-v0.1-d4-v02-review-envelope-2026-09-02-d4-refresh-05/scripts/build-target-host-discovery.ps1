[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
$repo=(Resolve-Path (Join-Path $PSScriptRoot '..\..\..\..\..')).Path
$plan=Join-Path $repo 'native\stellar\v0_1\evidence\d4-final\actual-install-plan.canonical.json'
$pinned='437e6d3dd6343d226825dffe98f00e1e0649987f20ee1b980af21e281dd8b3a8'
if((Get-FileHash $plan).Hash.ToLowerInvariant() -ne $pinned){throw 'T7E_ACCEPTED_PLAN_HASH_MISMATCH'}
$parsed=Get-Content $plan -Raw|ConvertFrom-Json
if($parsed.planHash -ne 'sha256:9958eb87768bbf305d0b4a1f859f86ed8cfb5bb94234bc7c82bb98fc65a0a3b0' -or $parsed.proposed.Count -ne 91 -or @($parsed.proposed|Where-Object kind -eq file).Count -ne 77){throw 'T7E_ACCEPTED_PLAN_SCOPE_MISMATCH'}
$out=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path (Join-Path $out 'stellar-target-host-discovery.exe')){throw 'T7E_OUTPUT_EXISTS'}
New-Item -ItemType Directory -Path $out -Force|Out-Null
$vswhere='C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
$install=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath|Select-Object -First 1
$dev=Join-Path $install 'Common7\Tools\VsDevCmd.bat';$src=(Resolve-Path (Join-Path $PSScriptRoot '..\src')).Path
$exe=Join-Path $out 'stellar-target-host-discovery.exe';$obj=Join-Path $out 'stellar-target-host-discovery.obj'
$hostileExe=Join-Path $out 'stellar-target-host-discovery-hostile-selftest.exe';$hostileObj=Join-Path $out 'stellar-target-host-discovery-hostile-selftest.obj'
$aclObj=Join-Path $out 'protected-output-acl.obj'
$rc=Join-Path $out 'fixed-plan.rc';$res=Join-Path $out 'fixed-plan.res';('101 RCDATA "'+$plan.Replace('\','\\')+'"')|Set-Content $rc -Encoding ascii
$command='"'+$dev+'" -arch=x64 -host_arch=x64 >nul && rc.exe /nologo /fo"'+$res+'" "'+$rc+'" && cl.exe /nologo /c /std:c++20 /W4 /WX /EHsc /guard:cf /DUNICODE /D_UNICODE /Brepro /Fo"'+$aclObj+'" "'+(Join-Path $src 'protected_output_acl.cpp')+'" && cl.exe /nologo /c /std:c++20 /W4 /WX /EHsc /guard:cf /DUNICODE /D_UNICODE /Brepro /Fo"'+$obj+'" "'+(Join-Path $src 'target_host_discovery.cpp')+'" && link.exe /Brepro /OUT:"'+$exe+'" /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /CETCOMPAT "'+$obj+'" "'+$aclObj+'" "'+$res+'" advapi32.lib bcrypt.lib crypt32.lib ncrypt.lib shell32.lib ole32.lib'
cmd.exe /d /s /c $command
if($LASTEXITCODE){throw "T7E_NATIVE_BUILD_FAILED_$LASTEXITCODE"}
$hostileCommand='"'+$dev+'" -arch=x64 -host_arch=x64 >nul && cl.exe /nologo /c /std:c++20 /W4 /WX /EHsc /guard:cf /DUNICODE /D_UNICODE /Brepro /Fo"'+$hostileObj+'" "'+(Join-Path $src 'target_host_discovery_hostile_selftest.cpp')+'" && link.exe /Brepro /OUT:"'+$hostileExe+'" /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA /CETCOMPAT "'+$hostileObj+'" "'+$aclObj+'" advapi32.lib'
cmd.exe /d /s /c $hostileCommand
if($LASTEXITCODE){throw "T7E_HOSTILE_NATIVE_BUILD_FAILED_$LASTEXITCODE"}
$hostileEvidence=& $hostileExe
if($LASTEXITCODE){throw "T7E_HOSTILE_NATIVE_ACCEPTANCE_FAILED_$LASTEXITCODE $hostileEvidence"}
$hostileEvidence|Set-Content (Join-Path $out 'hostile-native-selftest.canonical.json') -Encoding utf8NoBOM
