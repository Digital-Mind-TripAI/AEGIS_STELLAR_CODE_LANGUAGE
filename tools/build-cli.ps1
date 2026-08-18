param([Parameter(Mandatory = $true)][string]$Output)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputPath = [System.IO.Path]::GetFullPath($Output)
$vswhere = 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Visual Studio discovery is unavailable.' }
$installation = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if (-not $installation) { throw 'MSVC x64 tools are required.' }
$dev = Join-Path $installation 'Common7\Tools\VsDevCmd.bat'
$lines = & $env:ComSpec /d /s /c ('call "' + $dev + '" -arch=x64 -host_arch=x64 >nul && set')
if ($LASTEXITCODE -ne 0) { throw 'MSVC environment initialization failed.' }
foreach ($line in $lines) { $at = $line.IndexOf('='); if ($at -gt 0) { [Environment]::SetEnvironmentVariable($line.Substring(0,$at),$line.Substring($at+1),'Process') } }
$directory = Split-Path -Parent $outputPath
[System.IO.Directory]::CreateDirectory($directory) | Out-Null
$objectDirectory = Join-Path $directory 'obj'
[System.IO.Directory]::CreateDirectory($objectDirectory) | Out-Null
$sources = Get-ChildItem -LiteralPath (Join-Path $root 'src') -Filter '*.cpp' | Sort-Object Name | ForEach-Object FullName
$arguments = @('/nologo','/std:c++20','/EHsc','/W4','/WX','/O2','/Brepro','/utf-8',('/I' + (Join-Path $root 'include')),('/Fo' + $objectDirectory + '\'),('/Fe' + $outputPath)) + $sources + @('/link','/INCREMENTAL:NO','/OPT:REF','/OPT:ICF','/Brepro')
$captured = & (Get-Command cl.exe -ErrorAction Stop).Source @arguments 2>&1
if ($LASTEXITCODE -ne 0) { throw "Stellar v0.1 CLI build failed.`n$($captured -join [Environment]::NewLine)" }
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'build-package.ps1') -Destination (Join-Path $directory 'build-package.ps1') -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'build-stdlib.ps1') -Destination (Join-Path $directory 'build-stdlib.ps1') -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'release-acceptance.mjs') -Destination (Join-Path $directory 'release-acceptance.mjs') -Force
$schemaDestination=Join-Path $directory 'schemas'
if(-not(Test-Path -LiteralPath $schemaDestination)){[IO.Directory]::CreateDirectory($schemaDestination)|Out-Null}
Get-ChildItem -LiteralPath (Join-Path $root 'schemas') -File -Filter '*.json'|Sort-Object Name|Copy-Item -Destination $schemaDestination -Force
