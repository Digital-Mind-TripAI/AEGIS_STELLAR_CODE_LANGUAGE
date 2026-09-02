[CmdletBinding()]
param([Parameter(Mandatory=$false)][string]$InstallRoot='C:\Program Files\AEGIS\Stellar\v0.1',[Parameter(Mandatory=$false)][string]$DataRoot='C:\ProgramData\AEGIS\Stellar\v0.1')
$ErrorActionPreference='Stop'
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
$elevated=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$dataDrive=[IO.Path]::GetPathRoot($DataRoot)
$volume=Get-Volume -DriveLetter $dataDrive.Substring(0,1)
$paths=@($InstallRoot,$DataRoot)
foreach($path in $paths){if(-not [IO.Path]::IsPathFullyQualified($path) -or $path.Contains('..')){throw "T7C_PATH_INVALID: $path"};$cursor=[IO.DirectoryInfo]::new($path);while($cursor){if($cursor.Exists -and ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw "T7C_REPARSE_REFUSED: $($cursor.FullName)"};$cursor=$cursor.Parent}}
if($volume.FileSystem -ne 'NTFS'){throw 'T7C_NTFS_REQUIRED'}
$result=[ordered]@{schema='stellar.t7c-service-preflight/v0.1';elevated=$elevated;administratorRequiredForInstall=$true;ntfs=$true;pathsAbsolute=$true;reparseAncestorsAbsent=$true;servicesMutated=$false;s7001Closed=$true}
$result|ConvertTo-Json -Compress
if(-not $elevated){exit 5}
