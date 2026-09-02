[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Path)
$ErrorActionPreference='Stop';$item=Get-Item -LiteralPath $Path -Force;if($item.Attributes -band [IO.FileAttributes]::ReparsePoint -or $item.LinkType){throw 'D4_FILE_IDENTITY_REFUSED'}
$streams=@(Get-Item -LiteralPath $item.FullName -Stream *|ForEach-Object{$_.Stream});$acl=Get-Acl -LiteralPath $item.FullName;if(-not $acl.Owner -or -not $acl.Sddl){throw 'D4_ACL_READBACK_INCOMPLETE'}
[ordered]@{schema='stellar.t7d-package-file-readback/v0.1';streams=$streams;aclReviewed=$true;owner=$acl.Owner;sddl=$acl.Sddl}|ConvertTo-Json -Compress
