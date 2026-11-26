[CmdletBinding()]
param([switch]$GlobalIPv6)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$p=Join-Path $root 'dist\Portable'
$exe=Join-Path $p 'Phantom Vault.exe'
if(!(Test-Path $exe)){throw 'Build the portable application first.'}
$log=Join-Path $root 'dist\audit'
New-Item -ItemType Directory -Path $log -Force | Out-Null
$arg='--pv-audit'
if($GlobalIPv6){$arg+=' --pv-audit-ipv6'}
$a=Start-Process -FilePath $exe -ArgumentList $arg -WorkingDirectory $p -RedirectStandardOutput (Join-Path $log 'stdout.log') -RedirectStandardError (Join-Path $log 'stderr.log') -PassThru -Wait
Get-Content (Join-Path $log 'stdout.log')
Get-Content (Join-Path $log 'stderr.log')
if($a.ExitCode -ne 0){throw "Audit exit code $($a.ExitCode)"}
