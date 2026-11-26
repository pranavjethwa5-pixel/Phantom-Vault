[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$source = Join-Path $root 'app'
$dist = Join-Path $root 'dist'
$out = Join-Path $dist 'Portable'
if (Test-Path $out) { throw 'dist\Portable exists. Archive or rename it before rebuilding.' }
foreach ($tool in 'python.exe','node.exe','npm.cmd','ffmpeg.exe','ffprobe.exe') {
    if (!(Get-Command $tool -ErrorAction SilentlyContinue)) { throw "Missing developer tool: $tool" }
}
$pyInfo = python.exe -c "import sys,struct;print(str(sys.version_info.major)+'.'+str(sys.version_info.minor));print(struct.calcsize('P')*8);print(sys.base_prefix)"
if ($LASTEXITCODE -ne 0 -or $pyInfo[0] -ne '3.12' -or $pyInfo[1] -ne '64') { throw 'Requires 64-bit Python 3.12' }
$pythonRoot = $pyInfo[2]
Push-Location $source
try {
    npm.cmd ci --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
    $electronExe = (node.exe -p "require('electron')" | Select-Object -Last 1).Trim()
    if (!(Test-Path $electronExe)) { throw 'Electron runtime unavailable' }
} finally { Pop-Location }
New-Item -ItemType Directory -Path $out -Force | Out-Null
Copy-Item (Join-Path (Split-Path $electronExe) '*') $out -Recurse
Rename-Item (Join-Path $out 'electron.exe') 'Phantom Vault.exe'
$base = Join-Path $out 'resources\app'
New-Item -ItemType Directory -Path $base -Force | Out-Null
foreach($n in 'package.json','main.cjs','security14.cjs','preload.cjs','launcher.html','launcher.js','launcher.css','backend') {
    Copy-Item (Join-Path $source $n) $base -Recurse
}
$deps=Join-Path $base 'pydeps'
python.exe -m pip install --target $deps -r (Join-Path $source 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Python dependency install failed' }
$runtime=Join-Path $base 'runtime'
$pyr=Join-Path $runtime 'python'
$nod=Join-Path $runtime 'node'
$ff=Join-Path $runtime 'ffmpeg'
New-Item -ItemType Directory -Path $pyr,$nod,$ff -Force | Out-Null
foreach($n in 'python.exe','python3.dll','python312.dll','vcruntime140.dll','vcruntime140_1.dll','LICENSE.txt','DLLs') {
    Copy-Item (Join-Path $pythonRoot $n) $pyr -Recurse
}
robocopy (Join-Path $pythonRoot 'Lib') (Join-Path $pyr 'Lib') /E /XD site-packages __pycache__ /XF *.pyc /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw 'Python runtime copy failed' }
$node=(Get-Command node.exe).Source
Copy-Item $node $nod
$license=Join-Path (Split-Path $node) 'LICENSE'
if(Test-Path $license){Copy-Item $license $nod}
$ffmpeg=(Get-Command ffmpeg.exe).Source
Copy-Item $ffmpeg $ff
Copy-Item (Get-Command ffprobe.exe).Source $ff
Get-ChildItem (Split-Path (Split-Path $ffmpeg)) -File | Where-Object Name -match 'license|copying|readme' | Copy-Item -Destination $ff
$env:PYTHONHOME=$pyr
$env:PYTHONPATH=$deps
$env:PYTHONNOUSERSITE='1'
try {
    & (Join-Path $pyr 'python.exe') -c "import ssl,sqlite3,cryptography,pymupdf; print('Bundled runtime imports passed')"
    if ($LASTEXITCODE -ne 0) { throw 'Bundled dependency validation failed' }
} finally { Remove-Item Env:PYTHONHOME,Env:PYTHONPATH,Env:PYTHONNOUSERSITE -ErrorAction SilentlyContinue }
Copy-Item (Join-Path $root 'docs\PORTABLE.txt') (Join-Path $out 'README_R14.txt')
Write-Host "Portable build: $out"
