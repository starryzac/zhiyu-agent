[CmdletBinding()]
param([string]$GoCommand='go',[string]$PnpmCommand='pnpm',[string]$StoreDir='',[switch]$Offline)
$ErrorActionPreference='Stop'
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$previousToolchain=$env:GOTOOLCHAIN
$previousProxy=$env:GOPROXY
$previousSumDB=$env:GOSUMDB
Push-Location $projectRoot
try {
 $env:GOTOOLCHAIN='local'
 if ($Offline) { $env:GOPROXY='off'; $env:GOSUMDB='off' }
 if ((& $GoCommand version) -notmatch '^go version go1\.27\.2 ') { throw 'Go 1.27.2 is required.' }
 if (!$Offline) { & $GoCommand mod download; if ($LASTEXITCODE -ne 0) { throw 'Go dependency download failed.' } }
 [IO.Directory]::CreateDirectory((Join-Path $projectRoot 'bin')) | Out-Null
 $sourceInfo=& (Join-Path $PSScriptRoot 'New-CoreSourceManifest.ps1') -Root $projectRoot
 foreach ($name in @('zhiyu','banksim','audit-anchor','creditseed','historyseed')) {
  $buildArgs=@('build','-mod=readonly','-trimpath','-buildvcs=false')
  if ($name -in @('zhiyu','audit-anchor')) { $buildArgs+=@('-ldflags',('-X main.auditSourceManifestSHA='+$sourceInfo.SourceManifestSHA256)) }
  $buildArgs+=@('-o',(Join-Path $projectRoot ('bin/'+$name+'.exe')),('./cmd/'+$name))
  & $GoCommand @buildArgs
  if ($LASTEXITCODE -ne 0) { throw ('Build failed: '+$name) }
 }
 $install=@('--dir','web','install','--frozen-lockfile')
 if ($StoreDir) { $install+=@('--store-dir',[IO.Path]::GetFullPath($StoreDir)) }
 if ($Offline) { $install+='--offline' }
 & $PnpmCommand @install
 if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' }
 & $PnpmCommand --dir web build
 if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
 $verifiedSource=& (Join-Path $PSScriptRoot 'New-CoreSourceManifest.ps1') -Root $projectRoot -VerifyOnly
 if ($verifiedSource.SourceManifestSHA256 -cne $sourceInfo.SourceManifestSHA256) { throw 'Source input changed during build.' }
} finally {
 $env:GOTOOLCHAIN=$previousToolchain
 $env:GOPROXY=$previousProxy
 $env:GOSUMDB=$previousSumDB
 Pop-Location
}
