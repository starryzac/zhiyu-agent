# Exact core source inventory only. No build, database, or network operation.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Root,[switch]$VerifyOnly)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$projectRoot=(Resolve-Path -LiteralPath $Root).Path.TrimEnd([IO.Path]::DirectorySeparatorChar)
if ((Get-Item -LiteralPath $projectRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'A linked root is not a source snapshot.' }
$names=[Collections.Generic.List[string]]::new()
function Excluded([string]$Name) {
 return $Name -match '(?i)(?:_test\.go$|\.test\.|\.spec\.|^test[_-]|^bench[_-])'
}
function Add-Source([IO.FileInfo]$File) {
 if ($File.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked source file rejected.' }
 $relative=$File.FullName.Substring($projectRoot.Length+1).Replace('\','/')
 if (Excluded $File.Name) { return }
 $names.Add($relative)
}
$fixed=@('.gitattributes','.gitignore','go.mod','go.sum','sqlc.yaml','Makefile','README.md','THIRD-PARTY-NOTICES.txt','web/index.html','web/package.json','web/pnpm-lock.yaml','web/pnpm-workspace.yaml','web/tsconfig.json','web/vite.config.ts')
foreach ($name in $fixed) {
 $file=Get-Item -LiteralPath (Join-Path $projectRoot $name) -Force
 if ($file -isnot [IO.FileInfo]) { throw 'Core build input must be a regular file.' }
 Add-Source $file
}
$groups=[ordered]@{
 'cmd'='\.go$';'internal'='\.(go|sql)$';'db'='\.(go|sql)$';
 'api/openapi'='\.ya?ml$';'api/schemaexport'='\.go$';
 'web/src'='\.(ts|tsx|css|json|svg|png|jpg|jpeg|webp|woff|woff2)$';
 'config'='\.example\.json$';'scripts'='(\.ps1|\.sql\.in|\.txt\.in)$';'licenses'='\.txt$'
}
$skip=@('.git','.runtime','node_modules','dist','bin','.cache','.tools','.pnpm-store','tests','testdata','testsupport','bench','benchmarks')
foreach ($entry in $groups.GetEnumerator()) {
 $directory=Get-Item -LiteralPath (Join-Path $projectRoot $entry.Key) -Force
 if ($directory -isnot [IO.DirectoryInfo]) { throw 'Core source directory is missing.' }
 $stack=[Collections.Generic.Stack[IO.DirectoryInfo]]::new();$stack.Push($directory)
 while ($stack.Count -gt 0) {
  $current=$stack.Pop()
  if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked source directory rejected.' }
  foreach ($item in Get-ChildItem -LiteralPath $current.FullName -Force) {
   if ($item -is [IO.DirectoryInfo]) { if ($skip -notcontains $item.Name) { $stack.Push($item) };continue }
   if (Excluded $item.Name) { continue }
   if ($item.Name -notmatch $entry.Value) { throw ('Unexpected core source file; review the allowlist: '+$item.Name) }
   Add-Source $item
  }
 }
}
$names.Sort([StringComparer]::Ordinal)
if ($names.Count -eq 0 -or @($names | Select-Object -Unique).Count -ne $names.Count) { throw 'Empty or duplicate source inventory.' }
function Hash-Bytes([byte[]]$Bytes) {
 $algorithm=[Security.Cryptography.SHA256]::Create()
 try { return ([BitConverter]::ToString($algorithm.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() } finally { $algorithm.Dispose() }
}
$rows=@(foreach ($name in $names) {
 $raw=[IO.File]::ReadAllBytes((Join-Path $projectRoot $name))
 [ordered]@{bytes=[long]$raw.LongLength;path=$name;sha256=(Hash-Bytes $raw)}
})
# Field order is canonical: files/protocol, then bytes/path/sha256. Relative paths
# are ordered with StringComparer.Ordinal; original file bytes are never decoded.
$document=[ordered]@{files=$rows;protocol='zhiyu-release-source-v1'}
$utf8=[Text.UTF8Encoding]::new($false)
$canonical=$utf8.GetBytes(($document | ConvertTo-Json -Depth 8 -Compress))
$digest=Hash-Bytes $canonical
$manifestBytes=$utf8.GetBytes(($document | ConvertTo-Json -Depth 8 -Compress)+"`n")
$bin=Join-Path $projectRoot 'bin'
if ((Test-Path -LiteralPath $bin) -and ((Get-Item -LiteralPath $bin -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked output directory rejected.' }
$manifest=Join-Path $bin 'source-manifest.json';$digestFile=Join-Path $bin 'source-manifest.sha256'
foreach ($path in @($manifest,$digestFile)) { if ((Test-Path -LiteralPath $path) -and ((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked output file rejected.' } }
if ($VerifyOnly) {
 if (!(Test-Path -LiteralPath $manifest -PathType Leaf) -or (Hash-Bytes ([IO.File]::ReadAllBytes($manifest))) -ne (Hash-Bytes $manifestBytes) -or [IO.File]::ReadAllText($digestFile).Trim() -cne $digest) { throw 'Core source changed after its manifest was prepared.' }
} else {
 [IO.Directory]::CreateDirectory($bin) | Out-Null
 [IO.File]::WriteAllBytes($manifest,$manifestBytes)
 [IO.File]::WriteAllText($digestFile,$digest+"`n",$utf8)
}
[pscustomobject]@{SourceManifestSHA256=$digest;SourceManifestPath=$manifest;SourceManifestFileSHA256=(Hash-Bytes $manifestBytes);FileCount=$rows.Count;VerifiedOnly=[bool]$VerifyOnly}
