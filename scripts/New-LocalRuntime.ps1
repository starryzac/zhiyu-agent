# Configuration generation only: no Docker, database, HTTP, or product execution.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$Root,
 [string]$RuntimeDir='.runtime',
 [ValidateRange(1024,65535)][int]$PostgresPort=55549,
 [ValidateRange(1024,65535)][int]$ApiPort=19520,
 [ValidateRange(1024,65535)][int]$BankPort=19521
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if (@(@($PostgresPort,$ApiPort,$BankPort) | Sort-Object -Unique).Count -ne 3) { throw 'Use three distinct ports.' }
$ProjectRoot=(Resolve-Path -LiteralPath $Root).Path.TrimEnd([IO.Path]::DirectorySeparatorChar)
if (!(Test-Path -LiteralPath (Join-Path $ProjectRoot 'go.mod')) -or !(Test-Path -LiteralPath (Join-Path $ProjectRoot 'web/package.json'))) { throw 'Root must be the core checkout.' }
$RuntimePath=if ([IO.Path]::IsPathRooted($RuntimeDir)) { [IO.Path]::GetFullPath($RuntimeDir) } else { [IO.Path]::GetFullPath((Join-Path $ProjectRoot $RuntimeDir)) }
if ($RuntimePath -ne (Join-Path $ProjectRoot '.runtime')) { throw 'RuntimeDir must resolve to this Root/.runtime.' }
if (Test-Path -LiteralPath $RuntimePath) { throw 'Runtime exists. Preserve it and select a new checkout.' }
$Ancestor=Split-Path -Parent $RuntimePath
while ($Ancestor -and $Ancestor.StartsWith($ProjectRoot,[StringComparison]::OrdinalIgnoreCase)) {
 if ((Test-Path -LiteralPath $Ancestor) -and ((Get-Item -LiteralPath $Ancestor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked runtime parents are not accepted.' }
 if ($Ancestor -eq $ProjectRoot) { break }; $Ancestor=Split-Path -Parent $Ancestor
}
function New-Hex([int]$Count) {
 $Buffer=New-Object byte[] $Count; $Generator=[Security.Cryptography.RandomNumberGenerator]::Create()
 try { $Generator.GetBytes($Buffer) } finally { $Generator.Dispose() }
 return ([BitConverter]::ToString($Buffer)).Replace('-','').ToLowerInvariant()
}
$Utf8=New-Object Text.UTF8Encoding($false)
function Write-New([string]$Name,[string]$Text) {
 $Stream=[IO.File]::Open((Join-Path $RuntimePath $Name),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try { $Bytes=$Utf8.GetBytes($Text);$Stream.Write($Bytes,0,$Bytes.Length);$Stream.Flush() } finally { $Stream.Dispose() }
}
function Write-Json([string]$Name,$Value) { Write-New $Name (($Value | ConvertTo-Json -Depth 12)+"`n") }
$Cluster=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'new-cluster-only.sql.in'))
$Zero=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'bank-zero-only.sql.in'))
$StartHere=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'START-HERE.txt.in'))
[IO.Directory]::CreateDirectory($RuntimePath) | Out-Null
$Lock=[IO.File]::Open((Join-Path $RuntimePath '.create.lock'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try {
 $Environment='zygo_local_'+[guid]::NewGuid().ToString('N').Substring(0,16);$Namespace='zygo_demo_'+[guid]::NewGuid().ToString('N').Substring(0,24)
 $EnvironmentId=[guid]::NewGuid().ToString();$UserId=[guid]::NewGuid().ToString();$AccountId=[guid]::NewGuid().ToString();$GoalId=[guid]::NewGuid().ToString();$OwnerId=[guid]::NewGuid().ToString()
 $OwnerPassword=New-Hex 24;$AppPassword=New-Hex 24;$BankPassword=New-Hex 24;$AdminPassword=New-Hex 24;$Permit=New-Hex 32;$Login=New-Hex 32
 $CreatedAt=[DateTimeOffset]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.ffffff'Z'")
 $Origin="http://127.0.0.1:$ApiPort";$BankUrl="http://127.0.0.1:$BankPort";$SeedPath=Join-Path $RuntimePath 'demo-seed.json'
 $AppDSN="postgresql://zygo_app:${AppPassword}@127.0.0.1:$PostgresPort/${Environment}_app"
 $OwnerDSN="postgresql://zygo_app_owner:${OwnerPassword}@127.0.0.1:$PostgresPort/${Environment}_app"
 $BankDSN="postgresql://zygo_bank:${BankPassword}@127.0.0.1:$PostgresPort/${Environment}_bank"
 Write-Json 'app-runtime.json' ([ordered]@{role='app';environment=$Environment;namespace=$Namespace;simulation=$true;listen_addr="127.0.0.1:$ApiPort";app_dsn=$AppDSN;bank_url=$BankUrl;bank_permit_secret=$Permit;web_origin=$Origin})
 Write-Json 'migration-runtime.json' ([ordered]@{role='migration';environment=$Environment;namespace=$Namespace;simulation=$true;listen_addr="127.0.0.1:$ApiPort";migration_dsn=$OwnerDSN})
 Write-Json 'bank-runtime.json' ([ordered]@{role='bank';environment=$Environment;bank_dsn=$BankDSN;bank_permit_secret=$Permit})
 Write-Json 'seed-runtime.json' ([ordered]@{role='seed';environment=$Environment;namespace=$Namespace;simulation=$true;listen_addr="127.0.0.1:$ApiPort";app_dsn=$AppDSN;bank_dsn=$BankDSN;bank_url=$BankUrl;bank_permit_secret=$Permit;seed_state=$SeedPath})
 Write-Json 'demo-seed.json' ([ordered]@{protocol='zhiyu-demo-seed-v1';namespace=$Namespace;environment_id=$EnvironmentId;user_id=$UserId;account_id=$AccountId;goal_id=$GoalId;login_secret=$Login;target_cents='50000';created_at=$CreatedAt})
 Write-New 'postgres.env' ("POSTGRES_USER=zygo_install_admin`nPOSTGRES_PASSWORD=$AdminPassword`nPOSTGRES_DB=postgres`n")
 $Cluster=$Cluster.Replace('__ENV__',$Environment).Replace('__OWNER_PASS__',$OwnerPassword).Replace('__APP_PASS__',$AppPassword).Replace('__BANK_PASS__',$BankPassword)
 Write-New 'new-cluster-only.sql' ($Cluster+"`n")
 $Zero=$Zero.Replace('__ENV__',$Environment).Replace('__NS__',$Namespace).Replace('__USER__',$UserId).Replace('__ACCOUNT__',$AccountId).Replace('__GOAL__',$GoalId)
 Write-New 'bank-zero-only.sql' ($Zero+"`n")
 Write-Json 'owner-read.json' ([ordered]@{protocol='zhiyu-recovery-operator-v1';namespace=$Namespace;action='READ'})
 Write-Json 'owner-arm.json' ([ordered]@{protocol='zhiyu-recovery-operator-v1';namespace=$Namespace;action='ARM';owner_id=$OwnerId})
 Write-Json 'owner-scan.json' ([ordered]@{protocol='zhiyu-recovery-operator-v1';namespace=$Namespace;action='SCAN'})
 Write-Json 'owner-handoff.template.json' ([ordered]@{protocol='zhiyu-recovery-operator-v1';namespace=$Namespace;action='HANDOFF';expected=$null;owner_id=$OwnerId})
 Write-Json 'owner-read-only.template.json' ([ordered]@{protocol='zhiyu-recovery-operator-v1';namespace=$Namespace;action='READ_ONLY';expected=$null})
 Write-Json 'owner-activate.template.json' ([ordered]@{protocol='zhiyu-recovery-operator-v1';namespace=$Namespace;action='ACTIVATE';run_id=$null;quiescence_file=(Join-Path $RuntimePath 'quiescence.json')})
 Write-Json 'writer-pin.template.json' ([ordered]@{protocol='zhiyu-writer-pin-v1';namespace=$Namespace;owner_id=$OwnerId;generation=$null})
 Write-Json 'quiescence.template.json' ([ordered]@{protocol='zhiyu-owned-process-quiescence-v1';namespace=$Namespace;all_registered_processes_stopped=$false;bank_process_stopped=$false;external_requests_drained=$false;checked_at=$null;processes=@()})
 $StartHere=$StartHere.Replace('__ROOT_PS__',$ProjectRoot.Replace("'","''")).Replace('__RUNTIME_PS__',$RuntimePath.Replace("'","''")).Replace('__ENV__',$Environment).Replace('__NS__',$Namespace).Replace('__EID__',$EnvironmentId).Replace('__OWNER__',$OwnerId).Replace('__PG_PORT__',[string]$PostgresPort).Replace('__API_PORT__',[string]$ApiPort).Replace('__BANK_PORT__',[string]$BankPort)
 Write-New 'START-HERE.txt' ($StartHere+"`n")
 Write-Json 'local-install.json' ([ordered]@{protocol='zhiyu-local-install-v1';status='CONFIGURATION_CREATED_NOT_INSTALLED';environment=$Environment;namespace=$Namespace;environment_id=$EnvironmentId;user_id=$UserId;account_id=$AccountId;goal_id=$GoalId;owner_id=$OwnerId;ports=[ordered]@{postgres=$PostgresPort;api=$ApiPort;bank=$BankPort};container=$Environment.Replace('_','-')+'-postgres';volume=$Environment.Replace('_','-')+'-pgdata';postgres_image='postgres@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea';runtime_dir=$RuntimePath;writer_control='NOT_CREATED';writer_pin='NOT_CREATED'})
 [ordered]@{status='CONFIGURATION_CREATED_NOT_INSTALLED';runtime_dir=$RuntimePath;url=$Origin;login_code_file=$SeedPath;writer_pin_created=$false} | ConvertTo-Json
} finally { $Lock.Dispose() }
