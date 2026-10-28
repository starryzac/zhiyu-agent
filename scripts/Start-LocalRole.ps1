# One fixed native role in the current console. PowerShell 7 / Windows only.
[CmdletBinding()]
param(
 [Parameter(Mandatory=$true)][string]$Root,
 [Parameter(Mandatory=$true)][ValidateSet('bank','api','worker','native-standing','projection')][string]$Role,
 [switch]$InitializeBank,
 [switch]$Bootstrap
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if (!$IsWindows -or $PSVersionTable.PSVersion.Major -lt 7) { throw 'Windows PowerShell 7 is required.' }
if ([Console]::IsInputRedirected) { throw 'A foreground console is required; use normal Ctrl+C in that console.' }
if ($InitializeBank -and $Role -ne 'bank') { throw 'InitializeBank is bank-only.' }
if ($Bootstrap -and $Role -notin @('api','worker')) { throw 'Bootstrap is only for the initial API/worker pair.' }
$ProjectRoot=(Resolve-Path -LiteralPath $Root).Path.TrimEnd([IO.Path]::DirectorySeparatorChar)
$RuntimePath=Join-Path $ProjectRoot '.runtime'
foreach ($Folder in @($ProjectRoot,$RuntimePath)) { if ((Get-Item -LiteralPath $Folder -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked roots are not accepted.' } }
$Install=Get-Content -LiteralPath (Join-Path $RuntimePath 'local-install.json') -Raw | ConvertFrom-Json
if ($Install.protocol -ne 'zhiyu-local-install-v1' -or [IO.Path]::GetFullPath($Install.runtime_dir) -ne $RuntimePath -or $Install.environment -notmatch '^zygo_local_[0-9a-f]{16}$' -or $Install.namespace -notmatch '^zygo_demo_[0-9a-f]{24}$') { throw 'This Root runtime metadata is required.' }
foreach ($Identity in @($Install.owner_id,$Install.environment_id,$Install.user_id,$Install.account_id,$Install.goal_id)) { if ([guid]$Identity -eq [guid]::Empty) { throw 'New nonzero identities are required.' } }
foreach ($Port in @($Install.ports.postgres,$Install.ports.api,$Install.ports.bank)) { if ([int]$Port -lt 1024 -or [int]$Port -gt 65535) { throw 'Invalid local ports.' } }
if (@(@($Install.ports.postgres,$Install.ports.api,$Install.ports.bank) | Sort-Object -Unique).Count -ne 3) { throw 'Ports must differ.' }
$Owner=$Install.owner_id; $Generation=0
$PinPath=Join-Path $RuntimePath 'writer-pin.json'
if ($InitializeBank) { if (Test-Path -LiteralPath $PinPath) { throw 'First bank migration must precede writer control.' } }
else {
 $Pin=Get-Content -LiteralPath $PinPath -Raw | ConvertFrom-Json
 if ($Pin.protocol -ne 'zhiyu-writer-pin-v1' -or $Pin.namespace -ne $Install.namespace -or $Pin.owner_id -ne $Owner -or $Pin.generation -lt 1) { throw 'Explicit same-owner actual pin is required.' }
 $Generation=[long]$Pin.generation
 if ($Bootstrap) {
  $Arm=Get-Content -LiteralPath (Join-Path $RuntimePath 'owner-arm-result.json') -Raw | ConvertFrom-Json
  if ($Arm.owner_id -ne $Owner -or $Arm.environment_id -ne $Install.environment_id -or $Arm.mode -ne 'READ_ONLY' -or $Arm.generation -ne $Generation) { throw 'Bootstrap pair must use the actual initial ARM pin.' }
 }
}
$Config=Join-Path $RuntimePath $(if ($Role -eq 'bank') {'bank-runtime.json'} else {'app-runtime.json'})
$ConfigObject=Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
if ($ConfigObject.environment -ne $Install.environment -or $ConfigObject.role -ne $(if ($Role -eq 'bank') {'bank'} else {'app'})) { throw 'Role configuration differs.' }
if ($Role -ne 'bank' -and ($ConfigObject.namespace -ne $Install.namespace -or $ConfigObject.PSObject.Properties.Name -contains 'bank_dsn' -or $ConfigObject.PSObject.Properties.Name -contains 'migration_dsn')) { throw 'Application role scope differs.' }
if ($Role -eq 'bank') { $DSN=[uri]$ConfigObject.bank_dsn; $DBRole='zygo_bank'; $DBSuffix='_bank' } else {
 if ($ConfigObject.listen_addr -ne ('127.0.0.1:'+[string]$Install.ports.api) -or $ConfigObject.web_origin -ne ('http://127.0.0.1:'+[string]$Install.ports.api) -or $ConfigObject.bank_url -ne ('http://127.0.0.1:'+[string]$Install.ports.bank)) { throw 'Local endpoints differ from this install.' }
 $DSN=[uri]$ConfigObject.app_dsn; $DBRole='zygo_app'; $DBSuffix='_app'
}
if ($DSN.Scheme -ne 'postgresql' -or $DSN.Host -ne '127.0.0.1' -or $DSN.Port -ne $Install.ports.postgres -or $DSN.AbsolutePath -ne ('/'+$Install.environment+$DBSuffix) -or !$DSN.UserInfo.StartsWith(($DBRole+':'),[StringComparison]::Ordinal)) { throw 'Role database differs from this install.' }
$Executable=Join-Path $ProjectRoot $(if ($Role -eq 'bank') {'bin/banksim.exe'} else {'bin/zhiyu.exe'})
if (!(Test-Path -LiteralPath $Executable)) { throw 'Build the fixed role executable first.' }
foreach ($File in @($Executable,$Config,(Join-Path $ProjectRoot 'bin'))) { if ((Get-Item -LiteralPath $File -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked executable/config paths are not accepted.' } }
$NativeArgs=if ($Role -eq 'bank') { @('-config',$Config,'-listen',('127.0.0.1:'+[string]$Install.ports.bank),'-protocol-v2','-credit-inventory') } else { @($Role,'-config',$Config) }
if ($InitializeBank) { $NativeArgs+=@('-migrate','-migrate-v2','-migrate-credit') }
if ($Role -eq 'api') { $NativeArgs+=@('-web-root',(Join-Path $ProjectRoot 'web/dist')) }
$Private=Join-Path $RuntimePath 'processes'
if ((Test-Path -LiteralPath $Private) -and ((Get-Item -LiteralPath $Private -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Linked process directories are not accepted.' }
[IO.Directory]::CreateDirectory($Private) | Out-Null
if ($InitializeBank) {
 $Claim=[IO.File]::Open((Join-Path $Private 'first-bank.claim'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None); $Claim.Dispose()
}
$RunDirectory=Join-Path $Private ($Role+'-'+[DateTimeOffset]::UtcNow.ToString('yyyyMMddTHHmmssfff')+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
[IO.Directory]::CreateDirectory($RunDirectory) | Out-Null
$Source=@"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
public static class ZhiyuLocalRoleHostV2 {
 [StructLayout(LayoutKind.Sequential)] struct NativeFileTime { public uint Low; public uint High; }
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr h,out NativeFileTime created,out NativeFileTime exited,out NativeFileTime kernel,out NativeFileTime user);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)] static extern bool QueryFullProcessImageNameW(IntPtr h,uint flags,StringBuilder image,ref uint size);
 static string NativeImage(IntPtr h) { var image=new StringBuilder(32768);uint size=(uint)image.Capacity;if(!QueryFullProcessImageNameW(h,0,image,ref size))throw new Win32Exception(Marshal.GetLastWin32Error());return image.ToString(); }
 static long NativeCreated(IntPtr h) { NativeFileTime c,e,k,u;if(!GetProcessTimes(h,out c,out e,out k,out u))throw new Win32Exception(Marshal.GetLastWin32Error());return ((long)c.High<<32)|c.Low; }
 static string Hash(string p) { using(var h=SHA256.Create()) using(var f=File.OpenRead(p)) return Convert.ToHexString(h.ComputeHash(f)).ToLowerInvariant(); }
 static void Save(string p, Dictionary<string,object> x) { var bytes=Encoding.UTF8.GetBytes(JsonSerializer.Serialize(x,new JsonSerializerOptions { WriteIndented=true })); using(var f=new FileStream(p,FileMode.CreateNew,FileAccess.Write,FileShare.Read)) { f.Write(bytes,0,bytes.Length);f.Flush(true); } }
 public static int Run(string root,string runtime,string role,bool init,bool bootstrap,string exe,string config,string[] args,string owner,long generation,string ns,string environment,string output,string helper) {
  Process proc=null; FileStream stdout=null,stderr=null; Task copyOut=null,copyErr=null;
  int interrupts=0; bool held=false,identity=false; string error=null;
  var r=new Dictionary<string,object> { {"protocol","zhiyu-local-role-v1"},{"role",role},{"root",root},{"runtime_dir",runtime},{"namespace",ns},{"environment",environment},{"owner_id",owner},{"writer_generation",generation==0?(object)null:generation},{"initialize_bank",init},{"bootstrap_cycle",init||bootstrap},{"argv",args},{"expected_exe",exe},{"helper_sha256",Hash(helper)},{"configuration_sha256",Hash(config)},{"started_at",DateTimeOffset.UtcNow.ToString("o")},{"verified_exited",false},{"actual_exit_code",null},{"identity_verified",false},{"native_handle_held",false},{"kill_or_signal_forwarded",false},{"same_console",true} };
  ConsoleCancelEventHandler cancel=(s,e)=>{Interlocked.Increment(ref interrupts);e.Cancel=true;};
  Console.CancelKeyPress+=cancel;
  try {
   var before=Hash(exe); var psi=new ProcessStartInfo(exe) { WorkingDirectory=root,UseShellExecute=false,CreateNoWindow=false,RedirectStandardOutput=true,RedirectStandardError=true,RedirectStandardInput=false };
   foreach(var arg in args) psi.ArgumentList.Add(arg);
   var names=new List<string>(psi.Environment.Keys);
   foreach(var name in names) { var u=name.ToUpperInvariant(); if(u.StartsWith("ZYGO_")||u.StartsWith("ZHIYU_")||u.StartsWith("PG")||u.StartsWith("OPENAI_")||u.StartsWith("DEEPSEEK_")||u.StartsWith("ANTHROPIC_")||u.StartsWith("GEMINI_")||u.StartsWith("MODEL_")||u.StartsWith("GO")||u.StartsWith("AZURE_OPENAI_")) psi.Environment.Remove(name); }
   stdout=new FileStream(Path.Combine(output,"stdout.log"),FileMode.CreateNew,FileAccess.Write,FileShare.Read);
   stderr=new FileStream(Path.Combine(output,"stderr.log"),FileMode.CreateNew,FileAccess.Write,FileShare.Read);
   proc=Process.Start(psi); if(proc==null) throw new InvalidOperationException();
   var handle=proc.Handle; held=handle!=IntPtr.Zero; r["native_handle_held"]=held;r["pid"]=proc.Id;
   copyOut=proc.StandardOutput.BaseStream.CopyToAsync(stdout);copyErr=proc.StandardError.BaseStream.CopyToAsync(stderr);
   try { var actual=NativeImage(handle);var ticks=NativeCreated(handle);var actualHash=Hash(actual);identity=held&&String.Equals(Path.GetFullPath(actual),Path.GetFullPath(exe),StringComparison.OrdinalIgnoreCase)&&before==actualHash;r["native_exe"]=actual;r["native_creation_filetime_100ns"]=ticks;r["exe_sha256"]=actualHash;r["identity_verified"]=identity; } catch(Exception x) { r["identity_error_type"]=x.GetType().Name; }
   r["status"]="NATIVE_RUNNING";Save(Path.Combine(output,"START.json"),r);
   Console.WriteLine("Native role running; use normal Ctrl+C in this console. Records: "+output);
   proc.WaitForExit();
  } catch(Exception x) { error=x.GetType().Name; r["status"]="UNKNOWN_RETAINED_WAITING";r["error_type"]=error;try{Save(Path.Combine(output,"UNKNOWN.json"),r);}catch{} }
  finally {
   if(proc!=null) {
    bool exited=false;
    while(!exited) { try { proc.WaitForExit();exited=proc.HasExited; } catch(Exception x) { error=x.GetType().Name;Thread.Sleep(250); } }
    if(exited && held) { r["verified_exited"]=true;r["actual_exit_code"]=proc.ExitCode;r["native_exited_at"]=DateTimeOffset.UtcNow.ToString("o"); }
   }
   try { if(copyOut!=null) copyOut.GetAwaiter().GetResult();if(copyErr!=null) copyErr.GetAwaiter().GetResult(); } catch(Exception x) { error=x.GetType().Name; }
   if(stdout!=null)stdout.Dispose();if(stderr!=null)stderr.Dispose();
   r["ctrl_c_observations"]=interrupts;r["finished_at"]=DateTimeOffset.UtcNow.ToString("o");
   if(error!=null)r["error_type"]=error;
   r["status"]=(bool)r["verified_exited"] ? (identity?"NATIVE_EXITED":"NATIVE_EXITED_IDENTITY_UNKNOWN") : "UNKNOWN_NOT_VERIFIED";
   try { Save(Path.Combine(output,"EXIT.json"),r); } finally { Console.CancelKeyPress-=cancel;if(proc!=null)proc.Dispose(); }
  }
  return (bool)r["verified_exited"]&&identity&&error==null?(int)r["actual_exit_code"]:1;
 }
}
"@
if (!('ZhiyuLocalRoleHostV2' -as [type])) { Add-Type -TypeDefinition $Source }
$Code=[ZhiyuLocalRoleHostV2]::Run($ProjectRoot,$RuntimePath,$Role,[bool]$InitializeBank,[bool]$Bootstrap,$Executable,$Config,[string[]]$NativeArgs,$Owner,$Generation,$Install.namespace,$Install.environment,$RunDirectory,$PSCommandPath)
exit $Code
