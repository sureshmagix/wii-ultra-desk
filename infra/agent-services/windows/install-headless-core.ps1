param(
  [Parameter(Mandatory = $true)][string]$AgentPath,
  [Parameter(Mandatory = $true)][string]$StateDirectory
)

$ErrorActionPreference = 'Stop'
if (-not [System.IO.Path]::IsPathFullyQualified($AgentPath) -or -not [System.IO.Path]::IsPathFullyQualified($StateDirectory)) {
  throw 'AgentPath and StateDirectory must be absolute paths.'
}
if (-not (Test-Path -LiteralPath $AgentPath -PathType Leaf)) { throw 'AgentPath does not exist.' }
if (-not (Test-Path -LiteralPath $StateDirectory -PathType Container)) {
  New-Item -ItemType Directory -Path $StateDirectory | Out-Null
}
# LocalService is non-administrative. It receives a distinct identity/state and
# therefore must be paired independently from any signed-in desktop user.
& sc.exe create WIIUltraDeskCore binPath= ('"{0}" daemon --state-dir "{1}"' -f $AgentPath, $StateDirectory) start= auto obj= 'NT AUTHORITY\LocalService'
if ($LASTEXITCODE -ne 0) { throw 'sc.exe create failed; no fallback account is used.' }
& icacls.exe $StateDirectory /inheritance:r /grant 'NT AUTHORITY\LOCAL SERVICE:(OI)(CI)F' /grant 'SYSTEM:(OI)(CI)F' | Out-Null
& sc.exe failure WIIUltraDeskCore reset= 86400 actions= restart/5000/restart/5000/""/0 | Out-Null
& sc.exe start WIIUltraDeskCore
