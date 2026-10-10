$ErrorActionPreference = 'Stop'
& sc.exe stop WIIUltraDeskCore | Out-Null
Start-Sleep -Seconds 2
& sc.exe delete WIIUltraDeskCore
# Intentionally preserves the state directory: deleting identity material
# would make recovery/audit impossible and should be a deliberate separate act.
