param([Parameter(Mandatory = $true)][string]$TargetBinary)
$ErrorActionPreference = 'Stop'
try {
    $item = Get-Item -LiteralPath $TargetBinary
    if ($item.PSIsContainer) { exit 1 }
    $version = $item.VersionInfo.ProductVersion
    if ($version -notmatch '^\d+\.\d+\.\d+(?:\.0)?$') { exit 1 }
    Write-Output $version
} catch { exit 1 }
