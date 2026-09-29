param(
  [Parameter(Mandatory = $true)]
  [ValidateRange(1, 2147483647)]
  [int]$TargetPid,
  [ValidateRange(1, 60)]
  [int]$PollSeconds = 25
)

$ErrorActionPreference = 'Stop'
$clock = [System.Diagnostics.Stopwatch]::StartNew()
while ($clock.Elapsed.TotalSeconds -lt $PollSeconds) {
  try {
    $targetProcess = [System.Diagnostics.Process]::GetProcessById($TargetPid)
    $targetProcess.Refresh()
    if ($targetProcess.HasExited) {
      Write-Output 'EXITED'
      exit 20
    }
    if ($targetProcess.MainWindowHandle -ne [IntPtr]::Zero) {
      Write-Output 'WINDOW'
      exit 0
    }
  } catch [System.ArgumentException] {
    Write-Output 'EXITED'
    exit 20
  } catch {
    Write-Output 'OBSERVATION_ERROR'
    exit 22
  }
  Start-Sleep -Milliseconds 250
}
Write-Output 'NO_WINDOW'
exit 21
