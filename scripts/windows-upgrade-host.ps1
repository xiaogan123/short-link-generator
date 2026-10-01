param(
    [ValidateSet('Inspect', 'RemoveOwnedLocation')][string]$Mode = 'Inspect',
    [string]$ExpectedInstall,
    [ValidateSet('Registry64', 'Registry32')][string]$RegistryView = 'Registry64'
)
$ErrorActionPreference = 'Stop'

$product = '短连接生成器'
$uninstallKey = "Software\Microsoft\Windows\CurrentVersion\Uninstall\$product"
$locationKey = "Software\shortlink\$product"

try {
    if ($Mode -eq 'RemoveOwnedLocation') {
        if ([string]::IsNullOrWhiteSpace($ExpectedInstall) -or
            -not [IO.Path]::IsPathFullyQualified($ExpectedInstall)) {
            throw 'An absolute owned installation path is required.'
        }
        $view = [Enum]::Parse([Microsoft.Win32.RegistryView], $RegistryView)
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::CurrentUser, $view)
        try {
            $key = $base.OpenSubKey($locationKey, $true)
            if ($null -eq $key) { throw 'Owned install-location key is missing.' }
            try {
                $actual = [string]$key.GetValue('')
                if (-not [string]::Equals([IO.Path]::GetFullPath($actual),
                        [IO.Path]::GetFullPath($ExpectedInstall),
                        [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'Install-location key is not owned by this run.'
                }
                if ($key.GetSubKeyNames().Count -ne 0) {
                    throw 'Install-location key contains unknown subkeys.'
                }
                foreach ($name in $key.GetValueNames()) {
                    if ($name -ne '' -and $name -ne 'Installer Language') {
                        throw 'Install-location key contains unknown values.'
                    }
                }
            } finally { $key.Close() }
            $base.DeleteSubKey($locationKey, $false)
        } finally { $base.Close() }
        Write-Output 'OWNED_LOCATION_REMOVED'
        exit 0
    }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class UpgradeKnownFolder {
    [DllImport("shell32.dll")]
    private static extern int SHGetKnownFolderPath(ref Guid id, uint flags, IntPtr token, out IntPtr path);
    public static string Read(string text) {
        Guid id = new Guid(text);
        IntPtr pointer;
        int hr = SHGetKnownFolderPath(ref id, 0, IntPtr.Zero, out pointer);
        Marshal.ThrowExceptionForHR(hr);
        try { return Marshal.PtrToStringUni(pointer); }
        finally { Marshal.FreeCoTaskMem(pointer); }
    }
}
'@
    $roaming = [UpgradeKnownFolder]::Read('3EB685DB-65F9-4CF6-A03A-E3EF65729F3D')
    $local = [UpgradeKnownFolder]::Read('F1B32785-6FBA-4FCF-9D55-7B8E7F157091')
    if ([string]::IsNullOrWhiteSpace($roaming) -or [string]::IsNullOrWhiteSpace($local)) {
        throw 'Known Folder query returned an empty path.'
    }
    function Test-ReparseAncestor([string]$path) {
        $current = [IO.Path]::GetFullPath($path)
        while ($true) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if (-not $item.PSIsContainer) { throw 'Known Folder ancestry is not a directory.' }
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return $true }
            $parent = [IO.Directory]::GetParent($current)
            if ($null -eq $parent) { return $false }
            $current = $parent.FullName
        }
    }
    $roamingReparse = Test-ReparseAncestor $roaming
    $localReparse = Test-ReparseAncestor $local

    $registrations = [System.Collections.Generic.List[object]]::new()
    foreach ($hiveName in @('CurrentUser', 'LocalMachine')) {
        foreach ($viewName in @('Registry64', 'Registry32')) {
            $hive = [Enum]::Parse([Microsoft.Win32.RegistryHive], $hiveName)
            $view = [Enum]::Parse([Microsoft.Win32.RegistryView], $viewName)
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
            try {
                foreach ($spec in @(@{ kind = 'uninstall'; path = $uninstallKey },
                                    @{ kind = 'location'; path = $locationKey })) {
                    $key = $base.OpenSubKey($spec.path)
                    if ($null -eq $key) { continue }
                    try {
                        $registrations.Add(@{
                            hive = $hiveName; view = $viewName; kind = $spec.kind
                            installLocation = [string]$key.GetValue('InstallLocation')
                            uninstallString = [string]$key.GetValue('UninstallString')
                            displayVersion = [string]$key.GetValue('DisplayVersion')
                            defaultValue = [string]$key.GetValue('')
                        })
                    } finally { $key.Close() }
                }
            } finally { $base.Close() }
        }
    }

    $shortcutPaths = [System.Collections.Generic.List[string]]::new()
    foreach ($folderName in @('Programs', 'CommonPrograms', 'DesktopDirectory', 'CommonDesktopDirectory')) {
        $folder = [Environment]::GetFolderPath($folderName)
        if ([string]::IsNullOrWhiteSpace($folder)) { throw 'Shortcut folder could not be resolved.' }
        $shortcutPaths.Add([IO.Path]::Combine($folder, "$product.lnk"))
        if ($folderName -like '*Programs') {
            $shortcutPaths.Add([IO.Path]::Combine($folder, $product, "$product.lnk"))
        }
    }
    $shortcuts = [System.Collections.Generic.List[object]]::new()
    $shell = New-Object -ComObject WScript.Shell
    foreach ($path in ($shortcutPaths | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $path -PathType Any -ErrorAction Stop) {
            $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
            $target = if ($item.PSIsContainer) { '' } else { [string]$shell.CreateShortcut($path).TargetPath }
            $shortcuts.Add(@{ path = $path; target = $target })
        }
    }
    @{ roaming = $roaming; local = $local;
       roamingReparse = $roamingReparse; localReparse = $localReparse;
       registrations = @($registrations.ToArray()); shortcuts = @($shortcuts.ToArray()) } |
        ConvertTo-Json -Compress -Depth 5
} catch {
    [Console]::Error.WriteLine('Windows upgrade host inspection or owned cleanup failed.')
    exit 1
}
