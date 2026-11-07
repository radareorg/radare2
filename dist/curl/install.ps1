# radare2 Windows Installer
$INSTALL_DIR = "$HOME\radare2"
if (!(Test-Path $INSTALL_DIR)) {
    Write-Host "Creating installation directory $INSTALL_DIR..."
    New-Item -ItemType Directory -Path $INSTALL_DIR -Force
}

# Get latest release zip
$releaseUrl = "https://api.github.com/repos/radareorg/radare2/releases/latest"
try {
    $releaseInfo = Invoke-RestMethod -Uri $releaseUrl
} catch {
    Write-Error "Failed to fetch latest release info from GitHub API."
    exit 1
}

$asset = $releaseInfo.assets | Where-Object { $_.name -like "*win64.zip" } | Select-Object -First 1
if ($null -eq $asset) {
    Write-Error "Could not find win64.zip in the latest release."
    exit 1
}
$downloadUrl = $asset.browser_download_url

Write-Host "Downloading radare2 from $downloadUrl..."
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile "$INSTALL_DIR\radare2.zip"
} catch {
    Write-Error "Failed to download the zip file."
    exit 1
}

Write-Host "Extracting..."
try {
    Expand-Archive -Path "$INSTALL_DIR\radare2.zip" -DestinationPath $INSTALL_DIR -Force
} catch {
    Write-Error "Failed to extract the zip file."
    exit 1
}
Remove-Item "$INSTALL_DIR\radare2.zip"

# The binaries are usually in the root of the zip or in a bin folder.
# Let's check where ra.exe is.
$exePath = Get-ChildItem -Path $INSTALL_DIR -Filter "ra.exe" -Recurse | Select-Object -First 1

if ($null -eq $exePath) {
    Write-Error "Could not find ra.exe in the extracted files."
    exit 1
}

$binDir = $exePath.DirectoryName
Write-Host "Found binaries in $binDir"

# Add to User PATH permanently
$oldPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($oldPath -notlike "*$binDir*") {
    Write-Host "Adding $binDir to User PATH..."
    $newPath = if ([string]::IsNullOrWhiteSpace($oldPath)) { $binDir } else { "$oldPath;$binDir" }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "Successfully added to PATH."
} else {
    Write-Host "Already in PATH."
}

Write-Host "`nInstallation complete!"
Write-Host "Please restart your terminal or run 'refreshenv' (if you have Chocolatey) to use radare2."
