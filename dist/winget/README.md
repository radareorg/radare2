# Radare2 Winget Package

This directory contains the necessary files to build and package Radare2 for Windows using Winget.

## Building the Package

1. Run `preconfigure.bat` to set up the build environment.

2. Run `configure.bat` or `meson setup --buildtype release b` to configure the build.

3. Run `make.bat` in this directory to build Radare2 and create the zip package.

## Creating the Winget Manifest

1. Upload the generated `radare2-6.0.7-w64.zip` to a release on GitHub or another hosting service.

2. Calculate the SHA256 hash of the zip file: `certutil -hashfile radare2-6.0.7-w64.zip SHA256`

3. Update the `InstallerSha256` in `RadareOrg.Radare2.yaml` with the calculated hash.

4. Update the `InstallerUrl` if necessary.

## Submitting to Winget

1. Fork the [winget-pkgs](https://github.com/microsoft/winget-pkgs) repository.

2. Create the directory structure: `manifests/r/RadareOrg/Radare2/6.0.7/`

3. Place the `RadareOrg.Radare2.yaml` file in that directory.

4. Submit a pull request.

For more information, see the [Winget documentation](https://learn.microsoft.com/en-us/windows/package-manager/package/manifest).