REM see .github/workflows/ci.yml for details
REM iscc radare2-win-installer\radare2.iss /DRadare2Location=..\radare2-install\* /DLicenseLocation=..\COPYING.LESSER /DIcoLocation=radare2.ico /DMyAppVersion=${{ steps.extract_version.outputs.branch }}
