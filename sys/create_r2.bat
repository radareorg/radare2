@echo off
if not exist "%MESON_INSTALL_DESTDIR_PREFIX%\bin" (
  mkdir "%MESON_INSTALL_DESTDIR_PREFIX%\bin"
)
echo @"%%~dp0\radare2" %%*> "%MESON_INSTALL_DESTDIR_PREFIX%\bin\r2.bat"
exit /b 0
