@echo off

set cwd=%CD%
set buildDir=%cwd%\build
set distDir=%cwd%\dist

rmdir %buildDir% /s /q
rmdir %distDir% /s /q


python meson.py %buildDir% --backend ninja --buildtype release --default-library static --prefix %distDir%
ninja -C %buildDir% install