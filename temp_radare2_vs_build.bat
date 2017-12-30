@echo off

set cwd=%CD%
set buildDir=%cwd%\build
set distDir=%cwd%\dist

rd %buildDir% /s /q
rd %distDir% /s /q


python meson.py %buildDir% --backend vs2017 --buildtype release --default-library static --prefix %buildDir% --libdir bin --bindir bin
rem cd %buildDir% 
rem msbuild /maxcpucount /p:Configuration=Release /p:OutDir=%buildDir%\bin radare2.sln
rem cd %cwd%
