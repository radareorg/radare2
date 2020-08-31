@echo off
setlocal
set SRC=%1
set SRC=%SRC:/=\%\*.sdb
set DST=%2
set DST=%MESON_INSTALL_PREFIX%\%DST:/=\%
md "%DST%"
echo copy "%SRC%" -^> "%DST%\"
copy "%SRC%" "%DST%"
