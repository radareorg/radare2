@echo off

set INCLUDE=C:\Program Files\PellesC\Include\;C:\Program Files\PellesC\Include\Win\;
set LIB=C:\Program Files\PellesC\Lib\;C:\Program Files\PellesC\Lib\Win64\;
set name=BeaEngine

echo ____________________________________
echo *
echo *  COMPILATION with POCC.EXE (Pelles C)
echo *
echo ____________________________________

"\Program Files\PellesC\bin\pocc" /Tamd64-coff /Ze /W2 %name%.c


echo ____________________________________
echo *
echo *   CREATE LIB with POLIB.EXE (Pelles C)
echo *
echo ____________________________________

"\Program Files\PellesC\bin\PoLib" /MACHINE:X64 /out:%name%64.lib %name%.obj
pause





