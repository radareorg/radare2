@echo off

set INCLUDE=C:\PellesC\Include\;C:\PellesC\Include\Win\;
set LIB=C:\PellesC\Lib\;C:\PellesC\Lib\Win\;
set name=BeaEngine

echo ____________________________________
echo *
echo *  COMPILATION with POCC.EXE (Pelles C)
echo *
echo ____________________________________
\PellesC\bin\Pocc /Ze /W0 %name%.c


echo ____________________________________
echo *
echo *   CREATE LIB with POLIB.EXE (Pelles C)
echo *
echo ____________________________________
\PellesC\bin\Polib /out:%name%.lib %name%.obj
pause





