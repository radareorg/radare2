@echo off
setlocal
powershell -ExecutionPolicy bypass^
 -Command "& {$process = Start-Process $args[0] $args[1..($args.length-1)] -PassThru; exit $process.id}"^
 r2 -N -e http.port=9393 -qq -c=h bins/elf/arg
set child=%errorlevel%
REM curl -s --retry 30 --retry-delay 1 --retry-connrefused http://127.0.0.1:9393/ > nul 2>&1
REM r2 -N -qc '=0 pd 10' -C http://127.0.0.1:9393/cmd
REM r2 -N -c 'b $s;pr~:0..9' -qcq http://127.0.0.1:9393/
curl -s --retry 30 --retry-delay 1 --retry-connrefused http://127.0.0.1:9393/ 2>nul | head -n 11
taskkill /PID %child% /T /F > nul 2>&1
