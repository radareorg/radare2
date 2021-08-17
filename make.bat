:: Build (and eventually install) r2 for windows
ninja -C b
echo "Installing r2 in C:\radare2"
set DESTDIR=C:\radare2
ninja -C b install