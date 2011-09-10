all:
	gcc -o r2-install r2-install.c `pkg-config --cflags --libs gtk+-2.0`

g:
	gtkamlc --pkg gtk+-2.0 r2-install.gtkon

c:
	gtkamlc --pkg gtk+-2.0 -C r2-install.gtkon

clean:
	rm -f r2-install
