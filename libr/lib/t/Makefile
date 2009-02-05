all: plugin.so test-plugin
	@true

plugin.so:
	gcc -Wall -o plugin.so -shared plugin.c -I../../include

test-plugin:
	gcc -Wall -o test-plugin test-plugin.c -I ../../include ../../lib/*.a -ldl

clean:
	-rm -f plugin.so test-plugin
