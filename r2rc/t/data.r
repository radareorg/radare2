msg@data() { "Hello World %d\n" }
num@data() { 33 }

# Note, that the pointers to numbers doesnt require '$'
main@global() {
	printf($msg, num);
}
