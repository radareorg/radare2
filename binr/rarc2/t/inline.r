foo@inline() {
	puts(.var0);
}

main@global(128) {
	.var0 = "Inline works";
	foo();
}
