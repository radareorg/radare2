fun1(32) {
	.var0 = "Hello World";
	puts(.var0);
}

fun2@inline() {
	puts(.arg0);
	#puts(.arg1);
}

main@global(32)
{
	.var0 = "Funny cow";
	puts(.var0);
	fun1();
	puts(.var0);
}
