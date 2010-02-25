#
# Test for various control flow statements
#

ok@data(){"var4 is ok"}

main@global(64) {
# counter
	.var4 = 3;
# enable/disable loop
	.var8 = 1;
# message
	.var12 = "Conditional stuff";
	.var38 = "Loop %d\n";

	if (.var4 = $3) {
		puts($ok);
	}

	##if ( .var0<$10) {
	while(.var4<$10) {
		puts(.var12);
		.var4 += 1;
	}

	puts(.var12);

	# if(.var8) # This is an infinite loop
	{
		printf(.var38, .var4);
		.var4 -=1;
	} while(.var4>0);
	0;
}
