<{include sys.r}>

puts(8)
{
	.var0 = strlen(.arg0);
	write($1, .arg0, .var0);
}
