struct PadStr {
	char pad[6];
	char str1[11];
};
union Str {
	char str0[5];
	PadStr str1;
}