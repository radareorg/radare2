using Radare;

void main()
{
	Crypto cto = new Crypto();

	cto.set_algorithm("aes");
	int keysize = cto.get_key_size();
	//cto.set_key();
	//cto.set_iv();

	/* dupplicate object */
	cry = cto.as_new();
}
