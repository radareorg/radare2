/* radare - LGPL - Copyright 2009 pancake<@nopcode.org> */

[CCode (cheader_filename="r_crypto.h", cprefix="r_crypto", lower_case_cprefix="r_crypto_")]
namespace Radare {
	[Compact]
	[CCode (cname="struct r_crypto_t", free_function="r_crypto_free", cprefix="r_crypto_")]
	public class rCrypto {
		
		[CCode (cprefix="R_CRYPTO_DIR")]
		public enum Direction {
			CIPHER,
			UNCIPHER
		}

		[CCode (cprefix="R_CRYPTO_MODE")]
		public enum Mode {
			ECB,
			CBC,
			OFB,
			CFB
		}

		public rCrypto();
		public bool use(string algorithm);
//		public bool set_key(uint8 *key, Crypto.Mode mode, Crypto.Direction direction);
		public bool set_iv(uint8 *iv);
		public int get_key_size();
		public int update(uint8 *buf, int len);
		public int final(uint8 *buf, int len);
		public uint8* get_output();
	}
}
