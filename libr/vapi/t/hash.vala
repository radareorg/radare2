using GLib;
using Radare;
/* using Radare.Hash */

public class HashExample
{
	private static void printChecksum(string str, uint8 *buf, int size)
	{
		stdout.printf(str);
		for(int i=0;i<size; i++)
			stdout.printf("%02x", buf[i]);
		stdout.printf("\n");
	}

	public static void main(string[] args)
	{
		/* calculate crc32 */
		stdout.printf("CRC32: %x\n", Hash.crc32("hello", 5));

		/* directly calculate md5 */
		Hash.State st = new Hash.State(true);
		printChecksum("Single MD5: ", (uint8*)st.md5("helloworld", 10), Hash.Size.MD5);

		/* incrementally calculate md5 */
		st = new Hash.State(false);
		st.md5("hello", 5);
		st.md5("world", 5);
		printChecksum("Incremental MD5: ", (uint8*)st.md5(null,0), Hash.Size.MD5);
		st.init(Hash.Algorithm.ALL);
	}
}
