using GLib;
using Radare;
/* using Radare.Hash */

public class HashExample
{
	private static void printChecksum(string str, uint8 *buf, int size)
	{
		print (str);
		for(int i=0;i<size; i++)
			print ("%02x", buf[i]);
		print ("\n");
	}

	public static void main(string[] args)
	{
		/* calculate crc32 */
		print ("CRC32: %x\n", RHash.crc32("hello", 5));

		/* directly calculate md5 */
		var st = new RHash (true, RHash.Algorithm.ALL);
		printChecksum ("Single MD5: ",
			(uint8*)st.do_md5 ("helloworld", 10), RHash.Size.MD5);

		/* incrementally calculate md5 */
		st = new RHash (false, RHash.Algorithm.ALL);
		st.do_md5 ("hello", 5);
		st.do_md5 ("world", 5);
		printChecksum ("Incremental MD5: ",
			(uint8*)st.do_md5 (null,0), RHash.Size.MD5);
		//st.init (true, RHash.Algorithm.ALL);
	}
}
