/* Run: java -Djava.library.path=. TestRBin */

import java.util.*;
import org.radare.radare2.*;

class TestRBin {
	static {
		System.loadLibrary("r_bin");
	}
	public static void main (String args[]) {
		RBin b;
		RBinSection s;
		RBinSectionVector sv;
		long nsects;
		int i;

		b = new RBin ();
		b.load ("/bin/ls", false);
		sv = b.get_sections ();
		nsects = sv.size ();

		for (i = 0; i < nsects; i++) {
			s = sv.get (i);
			System.out.printf ("offset=0x%08x size=%05d %s\n",
				s.getOffset (), s.getSize (), s.getName ());
		}
	}
}
