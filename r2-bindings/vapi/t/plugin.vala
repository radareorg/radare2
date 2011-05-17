/* vala r2 plugin */
using Radare;

[CCode (has_target = false)]
public bool mycall(void *user, string cmd) {
	print ("hello world\n");
	if (cmd.has_prefix (":bc")) {
		if (cmd.length == 3) {
			print ( "BinCrowd radare2 plugin help:\n"+
				":bc pull       retrieve signatures from server\n"+
				":bc push       upload signatures to server\n"+
				"See: http://bincrowd.zynamics.com/\n");
		} else {
			RCore* core = (RCore*)user;
			string p = (string)(((char*)cmd)+4);
			print ("Hello World from Vala! (%s)\n", p);
			//core->cmd ("pd 4 @ eip", false);
			//core->cmd ("x", false);
			/* hack to get address of anal .. FIXME */
			RAnal *anal = (RAnal*)(&core->anal);
			foreach (var f in anal->fcns) {
				print ("fun %s @ 0x%08llx\n", f.name, f.addr);
			}
		}
		return true;
	}
	return false;
}

/*
private const RCmdPlugin plugin = {
	"my plugin", mycall
};

const RCmdStruct radare_plugin = {
	RLibType.CMD, ref plugin
};
*/
