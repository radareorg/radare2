/* TODO: use node-daemon and chroot */

const nick = "r2bot";
const channel = "#radare";
const msgtimeout = 1000;

var r2 = require ('../r_core');

var core = new r2.RCore(), cons = r2.RCons;
var fileName = process.argv[2] || '/bin/ls';
const JS = JSON.stringify;
const JP = JSON.parse;
const JSHDR = {'Content-type': 'application/json'};

/* XXX FAIL 

var c = core.config
var b = core.bin

c.set ("io.va", "true");
console.log ("iova= "+ c.get ("io.va"));
process.exit(0);

core.bin.load (fileName, 0);
core.bin.select_idx (0);
var info = core.bin.get_info();
core.bin_load ('');

console.log ("TYPE: "+info.type);

core.config.set ("asm.arch", "x86");
core.config.set ("asm.bits", "64");
//core.bin = bin;
*/


core.file_open (fileName, 0, 0);
console.log ("core->bin = "+core.config);
   core.bin.select_idx (0);
   core.bin_load (null);

core.cmd0 ('? entry0')
core.cmd0 ('pd @entry0')

var IRC = require('irc.js');
var irc = new IRC('irc.freenode.net', 6667);
irc.on ('raw', function (data) {
		console.log (data);
		});
irc.on ('connected', function (s) {
	irc.nick ("r2bot");
	irc.join (channel, function (x) {
		irc.privmsg (channel, "hi");
	});
	console.log ("connected");
});

if (typeof String.prototype.startsWith != 'function') {
	String.prototype.startsWith = function (str){
		return this.slice(0, str.length) == str;
	};
}

irc.on('privmsg', function(from, to, msg) {
	console.log('<' + from + '> to ' + to + ': ' + msg);
	switch (to) {
	case  "#radare":
	case  "#radarebot":
		default:
		if (!msg.startsWith ("!")) return;
		var o = "";
		msg = msg.replace (/>/g, "");
		msg = msg.replace (/|/g, "");
		msg = msg.replace (/!/g, "");
		msg = msg.replace (/`/g, "");
		msg = msg.replace (/\t/g, "   ");
		var cmds = msg.split (";");
		for (var i in cmds) {
		msg = cmds[i];
		msg = msg.replace (/^\ */, "");
		if (msg.startsWith ("q")) o = "not now";
		else
		if (msg.startsWith ("o") && msg.length >1) o = "no open allowed";
		else
		if (msg.startsWith ("V")) o = "i cant do visuals on irc :(";
		else
		if (msg.startsWith ("ag")) o = "graphs cant be seen here.";
		else o = core.cmd_str_pipe (msg);
		}
		if (o != "")
			(function () {
				 var a = o.split (o.indexOf ("\r") ==-1? "\n": "\r");
				 var timedmsg = function (x) {
				 irc.privmsg (to, a[0]);
				 a = a.slice (1);
				 if (a.length>0)
				 setTimeout (timedmsg, msgtimeout);
			 }
			 setTimeout (timedmsg, msgtimeout);
			 })();
	break;
		}
	}
);
function finalize() {
	irc.privmsg (channel, "byebye");
	console.log ("byebye");
	process.exit (0);
}

process.on ('SIGINT', finalize);
process.on ('SIGTERM', finalize);

irc.connect (nick, 'http://www.radare.org/', 'r2');

