#!/usr/bin/node

/* TODO: use node-daemon and chroot */

/* config */
const nick = "r2bot"
const channel = "#radare"
const msgtimeout = 1000
const host = "irc.freenode.net"
const port = 6667
const file = "/bin/ls"
const Chi = "\x1b[32m"
const Cend = "\x1b[0m"
const print = console.log

var irc;

function finalize() {
	if (irc) irc.privmsg (channel, "byebye");
	print ("^C :D");
	process.exit (0);
}

process.on ('SIGINT', finalize);
process.on ('SIGTERM', finalize);

/* r2 stuff */

print (Chi, "[=>] Initializing r2 core...", Cend);
var r2 = require ('../r_core');

var core = new r2.RCore(), cons = r2.RCons;
var fileName = process.argv[2] || file;

core.bin.load (fileName, 0);
core.config.set ("asm.arch", "x86");
core.config.set ("asm.bits", "32");

core.file_open (fileName, 0, 0);

core.bin_load (null);

core.cmd0 ('? entry0')
core.cmd0 ('pd @entry0')

core.config.set ("io.va", "true");
print ("iova= "+ core.config.get ("io.va"));

core.file_open (fileName, 0, 0);
print ("core->bin = "+core.config);
   core.bin.select_idx (0);
   core.bin_load (null);

core.cmd0 ('? entry0')
core.cmd0 ('pd @entry0')

/* initialize irc connection */
core.config.set ("cfg.sandbox", "true");

print (Chi, "[=>] Connecting to irc ",Cend)
print (Chi, "     HOST: ", host, ":", port, Cend)
print (Chi, "     NICK: ", nick, " ", channel, Cend);
var IRC = require ('irc.js');
irc = new IRC (host, port);

irc.on ('raw', function (data) {
	print (data);
});
irc.on ('connected', function (s) {
	irc.nick (nick);
	irc.join (channel, function (x) {
		irc.privmsg (channel, "hi");
	});
	print ("connected");
});

if (typeof String.prototype.startsWith != 'function') {
	String.prototype.startsWith = function (str){
		return this.slice(0, str.length) == str;
	};
}

irc.on ('privmsg', function (from, to, msg) {
	print('<' + from + '> to ' + to + ': ' + msg);
	if (to[0] != "#" && from == "pancake") {
		if (msg.startsWith ("nick "))
			irc.nick (msg.slice (5));
		else if (msg.startsWith ("join "))
			irc.join (msg.slice (5));
		else if (msg.startsWith ("part "))
			irc.part (msg.slice (5));
		else irc.privmsg (channel, msg)
	} else
	switch (to) {
	case channel:
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
			if (msg.startsWith ("q"))
				o = "not now";
			else if (msg.startsWith ("o") && msg.length >1)
				o = "no open allowed";
			else if (msg.startsWith ("V"))
				o = "i cant do visuals on irc :(";
			else if (msg.startsWith ("ag"))
				o = "graphs cant be seen here.";
			else o = core.cmd_str_pipe (msg);
		}
		if (o != "") (
			function () {
				 var a = o.split (o.indexOf ("\r")!=-1?
					"\r": "\n");
				 var timedmsg = function (x) {
					 irc.privmsg (to, a[0]);
					 a = a.slice (1);
					 if (a.length>0)
					 setTimeout (timedmsg, msgtimeout);
				 }
				 setTimeout (timedmsg, msgtimeout);
			 }
		) ();
		break;
	}
});

irc.connect (nick, 'http://www.radare.org/', 'r2');
