#!/usr/bin/node
// $ r2 -qc '#!pipe node pipe-node.js' -

var isMain = process.argv[1] == __filename;

var fs = require ("fs");

function langPipe () {
	var IN = +process.env.R2PIPE_IN;
	var OUT = +process.env.R2PIPE_OUT;

	var r2io = {
		r: fs.createReadStream (null, {fd: IN}),
		w: fs.createWriteStream (null, {fd: OUT})
	};

	var replies = [];
	r2io.cmd = function(cmd, cb) {
		replies.push (cb);
		r2io.w.write (cmd);
	}
	r2io.r.on ('data', function (foo) {
		if (replies.length>0) {
			var cb = replies[0];
			replies = replies.slice(1);
			if (cb) cb (''+foo);
		}
	});

	r2io.repl = function () {
		/* r2 repl implemented in pipe-node.js */
		r2io.r.pipe (process.stdout);
		process.stdin.on ('data', function (chunk) {
			if (replies.length>0) {
				var cb = replies[0];
				replies = replies.slice(1);
				var cb = replies.pop ();
				if (cb) cb (''+chunk);
			}
			r2io.w.write (chunk);
		});
	}
	return r2io;
}

// Example:
if (isMain) {
	var lp = langPipe ();
	lp.cmd ("pd 3", function (x) {
		console.log (x);
		lp.cmd ("px 64", function (y) {
			console.log (y);
			lp.repl ();
		});
	});
} else {
	module.exports = langPipe();
}
