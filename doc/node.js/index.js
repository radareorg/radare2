
/*

Author : pancake <pancake@nopcode.org>

Date: 2015-03-31

From inside r2

	r2 -c '#!pipe node index.js' /bin/ls

Or from the shell:

	node .

*/

var r2p = require ("r2pipe")
var http = require('http');
var express = require('express');

function runWebServer(r) {
	r.cmd ("e http.root", function(wwwroot) {
		wwwroot = wwwroot.trim ();
		r.cmd ("e http.port", function(port) {
			port = +port.trim ();
			r.cmd ("e scr.color=false", function() {});
			r.cmd ("e scr.interactive=false", function() {});
			r.cmd ("e scr.html=true", function(){});
			var app = express();
			app.all('/cmd/*', function(req,res) {
				var cmd = unescape (req.url.substring (5));
				console.log ("cmd:", cmd);
				r.cmd (cmd, function (data) {
					res.send(data);
				});
			});
			app.use(express.static(wwwroot));
			r.cmd ("?e http://localhost:`e http.port`/p", function (data) {
				console.log (data.replace(' ','').trim());
			})
			app.listen (port);
		});
	});
}

if (process.env.R2PIPE_IN) {
	var r = r2p.rlangpipe(runWebServer);
} else {
	var targetfile = "/bin/ls";
	if (process.argv.length>2) {
		targetfile = process.argv[2];
	}
	var r = r2p.pipe (targetfile, runWebServer);
}
