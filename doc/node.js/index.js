
/*

r2 -c '#!pipe node index.js' /bin/ls

*/

var r2p = require ("r2pipe")
var http = require('http');
var express = require('express');

function runWebServer(r) {
	r.cmd ("e http.root", function(wwwroot) {
		wwwroot = wwwroot.trim ();
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

		r.cmd ("?e it works!", function (data) {
			console.log ("Test:", data);
		})
		app.listen (8080);
	});
}

var r = r2p.rlangpipe(runWebServer);
