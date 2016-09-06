var fs = require ('fs');

var nfd_in = +process.env.R2PIPE_IN;
var nfd_out = +process.env.R2PIPE_OUT;

if (!nfd_in || !nfd_out) {
	console.error ("Only from r2");
	process.exit(1);
}

var fd_in = fs.createReadStream(null, {fd: nfd_in});
var fd_out = fs.createWriteStream(null, {fd: nfd_out});

console.error ("Running r2pipe io using fds: ", nfd_in, nfd_out);

fd_in.on('data', function(data) {
	data = data.slice(0,-1);
	var obj_in = JSON.parse (data);
	console.error ("got data(",obj_in,")");
	var obj = {result:obj_in.count, data:[1,2,3]};
	fd_out.write (JSON.stringify (obj)+"\x00");
});

fd_in.on('end', function() {
	console.log ("--> THE END");
});
