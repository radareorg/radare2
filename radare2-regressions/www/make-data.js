var fs = require('fs')

const input = "../stats.csv"
const output = "data.js"

var data = {
	labels : [],
	datasets : [
		{ // OK
			fillColor : "rgba(0,220,0,0.1)",
			strokeColor : "rgba(220,220,220,1)",
			pointColor : "rgba(220,220,220,1)",
			pointStrokeColor : "#fff",
			data : []
		},
		{ // FIXED
			fillColor : "rgba(0,220,0,0.1)",
			strokeColor : "rgba(151,187,205,1)",
			pointColor : "rgba(151,187,205,1)",
			pointStrokeColor : "#fff",
			data : []
		},
		{ // BROKEN
			fillColor : "rgba(250,100,105,0.1)",
			strokeColor : "rgba(151,187,205,1)",
			pointColor : "rgba(151,187,205,1)",
			pointStrokeColor : "#fff",
			data : []
		},
		{ // FAILED
			fillColor : "rgba(255,0,0,0.1)",
			strokeColor : "rgba(151,187,205,1)",
			pointColor : "rgba(151,187,205,1)",
			pointStrokeColor : "#fff",
			data : []
		}
	]
}

fs.readFile (input, function (err,txt) {
	if (err) {
		console.error ("Cannot open input file");
		process.exit(1);
	}
	var rows = (""+txt).split(/\n/);
	for (var i in rows) {
		var cols = rows[i].split(/,/);
		if (cols.length>4) {
			var label = cols[0].split(/-/)[1];
			data.labels.push (label);
			data.datasets[0].data.push (cols[1]);
			data.datasets[1].data.push (cols[2]);
			data.datasets[2].data.push (cols[3]);
			data.datasets[3].data.push (cols[4]);
		}
	}
	fs.writeFileSync (output, "const data = "+
		JSON.stringify (data)+"\n");
});
