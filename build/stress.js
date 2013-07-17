switch (2) {
case 0:
	var U = require ("./make.js/utils.js");
	U.iterate ([1,2,3,4], function(x, next, done) {
		setTimeout (function() {
			console.log ("---");
			next ();
		},500);
	}, function(x) {
		console.log ("done: "+x);
	});
	break;
case 1:
	var U = require ("./make.js/utils.js");
	U.iterate ([1,2,3,4], function(x, next, done) {
		setTimeout (function() {
			console.log (arguments);
			done ();
		},1000);
		next();
	}, function(x) {
		console.log ("done: "+x);
	});
	break;
case 2:
	var U = require ("./make.js/utils.js");
	U.iterate ([1,2,3,4], function(x, next, done) {
		setTimeout (function() {
			console.log ("NOW RUN "+x+ "--- ");
			next();
		}, 1000*Math.random()%10000);
	}, function(x) {
		console.log ("done: "+x);
	});
}
