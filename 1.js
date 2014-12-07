var fs = require('fs');
var spawn = require('child_process').spawn;

var walk = function(dir, done) {
  var results = [];
  fs.readdir(dir, function(err, list) {
    if (err) return done(err);
    var pending = list.length;
    if (!pending) return done(null, results);
    list.forEach(function(file) {
      file = dir + '/' + file;
      fs.stat(file, function(err, stat) {
        if (stat && stat.isDirectory()) {
          walk(file, function(err, res) {
            results = results.concat(res);
            if (!--pending) done(null, results);
          });
        } else {
          results.push(file);
          if (!--pending) done(null, results);
        }
      });
    });
  });
};

var downloader = function(currentValue, index, array) {
    console.log(currentValue);  
    var spawn = require('child_process').spawn,
    ls = spawn('rabin2', ['-I', currentValue]);

    ls.stdout.on('data', function (data) {
      console.log(data.toString());
      
      /*
	data.toString().split('\r').map(function (str) { 
	var parts = str.split(' ');
	console.log(parts[0]); // key
	console.log(parts[1]); // value
    */
      
    });

   /* });*/
};

walk("/home/inisider/Downloads/dlls", function(err, results) {
    if (err) throw err;
  
    results.forEach(downloader);
});
