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
    var saved_guid_and_dbg_fname = [];
    var spawn = require('child_process').spawn,
    ls = spawn('rabin2', ['-I', currentValue]);

    ls.stdout.on('data', function (data) {     
	data.toString().split('\n').map(function (str) {
	  var curr_guid = '';
	  var curr_dbg_fname = '';
	  var parts = str.split(' ');
	  
	  if (parts[0].indexOf("guid") != -1) {
	    curr_guid = parts[0].substring("guid".length).trim();
	    console.log(curr_guid);
	  } else if (parts[0].indexOf("dbg_fname") != -1) {
	    curr_dbg_fname = parts[0].substring("dbg_fname".length).trim();
	    console.log(curr_dbg_fname);
	    //saved_guid_and_dbg_fname.push({ "guid" : curr_guid, "dbg_fname" : curr_dbg_fname});
	  }
	});
    });
};

walk("/home/inisider/Downloads/dlls", function(err, results) {
    if (err) throw err;
  
    results.forEach(downloader);
});
