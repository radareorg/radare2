var fs = require('fs');
var spawn = require('child_process').spawn;

const INPUT_FOLDER_ARG = 2;
const OUTPUT_FOLDER_ARG = 3;

const SYMBOL_SERVER = 'Microsoft-Symbol-Server/6.11.0001.402';
const DOWNLOABLE_LINK = 'http://msdl.microsoft.com/download/symbols';
const GUID = 'guid';
const DBG_FNAME = 'dbg_fname';
const CURL = 'curl';
const CABEXTRACTOR = 'cabextract';
const RABIN = 'rabin2'
var IN_FOLDER = '';
var OUT_FOLDER = '';

var print_usage = function() {
  console.log("usage: node pdb_downloader.js INPUT_FOLDER [OUT_FOLDER]");
  console.log("*if OUT_FOLDER is not set than OUT_FOLDER equal to INPUT_FOLDER");
}

var walk = function (dir, done) {
  var results = [];
  fs.readdir(dir, function (err, list) {
    if (err) return done(err);
    var pending = list.length;
    if (!pending) return done(null, results);
    list.forEach(function (file) {
      file = dir + '/' + file;
      fs.stat(file, function (err, stat) {
        if (stat && stat.isDirectory()) {
          walk(file, function (err, res) {
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

var extract_pdb_file = function (archive_name) {
  var spawn = require('child_process').spawn;

  cab_extractor_cmd = spawn(CABEXTRACTOR, ['-d', OUT_FOLDER, archive_name]);

  cab_extractor_cmd.on('error', function (err) {
    console.log(CABEXTRACTOR + 'error', err);
    console.log('check if cabextract is installed');
    process.exit(1);
  });
    
  cab_extractor_cmd.on('exit', function (code) {
    if (code != 0) {
      console.log("Failed to extract with code: " + code);
    } else {
      fs.unlink(archive_name);
      console.log("File " + archive_name + " has been uncompressed successfully");
    }      
  });
};

var curl_start = function(guid, dbg_fname) {
  var tmp_dbg_fname = dbg_fname;
  var link_end = '';
  var spawn = require('child_process').spawn;
   
  tmp_dbg_fname = tmp_dbg_fname.substring(0, tmp_dbg_fname.length - 1)  + '_';  
  link_end = '/' + dbg_fname + '/' + guid + '/' + tmp_dbg_fname;
  
  console.log("downloading file: " + tmp_dbg_fname);
  
  curl_cmd = spawn(CURL, ['-A', SYMBOL_SERVER, DOWNLOABLE_LINK + link_end, '-o', tmp_dbg_fname]);
  
  curl_cmd.on('error', function (err) {
    console.log(CURL + 'error', err);
    console.log('check if curl is installed'); 
    process.exit(1);
  });
  
  curl_cmd.on('exit', function (code) {
    if (code != 0) {
      console.log('Failed: ' + code);
    } else {
      console.log('File ' + tmp_dbg_fname + 'has been downloaded');
      console.log('Decompress of file: ' + tmp_dbg_fname); 
      extract_pdb_file(tmp_dbg_fname);
    }
  });
};

var downloader = function (currentValue, index, array) {
  var curr_guid = '';
  var curr_dbg_fname = '';
  var saved_guid_and_dbg_fname = [];
  var spawn = require('child_process').spawn,
  rabin2_cmd = spawn(RABIN, ['-I', currentValue]);

  // skip pdb files
  if (currentValue.indexOf('pdb') != -1) {
    return;
  }
  
  rabin2_cmd.stdout.on('error', function (err) {
    console.log('check if rabin is installed');
    process.exit(1);
  });
  
  rabin2_cmd.stdout.on('data', function (data) {     
    data.toString().split('\n').map(function (str) {
      var parts = str.split(' ');

      if (parts[0].indexOf(GUID) != -1) {
	curr_guid = parts[0].substring(GUID.length).trim();
      } else if (parts[0].indexOf(DBG_FNAME) != -1) {
	curr_dbg_fname = parts[0].substring(DBG_FNAME.length).trim();
	curl_start(curr_guid, curr_dbg_fname);
      }
    });
  });
};

IN_FOLDER = process.argv[INPUT_FOLDER_ARG];
OUT_FOLDER = process.argv[OUTPUT_FOLDER_ARG];

if (IN_FOLDER === undefined || IN_FOLDER === null) {
  console.log("set please input folder");
  print_usage();
  process.exit(1);
}

if (OUT_FOLDER === undefined || OUT_FOLDER === null) {
  OUT_FOLDER = IN_FOLDER;
}

walk(IN_FOLDER, function(err, results) {
  if (err) throw err;
    
  results.forEach(downloader);
});

