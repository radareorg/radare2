var fs = require('fs');
var spawn = require('child_process').spawn;
var os = require('os');
var path = require('path');
var curl = require('node-curl').Curl;

const INPUT_FOLDER_ARG = 2;
const OUTPUT_FOLDER_ARG = 3;

const SYMBOL_SERVER = 'Microsoft-Symbol-Server/6.11.0001.402';
const DOWNLOABLE_LINK = 'http://msdl.microsoft.com/download/symbols';
const GUID = 'guid';
const DBG_FNAME = 'dbg_file';
const CURL = 'curl';
const CABEXTRACTOR = (os.platform() != 'win32') ? 'cabextract' : 'expand';
const RABIN = 'rabin2'
var IN_FOLDER = '';
var OUT_FOLDER = '';
const EOL = os.EOL;

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
      file = path.join(dir, file);
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

var extract_pdb_file = function (archive_name, dbg_fname) {
  var spawn = require('child_process').spawn;

  if (os.platform() == 'win32') {
    cab_extractor_cmd = spawn(CABEXTRACTOR, [archive_name, OUT_FOLDER + dbg_fname]);
  } else {
    cab_extractor_cmd = spawn(CABEXTRACTOR, ['-d', OUT_FOLDER, archive_name]);
  }

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
  var archive_name = dbg_fname;
  var link_end = '';
  var spawn = require('child_process').spawn;
   
  archive_name = archive_name.substring(0, archive_name.length - 1)  + '_';  
  link_end = '/' + dbg_fname + '/' + guid + '/' + archive_name;

  var stream = fs.createWriteStream(archive_name, {flags:'a'});
  
  console.log("downloading file: " + archive_name);
  
  var curl_ = new curl(DOWNLOABLE_LINK + link_end, {RAW:0}, function(err) {
    console.info(this);
    return;
  });

  curl_.setOpt('URL', DOWNLOABLE_LINK + link_end);
  curl_.setOpt('USERAGENT', SYMBOL_SERVER);

  curl_.on('data', function(chunk) {
    stream.write(chunk);
    return chunk.length;
  });
  
  curl_.on('error', function(e) {
    console.log('File: ' + archive_name + 'has not been downloaded successfully');
    curl_.close();
    return;
  });
  
  curl_.on('end', function() {
    console.log('File ' + archive_name + 'has been downloaded and saved successfully');
    console.log('Decompress of file: ' + archive_name);
    extract_pdb_file(archive_name, dbg_fname);

    this.close();
  });

  curl_.perform();
};

var downloader = function (currentValue, index, array) {
  var curr_guid = '';
  var curr_dbg_fname = '';
  var saved_guid_and_dbg_fname = [];
  var spawn = require('child_process').spawn;

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
    data.toString().split(EOL).map(function (str) {
      var parts = str.split(' ');

      if (parts[0].indexOf(GUID) != -1) {
	curr_guid = parts.pop(); //parts[0].substring(GUID.length).trim();
      } else if (parts[0].indexOf(DBG_FNAME) != -1) {
	curr_dbg_fname = parts.pop(); //[0].substring(DBG_FNAME.length).trim();
	if (curr_guid != '' && curr_dbg_fname != '') {
	  curl_start(curr_guid, curr_dbg_fname);
	} else {
	  console.log('there is no guid and debug file information in binary');
	  console.log('check version of rabin2 or maybe this is not PE binary');
	  process.exit(1);
	}
      }
    });
  });
};

IN_FOLDER = process.argv[INPUT_FOLDER_ARG];
OUT_FOLDER = process.argv[OUTPUT_FOLDER_ARG];

// TODO: does not correct work if write like if (IN_FOLDER) {
if (IN_FOLDER === undefined || IN_FOLDER === null) {
  console.log("set please input folder");
  print_usage();
  process.exit(1);
}

// TODO: does not correct work if write like if (OUT_FOLDER) {
if (OUT_FOLDER === undefined || OUT_FOLDER === null) {
  OUT_FOLDER = IN_FOLDER;
}

walk(IN_FOLDER, function(err, results) {
  if (err) {
    console.log('Error while walking the directory.Error: ' + err);
    process.exit(1);
  }
    
  results.forEach(downloader);
});

