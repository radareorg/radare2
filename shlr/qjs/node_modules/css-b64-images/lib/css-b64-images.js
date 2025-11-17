'use strict';

var fs = require('fs'),
  Path = require('path'),
  MAX_SIZE = 4096,
  /* Adapted from https://gist.github.com/2594980 */
  imgRegex = /url\s?\(['"]?(.*?)(?=['"]?\))/gi,
  absoluteUrlRegex = /^\//,
  externalUrlRegex = /http/,
  mediatypes = {
    '.eot'       : 'application/vnd.ms-fontobject',
    '.gif'       : 'image/gif',
    '.ico'       : 'image/vnd.microsoft.icon',
    '.jpg'       : 'image/jpeg',
    '.jpeg'      : 'image/jpeg',
    '.otf'       : 'application/x-font-opentype',
    '.png'       : 'image/png',
    '.svg'       : 'image/svg+xml',
    '.ttf'       : 'application/x-font-ttf',
    '.webp'      : 'image/webp',
    '.woff'      : 'application/x-font-woff',
    '.woff2'     : 'application/font-woff2'
  };

module.exports = {
  fromFile: fromFile,
  fromString: fromString
};

function fromString(css, relativePath, rootPath , options, cb) {
  if(!cb) {
    cb = options;
    options = {maxSize: MAX_SIZE};
  }
  if(!css.replace && css.toString) css = css.toString();
  var urls = [],
      match = imgRegex.exec(css);
  while(match) {
    urls.push(match[1]);
    match = imgRegex.exec(css)
  }
  forEachSeries(urls, base64img, function(err){
    if(err) return cb(err, css);
    cb(null, css);
  });

  function base64img(imageUrl, cb){
    if(externalUrlRegex.test(imageUrl)) {
      return cb(new Error('Skip ' + imageUrl + ' External file.'), css);
    }

    var imagePath;
    if(absoluteUrlRegex.test(imageUrl)) {
      imagePath = Path.join(rootPath, imageUrl.substr(1));
    }else{
      imagePath = Path.join(relativePath, imageUrl);
    }
    replaceUrlByB64(imageUrl, imagePath, css, options, function (err, newCss){
      if(err) return cb(err, css);
      css = newCss;
      cb();
    });
  }
}

function fromFile(cssFile, root, options, cb) {
  if(!cb) {
    cb = options;
    options = {maxSize: MAX_SIZE};
  }
  fs.readFile(cssFile, function(err, css){
    if(err) return cb(err, css);
    fromString(css.toString(), Path.dirname(cssFile), root, options, cb);
  });
}

function replaceUrlByB64(imageUrl, imagePath, css, options, cb){
  imagePath = imagePath.replace(/[?#].*/g, '');
  fs.stat(imagePath, function(err, stat){
    if(err) return cb(err, css);
    if (stat.size > options.maxSize){
      return cb(new Error('Skip ' + imageUrl + ' Exceed max size'), css);
    }
    fs.readFile(imagePath, 'base64', function(err, img){
      if(err) return cb(err, css);
      var ext = Path.extname(imagePath);
      var newCss = css.replace(imageUrl, 'data:' + mediatypes[ext] + ';base64,' + img);
      cb(null, newCss);
    });
  });
}

/* Adapted from async. Continue on error. */
function forEachSeries(arr, iterator, callback) {
  callback = callback || function () {};
  if (!arr.length) {
    return callback();
  }
  var completed = 0, errs = [];
  var iterate = function () {
    iterator(arr[completed], function (err) {
      if (err) {
        errs.push(err);
      }
      completed += 1;
      if (completed === arr.length) {
        if(errs.length) return callback(errs);
        callback(null);
      }
      else {
        iterate();
      }
    });
  };
  iterate();
}
