/* utils.js - Public Domain - copyright 2013 - pancake */

var fs = require ('fs');
var exec = require('child_process').exec;
var cmds = 0;
var mkdir_callbacks = {};

var U = module.exports = {
  red: "\x1b[31m",
  green: "\x1b[32m",
  reset: "\x1b[0m",
  slurp: function(file) {
    return fs.readFileSync (file);;
  },
  exists: function (f) {
    try { return !!fs.statSync (f);
    } catch(e) { return false; }
  },
  exec: function (cmd, cb) {
    cmds ++;
    exec(cmd,cb);
/*
    if (cmds>10) {
      setTimeout (function () {
exec(cmd,cb);
        //exec (cmd, function() { cb(a,b,c);cmds--; });
      }, 300);
    } else {
//      exec (cmd, function(a,b,c) { cb(a,b,c);cmds--; });
exec(cmd,cb);
    }
*/
  },
  error: function() {
    var x = arguments
    x[0] = module.exports.red + x[0];
    x[x.length-1] = x[x.length-1] + module.exports.reset;
    console.log (x[0]);
	process.exit (1);
  },
  print: function() {
    var x = arguments
    x[0] = module.exports.green + x[0];
    x[x.length-1] = x[x.length-1] + module.exports.reset;
    console.log (x[0]);
  },
  load_config: function() {
    this.slurp (file)
  },
  merge: function(I, defaults) {
    for (var a in defaults)
      I[a] = I[a] || defaults[a];
    return I;
  },
  iterate: function(list, cb, eb) {
    if (list && list.length>0) {
      var count = list.length;
      (function iterate (list, cb, eb) {
        if (list.length>0) {
          cb (list[0],
            function() { iterate (list.slice(1), cb, eb); },
            function() { count--; if (eb && count==0) eb(true); }
);
        } else if (eb) eb (false);
      })(list, cb, eb);
    } else {
      //if (cb) cb ();
      if (eb) eb (false);
    }
  },
  mkdir_p: function (path, mode, cb, position) {
    mode = mode || 0755;
    position = position || 0;
    parts = require ('path').normalize (path).split('/');
    if (position == 0) {
      if (mkdir_callbacks[path]) {
        mkdir_callbacks[path].push (cb);
        return;
      } else {
        mkdir_callbacks[path] = [cb];
      }
    }
    function callbacks(x) {
      for (var i in mkdir_callbacks[path])
        mkdir_callbacks[path][i](x);
      mkdir_callbacks[path] = undefined;
    }
    if (position >= parts.length)
      return callbacks (false); // full path created

    var directory = parts.slice (0, position + 1).join('/');
    fs.stat (directory, function (err) {
      if (err === null) {
        return U.mkdir_p (path, mode, cb, position + 1);
      }
      fs.mkdir (directory, mode, function (err) {
         if (err)
           return callbacks(true);
         U.mkdir_p (path, mode, cb, position + 1);
      })
    });
  }
}
