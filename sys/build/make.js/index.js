/* make.js - Public Domain - copyright 2013 - pancake */

var U = require ('./utils.js');
var fs = require ("fs");
var cleaning = [];
var targets = [];

module.exports = M = {
  make: function(cfg) {
    var argv = process.argv.slice(2);
    var A = { targets: [] };
    for (var i = 0; i< argv.length; i++) {
      var k = argv[i];
      if (k[0]=='-') {
        switch(k) {
        case '-h':
        case '--help':
          U.print ("Help message");
          process.exit (0);
          break;
        }
      } else A.targets[A.targets.length] = k;
    }
    A.run = function(t) {
      const k = (A.targets[0] == 'clean');
      U.iterate (t||A.targets, function (t, next, done) {
        if (k) {
          M.clean_target (cfg, t);
          next ();
        } else {
          M.run_target (cfg, t, done);
          next ();
        }
      });
    }
    return A;
  },
  mustCompile: function(s, b, file) {
    try {
      var x = fs.statSync (s+'/'+file);
      var y = fs.statSync (b+'/'+file.replace ('.c','.o'));
      return (x.atime > y.atime);
    } catch (e) { }
    return true;
  },
  link: function(cfg, b, n, f, l, cb) {
    var objs = []
    for (var x in f)
      objs.push (b+'/'+f[x].replace ('.c', '.o'));
    var ofile = b+'/'+n;
    var libs = '';
    for (var x in l) {
      var T = cfg[l[x]];
      if (!T)
        U.error ("Cannot find target: "+l[x]);
      libs += ' -L'+T.path+' -l'+T.name;
    }
    if (ofile.indexOf ('/lib'))
      libs += ' -shared';
    var cmd = this.cfg.CC+' -liconv '+libs+' '+
      this.cfg.ldflags+' -o '+ofile+' '+objs.join(' ');
    console.log ("LINK: "+cmd);
    U.exec (cmd, function (oops, out, err) {
      if (oops) console.log (oops, out, err);
      cb ();
    });
  },
  clean: function(s, b, f, cb) {
    U.exec ('rm -rf '+b, function() {
      U.print ("CLEAN done");
    });
  },
  compile: function(s, b, f, cb) {
    if (!f || f.length<1)
      U.error ("Missing list of files in target.");
    var ctr = f.length;
    var done = 0;
    for (var x in f) {
      var file = f[x];
      if (M.mustCompile (s, b, file)) {
    	var sfile = s+'/'+file;
    	var ofile = b+'/'+file.replace ('.c', '.o');
    	(function (cfg) {
    	  var cmd = cfg.CC+' '+cfg.cflags+' -c -o '+
            ofile+' '+sfile;
          U.mkdir_p (b, undefined, function (err) {
    	    if (err) U.error ("Cannot mkdir "+b);
            done++;
    	    U.print (cmd);
    	    U.exec (cmd, function (oops, out, err) {
              if (err) console.log (err);
    	      if (oops) U.error ("Cannot compile: "+file);
    	      if (--ctr<1) cb (done);
    	    });
          });
        })(this.cfg);
      } else {
        ctr--;
    	if (ctr<1) cb (done);
      }
    }
  },
  build_program: function (cfg, t, cb) {
    var sdir = cfg.root+'/'+t.path;
    var bdir = t.path;
    var libname = 'lib'+t.name+'.'+cfg.soext;
    this.cfg = cfg;
    M.compile (sdir, bdir, t.files, function() {
      U.print ("LIB "+libname);
      M.link (cfg, bdir, libname, t.files, t.targets, function() {
    	U.print ("LINK done");
        cb ();
      });
    });
  },
  build_library: function (cfg, t, cb) {
    var sdir = cfg.root+'/'+t.path;
    var bdir = t.path;
    var libname = 'lib'+t.name+'.'+cfg.soext;
    this.cfg = cfg;
    M.compile (sdir, bdir, t.files, function(count) {
      U.print ("LIB "+libname);
      if (count>0 || !U.exists (bdir+'/'+libname)) {
        M.link (cfg, bdir, libname, t.files, t.targets, function() {
          U.print ("LINK done for "+libname);
          cb ();
        });
      }// else cb ();
    });
  },
  clean_target: function(cfg, t) {
    const T = cfg[t];
    function rmrf(p) {
      if (!cleaning[p]) {
        cleaning[p] = true;
        if (p && p.length>1 && U.exists (p)) {
          console.log ("rm -rf "+p);
          U.exec ('rm -rf ./'+p);
        }
      }
    }
    U.iterate (T.targets, function (t, next) {
      M.clean_target (cfg, t);
      rmrf (T.path);
      next ();
    }, function() {
      rmrf (T.path);
    });
  },
  install_target: function() {
    U.error ("TODO: install");
  },
  run_target: function(cfg, t, cb) {
    const T = cfg[t];
    if (targets[t]) {
      targets[t].push (cb);
      return;
    }
    function callbacks(n, x) {
      for (var i in targets[n])
        targets[n][i](x);
      targets[n] = undefined;
    }
    targets [t] = [cb];
    console.log ("DO "+t);
    if (!T) return callbacks (t, false);
    U.print ("Running target "+t);
    U.iterate (T.targets, function (t, next, done) {
      M.run_target (cfg, t, function() {
        done ();
      });
      next ();
    }, function(x) {
console.log ("NOW RUN "+t+ "--- "+x);
//return;
//if (!x) return;
    if (T.type) {
      switch (T.type) {
      case 'program':
        U.print ("Building program: "+T.name);
        M.build_program (cfg, T, function() {
          callbacks (t, true);
        });
        break;
      case 'library':
        U.print ("Building library: "+T.name);
        M.build_library (cfg, T, function() {
          callbacks (t, true);
        });
        break;
      case undefined:
        break;
      default:
        U.error ("Unknown type for target: "+t+" : "+ T.type);
        break;
      }
    }
//callbacks (t, true);
    });
//}, 1000*Math.random()%10000);
    //callbacks (t, true);
/*
if (T.targets) {
    var count = T.targets.length;
    for (var i in T.targets) {
      M.run_target (cfg, T.targets[i], function() {
        count--;
        if (count ==0) {
          console.log ("DONE "+t);
          cb ();
        }
      });
    }
*/
/*
    // Run dependencies
console.log ("T", T, "t", t);
*/
  },
  cast_install: function(I) {
    return merge (I, {
      prefix: '/usr',
      destdir: ''
    });
  },
}
