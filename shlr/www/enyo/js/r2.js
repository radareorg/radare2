/* radare2 Copyleft 2013 pancake */

var r2 = {};

var backward = false;
var next_curoff = 0;
var next_lastoff = 0;
var prev_curoff = 0;
var prev_lastoff = 0;

r2.root = ""; // prefix path

Array.prototype.push = function (x) {
  this[this.length] = x;
}

Array.prototype.pop = function () {
  var x = this[this.length-1];
  delete this[this.length-1];
  return x;
}

/* helpers */
function dump(obj) {
  var x = "";
  for (var a in obj) x += a+"\n";
  alert (x);
}

function objtostr(obj) {
  var str = "";
  for (var a in obj)
    str += a+": "+obj[a] + ",\n";
  return str;
}

function Ajax (method, uri, body, fn) {
  var x = new XMLHttpRequest ();
  x.open (method, uri, false);
  x.setRequestHeader ('Accept', 'text/plain');
  x.setRequestHeader ('Accept', 'text/html');
  x.setRequestHeader ("Content-Type", "application/x-ww-form-urlencoded; charset=UTF-8");
  x.onreadystatechange = function (y) {
    if (x.status == 200) {
      if (fn) fn (x.responseText);
    } else console.error ("ajax "+x.status)
  }
  x.send (body);
}

r2.assemble = function (offset, opcode, fn) {
  var off = offset? "@"+offset:'';
  r2.cmd ('"pa '+opcode+'"'+off, fn);
} 

r2.disassemble = function (offset, bytes, fn) {
  var off = offset? "@"+offset:'';
  var str = 'pi @b:'+bytes+off;
  r2.cmd (str, fn);
}

r2.get_disasm = function (offset, length, cb) {
  // TODO: honor offset and length
  r2.cmd ("b 512;pd", cb);
}

r2.config_set = function (fn) {
  // TODO
}

r2.config_get = function (fn) {
  // TODO
}

r2.set_flag_space = function (ns, fn) {
  r2.cmd ("fs "+ns, fn);
}

r2.set_flag_space = function (ns, fn) {
  r2.cmd ("fs "+ns, fn);
}

r2.get_flags = function (fn) {
  r2.cmd ("fj", function (x) {
    if (x) x = JSON.parse (x);
    fn (x);
  });
} 

r2.get_opcodes = function (off, n, cb) {
  r2.cmd ("pdj @"+off+"!"+n, function (json) {
    var o = JSON.parse (json);
    cb (o);
  });
}

r2.get_bytes = function (off, n, cb) {
  r2.cmd ("pcj @"+off+"!"+n, function (json) {
    var o = JSON.parse (json);
    cb (o);
  });
}

r2.get_info = function (cb) {
  r2.cmd ("ij", function (json) {
    cb (JSON.parse (json));
  });
}
r2.bin_imports = function (cb) {
  r2.cmd ("iij", function (json) {
    cb (JSON.parse (json));
  });
}

r2.bin_symbols = function (cb) {
  r2.cmd ("isj", function (json) {
    cb (JSON.parse (json));
  });
}

r2.bin_sections = function (cb) {
  r2.cmd ("iSj", function (json) {
    var o = JSON.parse (json);
    cb (o);
  });
}

r2.cmd = function (c, cb) {
  Ajax ('GET', r2.root+"/cmd/"+encodeURI (c), '', function (x) {
    if (cb) cb (x);
  });
}

r2.alive = function (cb) {
  r2.cmd ("b", function (o) {
    var ret = false;
    if (o && o.length () > 0)
      ret = true;
    if (cb) cb (o);
  });
}

r2.get_logger = function (obj) {
  if (typeof (obj) != "object")
    obj = {};
  obj.last = 0;
  obj.events = {};
  obj.interval = null;
  r2.cmd ("ll", function (x) {
    obj.last = +x;
  });
  obj.load = function (cb) {
    r2.cmd ("lj "+(obj.last+1), function (ret) {
      var json = JSON.parse (ret);
      if (cb) cb (json);
    });
  }
  obj.clear = function (cb) {
    // XXX: fix l-N
    r2.cmd ("l-", cb); //+obj.last, cb);
  }
  obj.send = function (msg, cb) {
    r2.cmd ("l "+msg, cb);
  }
  obj.refresh = function (cb) {
    obj.load (function (ret) {
      //obj.last = 0;
      for (var i = 0; i< ret.length; i++) {
        var message = ret[i];
        obj.events["message"] ({
          "id": message[0],
          "text": message[1]
        });
        if (message[0] > obj.last)
          obj.last = message[0];
      }
      if (cb) cb ();
    });
  }
  obj.autorefresh = function (n) {
    if (!n) {
      if (obj.interval)
        obj.interval.stop ();
      return;
    }
    function to() {
      obj.refresh (function () {
        //obj.clear ();
      });
      setTimeout (to, n*1000);
      return true;
    }
    obj.interval = setTimeout (to, n*1000);
  }
  obj.on = function (ev, cb) {
    obj.events[ev] = cb;
    return obj;
  }
  return obj;
}

r2.filter_asm = function (x, display) {
  var curoff = backward? prev_curoff: next_curoff;;
  var lastoff = backward? prev_lastoff: next_lastoff;;
  var lines = x.split (/\n/g);
  r2.cmd ("s", function (x) { curoff = x; });
  for (var i=lines.length-1;i>0;i--)  {
    var a = lines[i].match (/0x([a-fA-F0-9]*)/);
    if (a && a.length>0) {
      lastoff = a[0].replace (/:/g, "");
      break;
    }
  }
  if (display == "afl") {
    //hasmore (false);
    var z = "";
    for (var i=0;i<lines.length;i++)  {
      var row = lines[i].replace (/\ +/g," ").split (/ /g);
      z += row[0]+ "  "+row[3]+"\n";
    }
    x = z;
  } else
  if (display[0] == 'f') {
    //hasmore (false);
    if (display[1] == 's') {
      var z = "";
      for (var i=0; i<lines.length; i++)  {
        var row = lines[i].replace (/\ +/g," ").split (/ /g);
        var mark = row[1]=='*'? '*': ' ';
        var space = row[2]? row[2]: row[1];
        if (!space) continue;
        z += row[0]+ " "+mark+" <a href=\"javascript:runcmd('fs "+
          space+"')\">"+space+"</a>\n";
      }
      x = z;
    } else {
    }
  } else
  if (display[0] == "i") {
    //hasmore (false);
    if (display[1]) {
      var z = "";
      for (var i=0;i<lines.length;i++)  {
        var elems = lines[i].split (/ /g);
        var name = "";
        var addr = "";
        for (var j=0;j<elems.length;j++)  {
          var kv = elems[j].split (/=/);
          if (kv[0] == "addr") addr = kv[1];
          if (kv[0] == "name") name = kv[1];
          if (kv[0] == "string") name = kv[1];
        }
        z += addr+ "  "+name+"\n";
      }
      x = z;
    }
  } //else hasmore (true);

  function haveDisasm(x) {
    if (x[0]=='p' && x[1]=='d') return true;
    if (x.indexOf (";pd") != -1) return true;
    return false;
  }
  if (haveDisasm (display)) {
    x = x.replace (/function:/g,"<span style=color:red>function:</span>");
    x = x.replace (/;(\s+)/g, ";");
    x = x.replace (/;(.*)/g, "// <span style='color:red'>$1</span>");
    x = x.replace (/(bl|call)/g, "<b style='color:green'>call</b>");
    x = x.replace (/(jmp|bne|beq|jnz|jae|jge|jbe|jg|je|jl|jz|jb|ja|jne)/g, "<b style='color:green'>$1</b>");
    x = x.replace (/(dword|qword|word|byte|movzx|movsxd|cmovz|mov\ |lea\ )/g, "<b style='color:orange'>$1</b>");
    x = x.replace (/(hlt|leave|retn|ret)/g, "<b style='color:red'>$1</b>");
    x = x.replace (/(add|sub|mul|div|shl|shr|and|not|xor|inc|dec|sar|sal)/g, "<b style='color:orange'>$1</b>");
    x = x.replace (/(push|pop)/g, "<b style='color:magenta'>$1</b>");
    x = x.replace (/(test|cmp)/g, "<b style='color:green'>$1</b>");
    x = x.replace (/nop/g, "<b style='color:blue'>nop</b>");
    x = x.replace (/(sym|fcn|imp|loc).(.*)/g, "<a href='javascript:r2ui.seek(\"$1.$2\")'>$1.$2</a>");
  }
  x = x.replace (/0x([a-zA-Z0-9]*)/g, "<a href='javascript:r2ui.seek(\"0x$1\")'>0x$1</a>");
// registers
  if (backward) {
    prev_curoff = curoff;
    prev_lastoff = lastoff;
  } else {
    next_curoff = curoff;
    next_lastoff = lastoff;
    if (!prev_curoff)
      prev_curoff = next_curoff;
  }
  return x;
}
