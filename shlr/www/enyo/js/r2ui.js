var r2ui = {};

r2ui.history = [];
r2ui.history_idx = 0;

r2ui.load_colors = function () {
  // change css on the fly!
  var colors = {};
  r2.cmdj("ecj", function(x) {
    for (var i in x) {
      colors[".ec_" + i] = "rgb(" + String(x[i]) + ")";
    }
  });
  for (var k in document.styleSheets) {
    var mysheet = document.styleSheets[k];
    var myrules = mysheet.cssRules? mysheet.cssRules: mysheet.rules;
    var targetrule;
    for (var j in myrules) {
      if (myrules[j].selectorText !== undefined && myrules[j].selectorText !== null) {
        if (myrules[j].selectorText.toLowerCase().indexOf(".ec_") === 0) {
          var sel = myrules[j].selectorText.toLowerCase();
          var color = colors[sel];
          if (color !== undefined && color !== null) {
            myrules[j].style.color = color;
          }
        }
      }
    }
  }
}

r2ui.history_push = function (x) {
  // console.log("history push");
  if (x != r2ui.history_last()) {
    if (r2ui.history_idx != r2ui.history.length)
      r2ui.history = r2ui.history.splice (0,r2ui.history_idx);
    r2ui.history_idx++;
    //alert ("push "+x);
    r2ui.history.push (x);
  }
  // console.log(r2ui.history_idx + "/" + r2ui.history.length);
}

r2ui.history_pop = function () {
  // console.log("history pop");
  if (r2ui.history_idx == r2ui.history.length) r2ui.history_idx--;
  // console.log(r2ui.history_idx + "/" + r2ui.history.length);
  return r2ui.history.pop();
}

r2ui.history_last = function () {
  if (r2ui.history.length > 0) {
    return r2ui.history[r2ui.history_idx - 1];
  }
}

r2ui.history_prev = function () {
  // console.log("history prev");
  if (r2ui.history_idx > 1) r2ui.history_idx--;
  // console.log(r2ui.history_idx + "/" + r2ui.history.length);
  return r2ui.history[r2ui.history_idx - 1];
}

r2ui.history_next = function () {
  // console.log("history next");
  var ret = r2ui.history[r2ui.history_idx];
  if (r2ui.history_idx < r2ui.history.length) r2ui.history_idx++;
  // console.log(r2ui.history_idx + "/" + r2ui.history.length);
  return ret;
}

r2ui.next_instruction = function() {
  var offset = parseInt(r2ui.history_last(), 16);
  r2.cmd ("pdl 1", function (x) {
    offset += parseInt(x.trim());
  });
  return "0x" + offset.toString(16);
}

r2ui.prev_instruction = function() {
  var offset = parseInt(r2ui.history_last(), 16);
  r2.cmdj("pdfj", function (x) {
    if (x !== undefined && x !== null) {
      for (var i in x.ops) {
        if (i === 0) continue;
        var opcode = x.ops[i];
        if (opcode.offset == offset) {
          offset =  x.ops[i-1].offset;
          break;
        }
      }
    }
  });
  return "0x" + offset.toString(16);;
}

r2ui.seek = function (addr, push, scroll) {
  // Resolve flag in case we dont have an address
  if (addr.indexOf("0x") === 0) {
    addr = address_canonicalize(addr);
  } else {
    var a = r2.get_flag_address(addr);
    if (a !== null) {
      addr = address_canonicalize(a);
    } else {
      r2.cmd("? $$~[1]", function(x) {
        addr = address_canonicalize(x.replace('\n',''));
      });
    }
  }

  if (push) r2ui.history_push(addr);

  // What is this for?
  if (r2ui.ra.getIndex ()==2) r2ui.ra.setIndex (1);

  r2.cmd ("s " + addr, function () {
    r2ui._dis.seek(addr, scroll);
    //r2ui._dis.scrollTo (0, 0);
    r2ui._hex.seek(addr);
    r2ui._hex.scrollTo(0, 0);
  });
}

r2ui.seek_in_graph = function (addr, push) {
  if (push) r2ui.history_push (addr);

  // What is this for?
  if (r2ui.ra.getIndex ()==2) r2ui.ra.setIndex (1);

  r2.cmd ("s "+addr, function () {
    rehighlight_iaddress(addr);
    r2ui._hex.seek(addr);
    r2ui._hex.scrollTo(0, 0);
  });
}

r2ui.seek_prev = function () {
  // XXX. this is only for disasm
  var addr = r2ui.history.pop ();
  r2.cmd("s "+addr, function () {
    r2ui._dis.seek(addr);
    r2ui._dis.scrollTo(0, 0);
    r2ui._hex.seek(addr);
    r2ui._hex.scrollTo(0, 0);
  });
}

/* used from mainpanel */
r2ui.openpage = function(addr, idx) {
  if (idx === undefined) {
    idx = addr;
    addr = undefined;
  }
  if (addr !== undefined) {
    r2ui.seek(addr, true);
  }

  // What is this for?
  if (r2ui.ra.getIndex()==2) r2ui.ra.setIndex(1);

  r2ui.mp.openPage(idx);

}

r2ui.opendis = function (addr) {
  r2ui.openpage(addr, 0);
}

r2ui.openhex = function (addr) {
  r2ui.openpage(addr, 2);
}


