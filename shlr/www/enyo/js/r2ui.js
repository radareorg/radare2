var r2ui = {};

r2ui.history = [];
r2ui.history_idx = 0;

r2ui.history_push = function (x) {
  if (r2ui.history_idx != r2ui.history.length)
    r2ui.history = r2ui.history.splice (0,r2ui.history_idx);
  r2ui.history_idx++;
//alert ("push "+x);
  r2ui.history.push (x);
}

r2ui.history_pop = function () {
  if (r2ui.history_idx == r2ui.history.length)
    r2ui.history_idx--;
  return r2ui.history.pop();
}

r2ui.history_prev = function () {
  if (r2ui.history_idx>1)
    r2ui.history_idx--;
  var ret = r2ui.history[r2ui.history_idx-1];
  return ret;
}

r2ui.history_next = function () {
//alert(r2ui.history_idx);
//alert(r2ui.history.length);
  var ret = r2ui.history[r2ui.history_idx];
  if (r2ui.history_idx<r2ui.history.length)
    r2ui.history_idx++;
  return ret;
}

// XXX . this is used from disasm()
r2ui.seek = function (addr, x) {
  // XXX. this is only for disasm 
  if (x !== true)
    r2ui.history_push (addr);
  r2.cmd ("s "+addr);
  r2ui._dis.seek (addr);
  r2ui._dis.scrollTo (0, 0);
}

r2ui.seek_prev = function () {
  // XXX. this is only for disasm 
  var addr = r2ui.history.pop ();
  r2.cmd ("s "+addr);
  r2ui._dis.seek (addr);
  r2ui._dis.scrollTo (0, 0);
}

/* used from mainpanel */
r2ui.opendis = function (addr) {
  r2ui.seek (addr);
  if (r2ui.ra.getIndex ()==2)
    r2ui.ra.setIndex (1);
}
