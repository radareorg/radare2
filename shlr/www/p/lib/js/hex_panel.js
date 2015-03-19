// HEXDUMP PANEL
var HexPanel = function () {
  this.block = 1024;
  this.base = "entry0";
  this.first = 0;
  this.last = 0;
  this.lines = {};
  this.scrolling = false;
  this.renaming = null;
  this.dwors = null;
  this.renameOldValue = "";
  this.rbox = null;
  this.address = null;
  this.scroll_offset = 0;
};
HexPanel.prototype.scrollTo = function(x,y) {
};
HexPanel.prototype.render = function() {
  r2ui.seek("$$", false);
  $("#center_panel").unbind( "click" );
  $(document).unbind( "keypress" );
  $(document).unbind( "click" );
  $(document).unbind( "dblclick" );

  $("#center_panel").scroll(on_hex_scroll);
  $(document).keypress(handle_hex_keypress);
  $(document).dblclick(rename_dword);
  // $(document).click(rename_dword);
  // $(document).dblclick(handle_hex_double_click);
  // Context menu for disas addresses:
  $(document).contextmenu({
      delegate: ".addr",
      menu: [
          {title: "jump to address<kbd>g</kbd>", cmd: "goto"},
          {title: "rename<kbd>n</kbd>", cmd: "rename"},
          {title: "add comment<kbd>;</kbd>", cmd: "comment"},
          {title: "code<kbd>c</kbd>", cmd: "define"},
          {title: "undefine<kbd>u</kbd>", cmd: "undefine"},
          {title: "random colors<kbd>R</kbd>", cmd: "randomcolors"},
          {title: "switch disasm/graph<kbd>s</kbd>", cmd: "switchview"}
      ],
      preventSelect: true,
      taphold: true,
      preventContextMenuForPopup: true,
      show: false
  });
}
function handle_hex_keypress(inEvent) {
  var keynum = inEvent.keyCode || inEvent.charCode || inEvent.which || 0;
  var key = String.fromCharCode(keynum);
}
// function handle_hex_click(inEvent) {
//  console.log(1);
// }
// function handle_hex_double_click(inEvent) {
//  console.log(2);
// }
function scroll_to_hexaddress(address, pos) {
  if (address === undefined || address === null) return;
  var offset = 0;
  if (pos == "top") offset = $('#center_panel').height();
  else if (pos == "bottom") offset = 0;
  else offset = window.innerHeight / 2;
  var elements = $(".hexaddr.hexaddr_" + address);
  if (elements === undefined || elements === null) return;
  if (elements[0] === undefined || elements[0] === null) return;
  var top = elements[0].documentOffsetTop() - offset;
  top = Math.max(0,top);
  $('#center_panel').scrollTo(top, {axis: 'y'});
  r2ui._dis.scroll_offset = top;
}
function on_hex_scroll() {
  if (!r2ui._hex.scrolling) {
    r2ui._hex.scrolling = true;
    var scroll_offset = $("#center_panel").scrollTop();
    var top_offset = $(".hexoffset").height() - $("#center_panel").height();
    var container_element = $("#hex_tab");
    if (scroll_offset === 0 ) {
      var new_lines = get_hexdump(r2ui._hex.first - r2ui._hex.block + 16);
      for (var offset in r2ui._hex.lines) {
        new_lines[offset] = r2ui._hex.lines[offset];
      }
      r2ui._hex.lines = new_lines;
      html = "<div class='hex'>";
      html += render_hexdump(r2ui._hex.lines);
      html += "</div>";
      $("#hex_tab").html(html);
      scroll_to_hexaddress("0x"+r2ui._hex.first.toString(16), "bottom");
      r2ui._hex.first = r2ui._hex.first - r2ui._hex.block + 16;
    } else if (scroll_offset > top_offset-10) {
      var new_lines = get_hexdump(r2ui._hex.last - 16);
      for (var offset in new_lines) {
        r2ui._hex.lines[offset] = new_lines[offset];
      }
      r2ui._hex.last = r2ui._hex.last - 16 + r2ui._hex.block;
      html = "<div class='hex'>";
      html += render_hexdump(r2ui._hex.lines);
      html += "</div>";
      $("#hex_tab").html(html);
      scroll_to_hexaddress("0x"+r2ui._hex.last.toString(16), "top");
    }
    $(".dword").click(function(inEvent) {
      if ($(inEvent.target).hasClass('dword')) {
        var dword = inEvent.target.className.split(" ").filter(function(x) { return x.substr(0,"dword_".length) == "dword_"; });
        $('.autohighlighti').removeClass('autohighlighti');
        $("." + dword).addClass('autohighlighti');
      }
    });
    r2ui._hex.scrolling = false;
  }
};

function get_hexdump(addr) {
  var l = {};
  r2.cmd ("px " + r2ui._hex.block + "@" + addr, function (x) {
    var lines = x.split('\n');
    for (var i in lines) {
      if (i > 1 && i < lines.length-1) {
        var offset = lines[i].split('  ')[0];
        var dwords = (lines[i].split('  ')[1]).split(' ');
        var text = lines[i].split('  ')[2].match(/.{1,2}/g);
        var line = { 'offset': offset, 'dwords': dwords, 'text': text};
        l[offset] = line;
      }
    }
  });
  return l;
}
function color_dword(dword) {
  return dword
        .replace(/(7f)/gi, function(x){return "<font class='ec_b0x7f'>" + x + "</font>";})
        .replace(/(ff)/gi, function(x){return "<font class='ec_b0xff'>" + x + "</font>";})
        .replace(/(00)/gi, function(x){return "<font class='ec_b0x00'>" + x + "</font>";});
}
function uncolor_dword(cdword) {
  return cdword.replace(/(<([^>]+)>)/ig,"");
}
function render_hexdump(lines) {
  r2ui._hex.scrolling = true;
  var hexoffset = "<div class='hexoffset'><div><div>";
  var hexdump = "<div class='hexdump' style='color: white;'>";
  var hextext = "<div class='hextext'>";
  for (var l in lines) {
    var line = lines[l];
    hexoffset += "<span class='hexaddr ec_offset hexaddr_" + address_canonicalize(line.offset) + "'>" + line.offset + "</span><br>";
    for (var i in line.dwords) {
      var offset_dec = parseInt(line.offset, 16);
      offset_dec = offset_dec + i*2;
      dword_offset = "0x" + offset_dec.toString(16);
      hexdump += "<span class='dword dword_" + address_canonicalize(dword_offset) + " line_" + address_canonicalize(line.offset) +"'>" + color_dword(line.dwords[i]) + "</span> ";
    }
    hexdump += "<br>";
    for (var i in line.text) {
      var offset_dec = parseInt(line.offset, 16);
      offset_dec = offset_dec + i*2;
      dword_offset = "0x" + offset_dec.toString(16);
      hextext += "<span class='dword dword_" + address_canonicalize(dword_offset) + "'>" + line.text[i] + "</span>";
    }
    hextext += "<br>";
  }
  hextext += "</div>";
  hexdump += "</div>";
  hexoffset += "</div></div></div>";
  return hexoffset + hexdump + hextext;
};
HexPanel.prototype.seek = function(addr) {
  this.base = addr;
  this.first = parseInt(addr, 16);
  this.last = parseInt(addr, 16) + this.block;
  this.lines = get_hexdump(addr);
  html = "<div class='hex'>";
  html += render_hexdump(this.lines);
  html += "</div>";
  $("#hex_tab").html(html);
  $(document).on('dblclick','.dword', rename_dword);
  $(document).on('mouseenter','.dword', highlight_in);
  $(document).on('mouseleave','.dword', highlight_out);
  $(document).on('mouseenter','.dword font', highlight_in);
  $(document).on('mouseleave','.dword font', highlight_out);
  r2ui._hex.scrolling = false;
};
function handleInputHexChange() {
  if (r2ui._hex.renaming !== null && r2ui._hex.rbox.value.length > 0) {
    var value = r2ui._hex.rbox.value;
    value = value.match(/^[0-9a-f]{0,4}$/gi);
    if (value === null) {
      alert("Invalid dword");
      value = r2ui._hex.renameOldValue;
    }
    if (value.length < 4) {
      var zeroes = "0";
      var padding = 5 - value.length;
      for (var i = 0; i < padding; i++) { zeroes += "0"; }
      value = (zeroes + value).slice(padding * -1);
    }
    if (value !== r2ui._hex.renameOldValue) {
      r2.cmdj("wx 0x" + value.substring(0,2) + " @ " + parseInt(r2ui._hex.dword,16), function(x) {});
      r2.cmdj("wx 0x" + value.substring(2,4) + " @ " + (parseInt(r2ui._hex.dword,16)+1), function(x) {});
    }
    r2ui._hex.renaming[0].innerHTML = "<span class='dword dword_" + r2ui._hex.dword + " line_" + r2ui._hex.address + "'>" + color_dword(value) + "</span>";
    $('.autohighlighti').removeClass('autohighlighti');
    $(".dword_" + r2ui._hex.dword).addClass('autohighlighti');
    r2ui._hex.renaming = null;
    r2ui._hex.rbox = null;
  }
}
function rename_dword(inEvent) {
  var write = true;
  r2.cmdj("ij", function(x) {
    if (x['core']['mode'].indexOf("w") == -1) {
      write = false;
      alert("Not in write mode");
    }
  });
  if (!write) return;
  var element = null;
  if ($(inEvent.target).hasClass('dword')) {
    element = $(inEvent.target);
  } else if ($(inEvent.target).parent().hasClass('dword')) {
    element = $(inEvent.target).parent();
  } else {
    return;
  }
  if (r2ui._hex.renaming === null && element !== null && element.hasClass("dword")) {
    var classes = element[0].className.split(' ');
    var dword = 0;
    var offset = 0;
    for (var i in classes) {
      if (classes[i].indexOf('dword_') > -1) {
        dword = classes[i].substr(6);
      } else if (classes[i].indexOf('line_') > -1) {
        offset = classes[i].substr(5);
      }
    }
    r2ui._hex.dword = dword;
    r2ui._hex.address = offset;
    r2ui._hex.renaming = element;
    r2ui._hex.renameOldValue = uncolor_dword(element[0].innerHTML);

    var form = document.createElement('form');
    form.setAttribute("onSubmit", "handleInputHexChange(); return false;");
    form.setAttribute("style", "display:inline;");
    r2ui._hex.rbox = document.createElement('input');
    r2ui._hex.rbox.setAttribute("type", "text");
    r2ui._hex.rbox.setAttribute("id", "rename");
    r2ui._hex.rbox.setAttribute("style", "border-width: 0;padding: 0; background-color:yellow; font-family: monospace; font-size: 10pt;");
    r2ui._hex.rbox.setAttribute("size", "4");
    r2ui._hex.rbox.setAttribute("maxlength", "4");
    r2ui._hex.rbox.setAttribute("value",r2ui._hex.renameOldValue);
    r2ui._hex.rbox.setSelectionRange(r2ui._hex.renameOldValue.length, r2ui._hex.renameOldValue.length);
    r2ui._hex.renaming[0].innerHTML = "";
    form.appendChild(r2ui._hex.rbox);
    r2ui._hex.renaming[0].appendChild(form);
    setTimeout('r2ui._hex.rbox.focus();', 200);
    inEvent.returnValue=false;
    inEvent.preventDefault();
  }
}
function highlight_in(inEvent) {
  var element = null;
  if ($(inEvent.target).hasClass('dword')) {
    element = inEvent.target;
  } else if ($(inEvent.target).parent().hasClass('dword')) {
    element = $(inEvent.target).parent()[0];
  } else {
    return;
  }
  var dword = element.className.split(" ").filter(function(x) { return x.substr(0,"dword_".length) == "dword_"; });
  $("." + dword).addClass('autohighlighti');
}
function highlight_out(inEvent) {
  $('.autohighlighti').removeClass('autohighlighti');
}
function highlight_dword(inEvent) {
  if ($(inEvent.target).hasClass('dword')) {
    var dword = inEvent.target.className.split(" ").filter(function(x) { return x.substr(0,"dword_".length) == "dword_"; });
    $('.autohighlighti').removeClass('autohighlighti');
    $("." + dword).addClass('autohighlighti');
  }
}
