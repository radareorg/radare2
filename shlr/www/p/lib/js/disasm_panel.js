// DISASSEMBLER PANEL
var DisasmPanel = function () {
  this.display = "flat";
  this.min = 0;
  this.max = 0;
  this.block = 512;
  this.base = "entry0";
  this.selected = null;
  this.selected_offset = null;
  this.tmp_address = null;
  this.renaming = null;
  this.renameOldValue = "";
  this.rbox = null;
  this.panel = $("#disasm_tab")[0];
  this.scroll_offset = null;
  this.minimap = true;
  this.instructions = [];
  this.scrolling = false;
};
DisasmPanel.prototype.render = function(mode) {

  // r2ui.seek("$$", false);
  $("#center_panel").unbind( "click" );
  $(document).unbind( "keypress" );
  $(document).unbind( "click" );
  $(document).unbind( "dblclick" );
  $("#center_panel").scroll(on_scroll);
  $(document).keypress(handleKeypress);
  $(document).click(handleClick);
  $(document).dblclick(handleDoubleClick);
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
      show: false,
      position: function(event, ui){
        return {my: "left+100 top-10", at: "left bottom", of: ui.target};
      },
      beforeOpen: function(event, ui) {
        var address = get_address_from_class(ui.target[0]);
        var xrefs_to = [];
        var xrefs_from = [];
        var xrefto_submenu = null;
        var xreffrom_submenu = null;
        r2.cmd("axf @" + address, function(x){
          var lines = x.split('\n');
          for (var l in lines) {
            if (lines[l] !== "") xrefs_to[xrefs_to.length] = lines[l];
          }
        });
        if (xrefs_to.length > 0) {
          $(document).contextmenu("showEntry", "xrefs_to", true);
          var refs = [];
          for (var r in xrefs_to) {
            var addr = xrefs_to[r].split(' ')[1];
            var type = xrefs_to[r].split(' ')[0];
            refs[refs.length] = {title: addr + "<kbd>" + type + "</kbd>", cmd: "jumpto_" + addr};
          }
          var xrefto_submenu = {title: "xrefs to", children: refs};
        }
        r2.cmd("axt @" + address, function(x){
          var lines = x.split('\n');
          for (var l in lines) {
            if (lines[l] !== "") xrefs_from[xrefs_from.length] = lines[l];
          }
        });
        if (xrefs_from.length > 0) {
          $(document).contextmenu("showEntry", "xrefs_from", true);
          var refs = [];
          for (var r in xrefs_from) {
            var addr = xrefs_from[r].split(' ')[1];
            var type = xrefs_from[r].split(' ')[0];
            refs[refs.length] = {title: addr + "<kbd>" + type + "</kbd>", cmd: "jumpto_" + addr};
          }
          var xreffrom_submenu = {title: "xrefs from", children: refs};
        }
        var menu = [
            {title: "jump to address<kbd>g</kbd>", cmd: "goto"},
            {title: "rename<kbd>n</kbd>", cmd: "rename"},
            {title: "add comment<kbd>;</kbd>", cmd: "comment"},
            {title: "code<kbd>c</kbd>", cmd: "define"},
            {title: "undefine<kbd>u</kbd>", cmd: "undefine"},
            {title: "random colors<kbd>R</kbd>", cmd: "randomcolors"},
            {title: "switch disasm/graph<kbd>s</kbd>", cmd: "switchview"}
        ];
        if (xreffrom_submenu !== null || xrefto_submenu !== null) {
          if (xrefto_submenu !== null) menu[menu.length] = xrefto_submenu;
          if (xreffrom_submenu !== null) menu[menu.length] = xreffrom_submenu;
        }
        $(document).contextmenu("replaceMenu", menu);

        r2.cmdj("pdj 1 @" + address, function(x) {
          if(x) {
            if(x[0].fcn_addr == x[0].offset) {
              $(document).contextmenu("showEntry", "define", false);
              $(document).contextmenu("showEntry", "undefine", true);
            } else {
              $(document).contextmenu("showEntry", "define", true);
              $(document).contextmenu("showEntry", "undefine", false);
            }
          }
        });

        if (ui.target.hasClass('insaddr')) {
          $(document).contextmenu("showEntry", "comment", true);
          $(document).contextmenu("showEntry", "rename", true);
        } else {
          $(document).contextmenu("showEntry", "comment", false);
          $(document).contextmenu("showEntry", "rename", true);
          $(document).contextmenu("showEntry", "define", false);
          $(document).contextmenu("showEntry", "undefine", false);
        }
        if (ui.target.hasClass('reloc') || ui.target.hasClass('symbol') || ui.target.hasClass('import')) {
          $(document).contextmenu("showEntry", "comment", false);
          $(document).contextmenu("showEntry", "rename", false);
          $(document).contextmenu("showEntry", "define", false);
          $(document).contextmenu("showEntry", "undefine", false);
        }
        // Context manu on disasm panel
        if (!$.contains($("#disasm_tab")[0], ui.target[0])) {
          $(document).contextmenu("showEntry", "switchview", false);
        }
      },
      select: function(event, ui) {
        $(document).contextmenu("close");
        var target = ui.target[0];
        var address = get_address_from_class(target);
        if (ui.cmd.indexOf("jumpto_") == 0) {
          address = ui.cmd.substring(ui.cmd.indexOf("jumpto_") + 7);
          do_jumpto(address);
        }
        switch (ui.cmd) {
          case "goto": do_goto(); break;
          case "comment": do_comment(target); break;
          case "rename": do_rename(target, event); break;
          case "define": do_define(target); break;
          case "undefine": do_undefine(target); break;
          case "randomcolors": do_randomcolors(target); break;
          case "switchview": do_switchview(target); break;
        }
      }
    });

    // Show disasm panel and seek to entrypoint
    if (mode === "flat")
      this.display_flat();
    else if (mode === "graph")
      this.display_graph();
    var addr = null;
    if (this.selected_offset !== null) {
      addr = this.selected_offset;
    } else {
      addr = this.base;
    }
    r2ui.seek(addr,true);
    if (addr.indexOf("0x") === 0) {
      addr = address_canonicalize(addr);
    } else {
      addr = r2.get_flag_address(addr);
    }
    scroll_to_address(addr);
}
DisasmPanel.prototype.seek = function(addr, scroll) {
    var panel = this.panel;
    var error = false;
    if (this.display === "graph") {
      panel.innerHTML = "";
      r2.cmd("agj " + addr, function(x) {
        panel.innerHTML = "<div id='minimap'></div></div><div id='canvas' class='canvas enyo-selectable ec_gui_background'></div>";
        // If render fails (address does not belong to function) then switch to flat view
        if (render_graph(x) === false) error = true;
      });
    }
    if (error) this.display_flat();
    if (this.display === "flat") {
      this.min = this.max = 0;
      r2.get_disasm_before_after(addr, -100, 100, function(x) {
        panel.innerHTML = "<div id='canvas' class='canvas enyo-selectable ec_gui_background'></div>";
        r2ui._dis.instructions = x;
        render_instructions(r2ui._dis.instructions);
      });
    }
    this.selected = get_element_by_address(addr);
    this.selected_offset = addr;

    render_history();
    rehighlight_iaddress(addr);
};
DisasmPanel.prototype.display_graph = function() {
  this.display = "graph";
  $("#main_panel").removeClass("ec_gui_background");
  $("#main_panel").addClass("ec_gui_alt_background");
  if ($('#minimap').length) $('#minimap')[0].innerHTML = "";
};
DisasmPanel.prototype.display_flat = function() {
  this.display = "flat";
  $("#main_panel").removeClass("ec_gui_alt_background");
  $("#main_panel").addClass("ec_gui_background");
  if ($('#minimap').length) $('#minimap')[0].innerHTML = "";
};
DisasmPanel.prototype.goToAddress = function() {
  if (this.renaming === null && this.selected !== null && (this.selected.className.indexOf(" addr ") > -1)) {
    var address = get_address_from_class(this.selected);
    if (this.selected.className.indexOf("ec_gui_dataoffset") > -1) {
      // address is located in not executable memory, switching to hex view
      r2ui.openpage(address, 2);
      return;
    }
    if (address !== undefined && address !== null) {
      address = address_canonicalize(address);
      do_jumpto(address);
    }
  }
};
DisasmPanel.prototype.handleInputTextChange = function() {
  if (this.renaming !== null && this.rbox.value.length > 0) {
    if ($(this.selected).hasClass('insaddr')) {
      var old_value = get_offset_flag(r2ui._dis.selected_offset);
      var type = "offsets";
      r2.cmdj("afij @ " + r2ui._dis.selected_offset, function(x) {
        if (x !== null && x !== undefined) {
          if ("0x" + x[0].offset.toString(16) === r2ui._dis.selected_offset) {
            type = "functions";
          }
        }
      });
      rename(r2ui._dis.selected_offset, old_value, this.rbox.value, type);
    } else if ($(this.selected).hasClass('faddr')) {
      if ($(this.selected).hasClass('fvar'))
        r2.cmd("afvn " + r2ui._dis.renameOldValue + " " + r2ui._dis.rbox.value + " @ " + r2ui._dis.selected_offset, function(x){});
      else if ($(this.selected).hasClass('farg'))
        r2.cmd("afan " + r2ui._dis.renameOldValue + " " + r2ui._dis.rbox.value + " @ " + r2ui._dis.selected_offset, function(x){});
    } else {
      // TODO, try to recognize other spaces
      var old_value = r2ui._dis.renameOldValue;
      if (old_value.indexOf("0x") === 0) old_value = "";
      rename(r2ui._dis.selected_offset, old_value, r2ui._dis.rbox.value, "*");
    }
    var instruction;
    if (this.display == "flat") instruction = $(this.selected).closest(".instructionbox").find('.insaddr')[0];
    if (this.display == "graph") instruction = $(this.selected).closest(".instruction").find('.insaddr')[0];
    this.renaming = null;
    var address = get_address_from_class(instruction);
    update_binary_details();
    r2ui.seek(address, false);
    scroll_to_address(address);
  }
};
function scroll_to_address(address, pos) {
  if (address === undefined || address === null) return;
  var offset = 0;
  if (pos == "top") offset = $('#center_panel').height();
  else if (pos == "bottom") offset = 0;
  else offset = window.innerHeight / 2;
  var elements = $(".insaddr.addr_" + address);
  if (elements === undefined || elements === null) return;
  if (elements[0] === undefined || elements[0] === null) return;
  var top = elements[0].documentOffsetTop() - offset;
  top = Math.max(0,top);
  $('#center_panel').scrollTo(top, {axis: 'y'});
  r2ui._dis.scroll_offset = top;
}


function handleClick(inEvent) {

  if ($(inEvent.target).hasClass('addr')) {
      if ($(inEvent.target).hasClass('history')) {
        var idx = inEvent.target.className.split(" ").filter(function(x) { return x.substr(0,"history_idx_".length) == "history_idx_"; });
        idx = String(idx).split("_")[2];
        r2ui.history_idx = idx;
        do_jumpto(r2ui.history[idx]);
      } 
      // If instruction address, add address to history
      else if ($(inEvent.target).hasClass('insaddr')) {
        var address = get_address_from_class(inEvent.target);
        r2ui._dis.selected = inEvent.target;
        r2ui._dis.selected_offset = address;
        rehighlight_iaddress(address);

        r2ui.history_push(address);
        render_history();
        var get_more_instructions = false;
        var next_instruction;
        var prev_instruction;
        var address;
        if (r2ui._dis.display == "flat") {
          next_instruction = $(r2ui._dis.selected).closest(".instructionbox").next().find('.insaddr')[0];
          if ($("#gbox .instructionbox").index( $(r2ui._dis.selected).closest(".instructionbox")[0]) > $("#gbox .instructionbox").length - 10) {
            get_more_instructions = true;
            address = get_address_from_class(next_instruction);
          }
          prev_instruction = $(r2ui._dis.selected).closest(".instructionbox").prev().find('.insaddr')[0];
          if ($("#gbox .instructionbox").index( $(r2ui._dis.selected).closest(".instructionbox")[0]) < 10) {
            get_more_instructions = true;
            address = get_address_from_class(prev_instruction);
          }
        }
        if (r2ui._dis.display == "graph") {
          var next_instruction = $(r2ui._dis.selected).closest(".instruction").next().find('.insaddr')[0];
          if (next_instruction === undefined || next_instruction === null) {
            next_instruction = $(r2ui._dis.selected).closest(".basicblock").next().find('.insaddr')[0];
          }
          var prev_instruction = $(r2ui._dis.selected).closest(".instruction").prev().find('.insaddr')[0];
          if (prev_instruction === undefined || prev_instruction === null) {
            prev_instruction = $(r2ui._dis.selected).closest(".basicblock").prev().find('.insaddr').last()[0];
          }
        }
        if (get_more_instructions) {
          r2ui.seek(address, false);
          rehighlight_iaddress(address);
          scroll_to_address(address);
        }
      }
  } else if ($(inEvent.target).hasClass('fvar') || $(inEvent.target).hasClass('farg')) {
    var eid = null;
    var address = get_address_from_class(inEvent.target, "faddr");
    r2ui._dis.selected = inEvent.target;
    r2ui._dis.selected_offset = address;
    var classes = inEvent.target.className.split(' ');
    for (var j in classes) {
      var klass = classes[j];
      if (klass.indexOf("id_") === 0) eid = klass.substring(3);
    }
    if (eid !== null) rehighlight_iaddress(eid, "id");
  }
}

function handleDoubleClick (inEvent) {
  if ($(inEvent.target).hasClass('addr') && !$(inEvent.target).hasClass('insaddr')) {
    var address = get_address_from_class(inEvent.target);
    do_jumpto(address);
  }
}

// key handler
function handleKeypress(inEvent) {
  var keynum = inEvent.keyCode || inEvent.charCode || inEvent.which || 0;
  var key = String.fromCharCode(keynum);
  // console.log(key);

  if (inEvent.ctrlKey||inEvent.metaKey) return;
  if ($(inEvent.target).prop("tagName") === "INPUT" || $(inEvent.target).prop("tagName") === "TEXTAREA") return;

  if (r2ui._dis.renaming !== null) return;

  // Spacebar Switch flat and graph views
  if (key === ' ') {
    do_switchview();
    inEvent.preventDefault();
  }

  if (key === 'm' && r2ui._dis.display == "graph") toggle_minimap();

  // h Seek to previous address in history
  if (key === 'h') do_jumpto(r2ui.history_prev());

  // l Seek to next address in history
  if (key === 'l') do_jumpto(r2ui.history_next());

  // j Seek to next Instruction
  if (key === 'j') {
    var get_more_instructions = false;
    if ($(r2ui._dis.selected).hasClass("insaddr")) {
      var next_instruction;
      if (r2ui._dis.display == "flat") {
        next_instruction = $(r2ui._dis.selected).closest(".instructionbox").next().find('.insaddr')[0];
        if ($("#gbox .instructionbox").index( $(r2ui._dis.selected).closest(".instructionbox")[0]) > $("#gbox .instructionbox").length - 10) get_more_instructions = true;
      }
      if (r2ui._dis.display == "graph") {
        var next_instruction = $(r2ui._dis.selected).closest(".instruction").next().find('.insaddr')[0];
        if (next_instruction === undefined || next_instruction === null) {
          next_instruction = $(r2ui._dis.selected).closest(".basicblock").next().find('.insaddr')[0];
        }
      }

      // if (next_instruction === null || next_instruction === undefined) return;
      var address = get_address_from_class(next_instruction);
      if (get_more_instructions) {
        r2ui.seek(address, false);
      } else {
        r2ui.history_push(address);
        render_history();
        r2ui._dis.selected = next_instruction;
        r2ui._dis.selected_offset = address;
      }
      rehighlight_iaddress(address);
      scroll_to_address(address);
    }
  }
  // k Seek to previous instruction
  if (key === 'k') {
    var get_more_instructions = false;
    if ($(r2ui._dis.selected).hasClass("insaddr")) {
      var prev_instruction;
      if (r2ui._dis.display == "flat") {
        prev_instruction = $(r2ui._dis.selected).closest(".instructionbox").prev().find('.insaddr')[0];
        if ($("#gbox .instructionbox").index( $(r2ui._dis.selected).closest(".instructionbox")[0]) < 10) get_more_instructions = true;
      }
      if (r2ui._dis.display == "graph") {
        var prev_instruction = $(r2ui._dis.selected).closest(".instruction").prev().find('.insaddr')[0];
        if (prev_instruction === undefined || prev_instruction === null) {
          prev_instruction = $(r2ui._dis.selected).closest(".basicblock").prev().find('.insaddr').last()[0];
        }
      }
      var address = get_address_from_class(prev_instruction);
      if (get_more_instructions) {
        r2ui.seek(address, false);
      } else {
        r2ui.history_push(address);
        render_history();
        r2ui._dis.selected = prev_instruction;
        r2ui._dis.selected_offset = address;
      }
      rehighlight_iaddress(address);
      scroll_to_address(address);
    }
  }
  // c Define function
  if (key === 'c') do_define(r2ui._dis.selected);

  // u Clear function metadata
  if (key === 'u') do_undefine(r2ui._dis.selected);

  // g Go to address
  if (key === 'g') {
    var a = prompt('Go to');
    if (a !== null) do_jumpto(a);
  }

  // ; Add comment
  if (key === ';') do_comment(r2ui._dis.selected);

  // n Rename
  if (key === 'n') do_rename(r2ui._dis.selected, inEvent);

  if (key === 'R') do_randomcolors();

  // esc
  if (keynum === 27) {
    // Esc belongs to renaming
    if(r2ui._dis.renaming !== null) {
      r2ui._dis.renaming.innerHTML = r2ui._dis.renameOldValue;
      r2ui._dis.renaming = null;
    } else {
      // go back in history
      var addr = r2ui.history_prev();
      if (addr !== undefined && addr !== null) r2ui.seek(addr, false);
      scroll_to_address(addr);
    }
  }
  // enter
  if (keynum === 13) {
    r2ui._dis.goToAddress();
  }
}

function do_switchview() {
    $("#switch_button").text("loading ...");
    var address = get_address_from_class(r2ui._dis.selected);
    if (address !== undefined && address !== null) {
      if (r2ui._dis.display === "flat") r2ui._dis.display_graph();
      else if (r2ui._dis.display === "graph") r2ui._dis.display_flat();
      r2ui.seek(address, true);
      scroll_to_address(address);
    }
    $("#switch_button").text("switch view");
}

function do_jumpto(address) {
  var element = $('.insaddr.addr_' + address);
  if (element.length > 0) {
    r2ui.history_push(address);
    r2ui._dis.selected = element[0];
    r2ui._dis.selected_offset = address;
    render_history();
  } else {
    r2ui.seek(address, true);
  }
  rehighlight_iaddress(address);
  scroll_to_address(address);
}

function do_rename(element, inEvent) {
  var address = get_address_from_class(element);
  if ($(element).hasClass("addr") && $(element).hasClass("flag")) {
     var space = "*";
     if ($(element).hasClass("function")) space = "functions";
     if ($(element).hasClass("import")) space = "functions";
     if ($(element).hasClass("symbol")) space = "symbols";
     if ($(element).hasClass("reloc")) space = "relocs";
     if ($(element).hasClass("section")) space = "sections";
     if ($(element).hasClass("string")) space = "strings";
     var old_value = $(element).html();
     var new_name = prompt('New name', old_value);
     if (new_name !== null) {
       rename(address, old_value, new_name, space);
       store_scroll_offset();
       r2ui.seek("$$", false);
       scroll_to_last_offset();
     }
  } else if (r2ui._dis.renaming === null && element !== null && $(element).hasClass("addr")) {
    r2ui._dis.selected = element;
    r2ui._dis.selected_offset = address;
    r2ui._dis.renaming = element;
    r2ui._dis.renameOldValue = element.innerHTML;
    r2ui._dis.rbox = document.createElement('input');
    r2ui._dis.rbox.setAttribute("type", "text");
    r2ui._dis.rbox.setAttribute("id", "rename");
    r2ui._dis.rbox.setAttribute("style", "border-width: 0;padding: 0;");
    r2ui._dis.rbox.setAttribute("onChange", "handleInputTextChange()");
    if ($(element).hasClass('insaddr')) {
      var value = get_offset_flag(address);
      r2ui._dis.rbox.setAttribute("value",value);
      r2ui._dis.rbox.setSelectionRange(value.length, value.length);
    } else {
      r2ui._dis.rbox.setAttribute("value", r2ui._dis.renameOldValue);
      r2ui._dis.rbox.setSelectionRange(r2ui._dis.renameOldValue.length, r2ui._dis.renameOldValue.length);
    }
    r2ui._dis.renaming.innerHTML = "";
    r2ui._dis.renaming.appendChild(r2ui._dis.rbox);
    setTimeout('r2ui._dis.rbox.focus();', 200);
    inEvent.returnValue=false;
    inEvent.preventDefault();
  } else if (r2ui._dis.renaming === null && element !== null && $(element).hasClass("faddr")) {
    address = get_address_from_class(element, "faddr");
    r2ui._dis.selected = element;
    r2ui._dis.selected_offset = address;
    r2ui._dis.renaming = element;
    r2ui._dis.renameOldValue = element.innerText;
    r2ui._dis.rbox = document.createElement('input');
    r2ui._dis.rbox.setAttribute("type", "text");
    r2ui._dis.rbox.setAttribute("id", "rename");
    r2ui._dis.rbox.setAttribute("style", "border-width: 0;padding: 0;");
    r2ui._dis.rbox.setAttribute("onChange", "handleInputTextChange()");
    r2ui._dis.rbox.setAttribute("value", r2ui._dis.renameOldValue);
    r2ui._dis.rbox.setSelectionRange(r2ui._dis.renameOldValue.length, r2ui._dis.renameOldValue.length);
    r2ui._dis.renaming.innerHTML = "";
    r2ui._dis.renaming.appendChild(r2ui._dis.rbox);
    setTimeout('r2ui._dis.rbox.focus();', 200);
    inEvent.returnValue=false;
    inEvent.preventDefault();
  }
  update_binary_details();
}

function do_comment(element) {
  var address = get_address_from_class(element);
  var c =  prompt('Comment');
  if (c !== null) {
    r2.cmd('CC ' + c  + " @ " + address);
    r2ui.seek(address, false);
    scroll_to_address(address);
  }
}

function do_undefine(element) {
  var address = get_address_from_class(element);
  r2.cmd("af-");
  r2.update_flags();
  update_binary_details();
  if (r2ui._dis.display == "graph") r2ui._dis.display_flat();
  r2ui.seek(address, false);
  scroll_to_address(address);
}

function do_define(element) {
  var address = get_address_from_class(element);
  var msg = prompt ('Function name?');
  if (msg !== null) {
    r2.cmd("af " + msg + " @ " + address);
    r2.update_flags();
    update_binary_details();
    r2ui.seek(address, false);
    scroll_to_address(address);
  }
}