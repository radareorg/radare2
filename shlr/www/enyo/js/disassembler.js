// function docss(x) {
//   return '<font color=black>'+x+'</font>';
// }

enyo.kind ({
  name: "Disassembler",
  kind: "Scroller",
  tag: "div",
  classes:"ec_background",
  style:"margin:0px;",
  data: null,
  draggable: false,
  components: [
      // {tag: "div", allowHtml: true, classes: "colorbar", name: "colorbar" },
      // {tag: "div", content: "^", name: "less_button", classes: "moreless", ontap: "less"},
      {tag: "div", allowHtml: true, name: "text", content: "..", style:"margin-left:5px;margin-right:5px"},
      // {tag: "div", content: "v", name: "more_button", classes: "moreless", ontap: "more"},
      {kind: enyo.Signals, onkeypress: "handleKeyPress"}
  ],
  handlers: {ontap: "handleTap", ondblclick: "handleDoubleClick"},
  handleDoubleClick: function (inSender, inEvent) {
    if (inEvent.target.className.indexOf(" addr ") > -1 && inEvent.target.className.indexOf("insaddr") === -1) {
      this.handleTap(inSender, inEvent);
      this.goToAddress();
      inEvent.preventDefault();
      return true;
    }
  },
  handleKeyPress: function(inSender, inEvent) {
    var key = inEvent.keyCode;
    // console.log(key);
    // Spacebar Switch flat and graph views
    if (key === 32) {
      if (this.display === "flat") this.display_graph();
      else this.display_flat();
      var addr = r2ui.history_last();
      if (addr !== undefined && addr !== null) r2ui.seek(addr, false);
    }
    // h Seek to previous address in history
    if (key === 104) {
      var addr = r2ui.history_prev();
      if (addr !== undefined && addr !== null) r2ui.seek(addr, false);
    }
    // l Seek to next address in history
    if (key === 108) {
      var addr = r2ui.history_next();
      if (addr !== undefined && addr !== null) r2ui.seek(addr, false);
    }
    // j Seek to next Instruction
    if (key === 106) {
      var addr = r2ui.next_instruction();
      if (addr !== undefined && addr !== null) r2ui.seek(addr, true);
    }
    // k Seek to previous instruction
    if (key === 107) {
      var addr = r2ui.prev_instruction();
      if (addr !== undefined && addr !== null) r2ui.seek(addr, true);
    }
    // c Define function
    if (key === 99) {
      var msg = prompt ('Function name?');
      r2.cmd("af " + msg, function() {
        r2.update_flags();
        r2ui.seek("$$", false);
      });
    }
    // d Clear function metadata
    if (key === 100) {
      r2.cmd("af-", function() {
        r2.update_flags();
        r2ui.seek("$$", false);
      });
    }
    // g Go to address
    if (key === 103) {
      r2ui.opendis(prompt('Go to'));
    }
    // ; Add comment
    if (key === 59) {
      r2.cmd('CC ' + prompt('Comment'));
      r2ui.seek('$$',false);
    }
    // n Rename
    if (key === 110) {
      if (this.renaming === null && this.selected !== null && (this.selected.className.indexOf(" addr ") ) -1) {
        this.renaming = this.selected;
        this.renameOldValue = this.selected.innerHTML;
        this.rbox = document.createElement('input');
        this.rbox.setAttribute("type", "text");
        this.rbox.setAttribute("id", "rename");
        this.rbox.setAttribute("style", "border-width: 0;padding: 0;");
        this.rbox.setAttribute("onChange", "handleInputTextChange()");
        this.rbox.setAttribute("value", "");
        this.renaming.innerHTML = "";
        this.renaming.appendChild(this.rbox);
        this.rbox.focus();
        inEvent.returnValue=false;
        inEvent.preventDefault();
      }
    }
    // esc
    if (key === 27) {
      // Esc belongs to renaming
      if(this.renaming !== null) {
        this.renaming.innerHTML = this.renameOldValue;
        this.renaming = null;
      } else {
        // go back in history
        var addr = r2ui.history_prev();
        if (addr !== undefined && addr !== null) r2ui.seek(addr, false);
      }
    }
    // enter
    if (key === 13) {
      // Enter means go to address
      this.goToAddress();
    }
  },
  handleTap: function(inSender, inEvent) {
    if (inEvent.target.className.indexOf(" addr ") > -1) {
      var address = get_address_from_class(inEvent.target);
      rehighlight_iaddress(address);
      this.selected = inEvent.target;
      this.selected_offset = address;

      // If instruction address, add address to history
      if (inEvent.target.className.indexOf("insaddr") === 0) {
        r2ui.seek(address, true);
      }
    }
  },
  goToAddress: function() {
    if (this.renaming === null && this.selected !== null && (this.selected.className.indexOf(" addr ") ) -1) {
      var address = get_address_from_class(this.selected);
      if (this.selected.className.indexOf("ec_dataoffset") > -1) {
        // address is located in not executable memory, switching to hex view
        r2ui.openpage(address, 2);
        return;
      }
      if (address !== undefined && address !== null) {
        address = address_canonicalize(address);
        if (this.display === "flat") {
          r2ui.seek(address, true);
        } else {
          // check if address belong to current function //
          r2.cmdj("pdfj", function(x) {
            if (x !== null && x !== undefined) {
              var ops = x.ops;
              var found = false;
              for (var i in ops) {
                if (ops[i].offset === parseInt(address,16)) {
                  found = true;
                }
              }
              if (found) {
                r2ui.seek_in_graph(address, true);
              } else {
                r2ui.seek(address, true);
              }
            }
          });
        }
      }
    }
  },
  handleInputTextChange: function() {
    if (this.renaming !== null && this.rbox.value.length > 0) {
      // Enter belongs to renaming
      var new_value = this.rbox.value;
      this.renaming.innerHTML = new_value;
      renaming = null;

      this.renaming.innerHTML = this.renameOldValue;
      this.renaming = null;

      var renamed = false;
      // If current offset is the beggining of a function, rename it with afr
      r2.cmdj("pdfj", function(x) {
        if (x !== null && x !== undefined) {
          if (x.addr === this.selected_offset) {
            r2.cmd("afn " + msg, function() {
              renamed = true;
             });
          }
        }
      });
      // Otherwise just add a flag
      if (!renamed) {
        var labels = '';
        r2.cmd("fs functions;f@" + this.selected_offset + "~[2]", function(x) {
          labels = x.trim().replace('\n', ';');
        });
        if (new_value) {
          var cmd = "fs functions;f-@" + this.selected_offset + ";f+" + new_value + "@" + this.selected_offset + ";";
          // labels = new_value.split(";");
          // for (var i in labels) {
          //   if (labels[i] !== "") cmd += "f+" + labels[i] + "@$$;";
          // }
          r2.cmd(cmd, function() {});
        } else {
          r2.cmd("f-@" + this.selected_offset, function() {});
        }
      }
      r2.update_flags();
      r2ui.seek("$$", false, false);
    }
  },
  min: 0,
  max: 0,
  block: 512,
  base: "entry0",
  display: "flat",
  selected: null,
  renaming: null,
  renameOldValue: "",
  rbox: null,
  display_graph: function() {
    this.display = "graph";
    // this.$.colorbar.hide();
    // this.$.less_button.hide();
    // this.$.more_button.hide();
    var panel = document.getElementById("radareApp_mp_pageDisassembler");
    panel.className = panel.className.replace("ec_background", "ec_alt_background");
  },
  display_flat: function() {
    this.display = "flat";
    // this.$.colorbar.show();
    // this.$.less_button.show();
    // this.$.more_button.show();
    var panel = document.getElementById("radareApp_mp_pageDisassembler");
    panel.className = panel.className.replace("ec_alt_background", "ec_background");
  },
  less: function() {
    var text = this.$.text;
    this.min += this.block;
    r2.get_disasm_before(this.base + "-" + this.min, this.block, function(x) {
      x = render_instructions(x);
      var oldy = r2ui._dis.getScrollBounds().height;
      text.setContent(x+text.getContent());
      var newy = r2ui._dis.getScrollBounds().height;
      r2ui._dis.scrollTo(0, newy-oldy);
    });
    rehighlight_iaddress(this.base);
  },
  more: function() {
    var text = this.$.text;
    this.max += this.block;
    r2.get_disasm_after(this.base + "+" + this.max, this.block, function(x) {
      x = render_instructions(x);
      text.setContent(text.getContent() + x);
    });
    rehighlight_iaddress(this.base);
  },
  seek: function(addr, scroll) {
    var text = this.$.text;
    if (this.display === "graph") {
      var display = "graph";
      text.setContent("");
      r2.store_asm_config();
      r2.cmd("e asm.bytes = false; e asm.flags = false; e asm.functions = false; e asm.lines = false; e asm.xrefs = false; e asm.cmtright = true; e asm.pseudo = false", function (x) {
        r2.cmd ("agj " + addr, function(x) {
          text.setContent("<div id='bb_canvas' class='bbcanvas ec_background'></div>");
          // If render fails (address does not belong to function) then switch to flat view
          if (render_graph(x) === false) display = "flat";
        });
      });
      this.display = display;
      r2.restore_asm_config();
    }
    else if (this.display === "flat") {
      this.min = this.max = 0;
      r2.get_disasm_before_after(addr, -0.5*this.block, this.block, function(x) {
        text.setContent("<div id='flat_canvas' class='flatcanvas ec_background'></div>");
        render_instructions(x);
        // text.setContent(x);
      });
    }
    this.selected = get_element_by_address(addr);
    this.selected_offset = addr;

    rehighlight_iaddress(addr);
    if (scroll === undefined || scroll === true) {
      scroll_to_address(addr);
    }
  },
  create: function() {
    this.inherited(arguments);
    this.base = "entry0";
    r2ui._dis = this;

    // TODO: Move this to the application constructor
    r2.update_flags();
    r2.analAll();
    r2.load_mmap();
    r2ui.load_colors();

  },
  rendered: function() {
    this.inherited(arguments);
    this.display_flat();
    r2ui.seek(this.base,true);
  },
  colorbar_create: function () {
    var self = this;
    r2.cmd ("pvj 24", function(x) {
      try {
        var y = JSON.parse (x);
      } catch (e) {
        alert (e);
        return;
      }
      // console.log (y);

      // TODO: use canvas api for faster rendering and smaller dom
      var c = "<table class='colorbar'>"+
          "<tr valign=top style='height:8px;border-spacing:0'>";
      var colors = {
        flags: "#c0c0c0",
        comments: "yellow",
        functions: "#5050f0",
        strings: "orange",
      };
      var off = "";
      var WIDTH = '100%';
      var HEIGHT = 16;
      for (var i=0; i< y.blocks.length; i++) {
        var block = y.blocks[i];
        var r = "<div style='overflow:hidden;width:12px;'>____</div>";
        if (block.offset) {  // Object.keys(block).length>1) {
          var r = "<table width='width:100%' height="+HEIGHT+" style='border-spacing:0px'>";
          var count = 0;
          for (var k in colors)
            if (block[k])
              count++;
	  count++; // avoid 0div wtf
	  if (count==1) break;
          var h = HEIGHT / count;
          for (var k in colors) {
            var color = colors[k];
            if (block[k])
              r += "<tr><td class='colorbar_item' style='background-color:"
                  + colors[k]+"'><div style='width:12px;overflow:"
                  + "hidden;height:"+h+"px'>____</div></td></tr>";
          }
          r += "</table>";
          off = "0x"+block.offset.toString (16);
        } else {
          off = "0x"+(y.from + (y.blocksize * i)).toString (16);
        }
        c += "<td onclick='r2ui.seek("+off+",true)' title='"+off
              + "' style='height:"+HEIGHT+"px' "
	      + "width=15px>"+r+"</td>";
      }
      c += "</tr></table>";
      self.$.colorbar.setContent (c);
    });
  }
});
