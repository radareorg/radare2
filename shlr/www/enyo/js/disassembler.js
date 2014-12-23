enyo.kind ({
  name: "Disassembler",
  kind: "Scroller",
  tag: "div",
  classes:"ec_gui_background",
  style:"margin:0px;",
  draggable: false,
  data: null,
  components: [
      // {tag: "div", allowHtml: true, classes: "colorbar", name: "colorbar" },
      {tag: "div", allowHtml: true, name: "text", content: "..", style:"margin-left:5px;margin-right:5px"},
      {kind: enyo.Signals,
        onkeypress: "handleKeyPress"
      },
      {name: "menuPopup", kind: "onyx.Popup", floating: true, onHide:'hideContextMenu', onShow:"showContextMenu", style:"padding: 0px;",
          style: "padding: 10px", components: [
            {name: "menu", kind: "onyx.MenuDecorator", onSelect: "itemSelected", components: [
              {content: "Show menu"},
              {kind: "onyx.Menu", name: "contextMenu", components: [
                  {content: "rename", value: "rename"},
                  {content: "comment", value: "comment"}
              ]}
            ]}
          ]
      },

  ],
  handlers: {
    ontap: "handleTap",
    onhold: "handleHold",
    ondblclick: "handleDoubleClick"
  },
  itemSelected: function (inSender, inEvent) {
    if (inEvent.originator.content) {
        var itemContent = inEvent.originator.content;
        if (itemContent == "rename") {
          this.do_rename(this.selected, inEvent);
        } else {
          this.do_comment(this.selected_offset);
        }
    }
    this.$.menuPopup.hide();
  },
  handleHold: function (inSender, inEvent) {
    this.handleTap(inSender, inEvent);
    if (inEvent.target.className.indexOf(" addr ") > -1 || inEvent.target.className.indexOf(" faddr ") > -1) {
      var address = get_address_from_class(inEvent.target);
      this.selected = inEvent.target;
      this.selected_offset = address;
      rehighlight_iaddress(address);
      this.showContextMenu(inEvent.pageY, inEvent.pageX);
    }
  },
  showContextMenu:function(inSender, inEvent){

    if((parseFloat(inSender) == parseInt(inSender)) && !isNaN(inSender) && (parseFloat(inEvent) == parseInt(inEvent)) && !isNaN(inEvent)){
      this.$.menuPopup.addStyles('top:'+inSender+'px; left:'+inEvent+'px;padding:0px;');
      this.$.menuPopup.show();
      this.$.menuPopup.children[0].children[0].hide();
      this.$.menuPopup.children[0].children[1].show();
      this.$.menuPopup.render();
    }
  },
  hideContextMenu:function(inSender,inEvent){
  },
  handleDoubleClick: function (inSender, inEvent) {
    if (inEvent.target.className.indexOf(" addr ") > -1 && inEvent.target.className.indexOf("insaddr") === -1) {
      this.handleTap(inSender, inEvent);
      this.goToAddress();
      // inEvent.returnValue=false;
      // inEvent.preventDefault();
      // return true;
    }
  },
  handleKeyPress: function(inSender, inEvent) {
    var key = inEvent.keyCode || inEvent.charCode || inEvent.which || 0;
    // console.log(key);
    // show help
    if (key === 63) {
      r2ui.mp.show_popup();
    }
    // Spacebar Switch flat and graph views
    if (key === 32) {
      this.switch_view();
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
      var get_more_instructions = false;
      if ($(this.selected).hasClass("insaddr")) {
        var next_instruction;
        if (this.display == "flat") {
          next_instruction = $(this.selected).closest(".instructionbox").next().find('.insaddr')[0];
          if ($("#gbox .instructionbox").index( $(this.selected).closest(".instructionbox")[0]) > $("#gbox .instructionbox").length - 10) get_more_instructions = true;
        }
        if (this.display == "graph") {
          var next_instruction = $(this.selected).closest(".instruction").next().find('.insaddr')[0];
          if (next_instruction === undefined || next_instruction === null) {
            next_instruction = $(this.selected).closest(".basicblock").next().find('.insaddr')[0];
          }
        }

        // if (next_instruction === null || next_instruction === undefined) return;
        var address = get_address_from_class(next_instruction);
        if (get_more_instructions) {
          r2ui.seek(address, false);
        } else {
          r2ui.history_push(address);
          this.selected = next_instruction;
          this.selected_offset = address;
        }
        rehighlight_iaddress(address);
        scroll_to_address(address);
      }
    }
    // k Seek to previous instruction
    if (key === 107) {
      var get_more_instructions = false;
      if ($(this.selected).hasClass("insaddr")) {
        var prev_instruction;
        if (this.display == "flat") {
          prev_instruction = $(this.selected).closest(".instructionbox").prev().find('.insaddr')[0];
          if ($("#gbox .instructionbox").index( $(this.selected).closest(".instructionbox")[0]) < 10) get_more_instructions = true;
        }
        if (this.display == "graph") {
          var prev_instruction = $(this.selected).closest(".instruction").prev().find('.insaddr')[0];
          if (prev_instruction === undefined || prev_instruction === null) {
            prev_instruction = $(this.selected).closest(".basicblock").prev().find('.insaddr').last()[0];
          }
        }
        var address = get_address_from_class(prev_instruction);
        if (get_more_instructions) {
          r2ui.seek(address, false);
        } else {
          r2ui.history_push(address);
          this.selected = prev_instruction;
          this.selected_offset = address;
        }
        rehighlight_iaddress(address);
        scroll_to_address(address);
      }
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
      this.do_comment(this.selected_offset);
    }
    // n Rename
    if (key === 110) {
      this.do_rename(this.selected, inEvent);
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
        if ($(inEvent.target).hasClass('insaddr')) {
          r2ui.history_push(address);
          var get_more_instructions = false;
          var next_instruction;
          var prev_instruction;
          var address = get_address_from_class(inEvent.target);
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
            document.getElementById("canvas").focus();
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
      if ($(this.selected).hasClass('insaddr')) {
        var old_value = get_offset_flag(r2ui._dis.selected_offset);
        rename(r2ui._dis.selected_offset, old_value, this.rbox.value, "offsets");
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
      r2ui.seek(address, false);
      scroll_to_address(address);
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
  do_comment: function(address) {
    r2.cmd('CC- ' + " @ " + address + ';CC ' + prompt('Comment')  + " @ " + address);
    r2ui.seek(address, false);
    scroll_to_address(address);
  },
  do_rename: function(element, inEvent) {
    if (this.renaming === null && this.selected !== null && this.selected.className.indexOf(" addr ") > -1) {
      var address = get_address_from_class(this.selected);
      this.renaming = this.selected;
      this.renameOldValue = this.selected.innerHTML;
      this.rbox = document.createElement('input');
      this.rbox.setAttribute("type", "text");
      this.rbox.setAttribute("id", "rename");
      this.rbox.setAttribute("style", "border-width: 0;padding: 0;");
      this.rbox.setAttribute("onChange", "handleInputTextChange()");
      if (this.selected.className.indexOf("insaddr") > -1) {
        var value = get_offset_flag(address);
        this.rbox.setAttribute("value",value);
        this.rbox.setSelectionRange(value.length, value.length);
      } else {
        this.rbox.setAttribute("value", this.renameOldValue);
        this.rbox.setSelectionRange(this.renameOldValue.length, this.renameOldValue.length);
      }
      this.renaming.innerHTML = "";
      this.renaming.appendChild(this.rbox);
      setTimeout('r2ui._dis.rbox.focus();', 200);
    } else if (this.renaming === null && element !== null && $(element).hasClass("faddr")) {
      var address = get_address_from_class(element, "faddr");
      this.selected = element;
      this.selected_offset = address;
      this.renaming = element;
      this.renameOldValue = element.innerText;
      this.rbox = document.createElement('input');
      this.rbox.setAttribute("type", "text");
      this.rbox.setAttribute("id", "rename");
      this.rbox.setAttribute("style", "border-width: 0;padding: 0;");
      this.rbox.setAttribute("onChange", "handleInputTextChange()");
      this.rbox.setAttribute("value", this.renameOldValue);
      this.rbox.setSelectionRange(this.renameOldValue.length, this.renameOldValue.length);
      this.renaming.innerHTML = "";
      this.renaming.appendChild(r2ui._dis.rbox);
      setTimeout('r2ui._dis.rbox.focus();', 200);
    }


  },
  switch_view: function() {
    if (this.display === "flat") this.display_graph();
    else this.display_flat();
    var addr = r2ui.history_last();
    if (addr !== undefined && addr !== null) r2ui.seek(addr, false);
  },
  display_graph: function() {
    this.display = "graph";
    var panel = document.getElementById("radareApp_mp_panels_pageDisassembler");
    if (panel !== undefined && panel !== null) panel.className = panel.className.replace("ec_gui_background", "ec_gui_alt_background");
  },
  display_flat: function() {
    this.display = "flat";
    var panel = document.getElementById("radareApp_mp_panels_pageDisassembler");
    if (panel !== undefined && panel !== null) panel.className = panel.className.replace("ec_gui_alt_background", "ec_gui_background");
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
    var error = false;
    if (this.display === "graph") {
      text.setContent("");
      r2.cmd ("agj " + addr, function(x) {
        text.setContent("<div id='bb_canvas' class='bbcanvas enyo-selectable ec_gui_background'></div>");
        // If render fails (address does not belong to function) then switch to flat view
        if (render_graph(x) === false) error = true;
      });
    }
    if (error) this.display_flat();
    if (this.display === "flat") {
      this.min = this.max = 0;
      r2.get_disasm_before_after(addr, -49, 100, function(x) {
        text.setContent("<div id='flat_canvas' class='flatcanvas enyo-selectable ec_gui_background'></div>");
        render_instructions(x);
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
