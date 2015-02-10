enyo.kind ({
  name: "Disassembler",
  kind: "Scroller",
  tag: "div",
  classes:"ec_gui_background",
  style:"margin:0px;position: relative;",
  data: null,
  components: [
      // {tag: "div", allowHtml: true, classes: "colorbar", name: "colorbar" },
      {
        tag: "div",
        allowHtml: true,
        name: "minimap",
        style : "width:200px; height:200px; position:fixed; top:0; right 0px",
        id: "minimap"
      },
      {
        tag: "div",
        allowHtml: true,
        name: "panel",
        content: "<div id='main_panel' class='ui-layout-center ec_gui_background'><div id='center_panel'></div></div>"
                 + "<div class='ui-layout-south' style='display: none;background-color:rgb(20,20,20);'><pre id='cmd_output' class='ui-layout-content'></pre><div><input id='command' type='text' value=''/></div></div>",
        style:"margin-right:5px;width:100%;height:100%",
      },
      {kind: enyo.Signals,
        onkeypress: "handleKeyPress"
      },
      {name: "menuPopup", kind: "onyx.Popup", floating: true, onHide:'hideContextMenu', onShow:"showContextMenu", style:"padding: 0px;",
          style: "padding: 10px", components: [
            {name: "menu", kind: "onyx.MenuDecorator", onSelect: "itemSelected", components: [
              {content: "Show menu"},
              {kind: "onyx.Menu", name: "contextMenu", components: [
                  {content: "rename", value: "rename"},
                  {content: "comment", value: "comment"},
                  {content: "switch view", value: "do_switchview"},
                  {content: "random colors", value: "do_randomcolors"}
              ]}
            ]}
          ]
      },
  ],
  handlers: {
    ontap: "handleTap",
    onhold: "handleHold",
    ondblclick: "handleDoubleClick",
    onTransitionFinish: "handleTransitionFinish",
  },
  handleTransitionFinish: function() {
    if (r2ui._dis.display == "graph" && r2ui._dis.minimap) update_minimap();
  },
  itemSelected: function (inSender, inEvent) {
    if (inEvent.originator.content) {
        var itemContent = inEvent.originator.content;
        if (itemContent == "rename") {
          this.do_rename(this.selected, inEvent);
        } else if (itemContent == "comment") {
          this.do_comment(this.selected_offset);
        } else if (itemContent == "random colors") {
          do_randomcolors();
        } else if (itemContent == "switch view") {
          this.switch_view();
        }
    }
    this.$.menuPopup.hide();
  },
  handleHold: function (inSender, inEvent) {
    this.handleTap(inSender, inEvent);
    if (typeof inEvent.target.className === "string" && (inEvent.target.className.indexOf(" addr ") > -1 || inEvent.target.className.indexOf(" faddr ") > -1)) {
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
    }
  },

  handleKeyPress: function(inSender, inEvent) {
    var keynum = inEvent.keyCode || inEvent.charCode || inEvent.which || 0;
    var key = String.fromCharCode(keynum);
    // console.log(key);

    if (inEvent.ctrlKey||inEvent.metaKey) return;
    if ($(inEvent.target).prop("tagName") === "INPUT" || $(inEvent.target).prop("tagName") === "TEXTAREA") return;


    // show help
    if (key === '?') {
      r2ui.mp.show_popup();
    }
    // Spacebar Switch flat and graph views
    if (key === ' ') {
      this.switch_view();
    }
    // h Seek to previous address in history
    if (key === 'h') {
      var addr = r2ui.history_prev();
      if (addr !== undefined && addr !== null) r2ui.seek(addr, false);
    }
    // l Seek to next address in history
    if (key === 'l') {
      var addr = r2ui.history_next();
      if (addr !== undefined && addr !== null) r2ui.seek(addr, false);
    }
    if (key === 'm' && r2ui._dis.display == "graph") toggle_minimap();
    // j Seek to next Instruction
    if (key === 'j') {
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
    if (key === 'k') {
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
    if (key === 'c') {
      var msg = prompt ('Function name?');
      if (msg !== null) {
        r2.cmd("af " + msg, function() {
          r2.update_flags();
          r2ui.seek("$$", false);
        });
      }
    }
    // d Clear function metadata
    if (key === 'd') {
      r2.cmd("af-", function() {
        r2.update_flags();
        r2ui.seek("$$", false);
      });
    }
    // g Go to address
    if (key === 'g') {
      var a = prompt('Go to');
      if (a !== null) r2ui.opendis(a);
    }
    // ; Add comment
    if (key === ';') {
      this.do_comment(this.selected_offset);
    }
    // n Rename
    if (key === 'n') {
      this.do_rename(this.selected, inEvent);
    }

    if (key === 'R') do_randomcolors();

    // esc
    if (keynum === 27) {
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
    if (keynum === 13) {
      // Enter means go to address
      this.goToAddress();
    }
  },
  handleTap: function(inSender, inEvent) {
    if (typeof inEvent.target.className === 'string') {
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
  minimap:true,
  console_history: [],
  console_history_idx: 0,
  instructions: [],
  scrolling: false,
  do_comment: function(address) {
    var c = prompt('Comment');
    if (c !== null) {
      r2.cmd('CC- ' + " @ " + address + ';CC ' + c + " @ " + address);
      r2ui.seek(address, false);
      scroll_to_address(address);
    }
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
    $("#main_panel").removeClass("ec_gui_background");
    $("#main_panel").addClass("ec_gui_alt_background");
  },
  display_flat: function() {
    this.display = "flat";
    $("#main_panel.ui-layout-pane").removeClass("ec_gui_alt_background");
    $("#main_panel.ui-layout-pane").addClass("ec_gui_background");
  },
  // less: function() {
  //   this.min += this.block;
  //   r2.get_disasm_before(this.base + "-" + this.min, this.block, function(x) {
  //     x = render_instructions(x);
  //     var oldy = r2ui._dis.getScrollBounds().height;
  //     $("#center_panel").html(x+text.getContent());
  //     var newy = r2ui._dis.getScrollBounds().height;
  //     r2ui._dis.scrollTo(0, newy-oldy);
  //   });
  //   rehighlight_iaddress(this.base);
  // },
  // more: function() {
  //   this.max += this.block;
  //   r2.get_disasm_after(this.base + "+" + this.max, this.block, function(x) {
  //     x = render_instructions(x);
  //     $("#center_panel").html(text.getContent() + x);
  //   });
  //   rehighlight_iaddress(this.base);
  // },
  seek: function(addr, scroll) {
    var error = false;
    if (this.display === "graph") {
      this.$.minimap.show();
      $("#center_panel").html("");
      r2.cmd ("agj " + addr, function(x) {
        $("#center_panel").html("<div id='center_panel' style='width:100%;height:100%;overflow: auto;'><div id='canvas' class='canvas enyo-selectable ec_gui_background'></div></div>");
        if (render_graph(x) === false) error = true;
      });
    }
    if (error) this.display_flat();
    if (this.display === "flat") {
      $("#main_panel").scroll(on_scroll);
      this.$.minimap.hide();
      this.min = this.max = 0;
      r2.get_disasm_before_after(addr, -100, 100, function(x) {
        $("#center_panel").html("<div id='canvas' class='canvas enyo-selectable ec_gui_background'></div>");
        r2ui._dis.instructions = x;
        render_instructions(r2ui._dis.instructions);
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
  resizeHandler: function() {
    this.inherited(arguments);
    if (r2ui._dis.display == "graph" && r2ui._dis.minimap) update_minimap();
  },
  rendered: function() {
    this.inherited(arguments);
    myLayout = $('#radareApp_mp_panels_pageDisassembler_panel').layout({
      south__size:    200,
    });
    this.display_flat();
    r2ui.seek(this.base,true);

    var console_history = this.console_history;
    var console_history_idx = this.console_history_idx;

    // Handle commands in console
    $("#command").keypress(function( inEvent ) {
      var key = inEvent.keyCode || inEvent.charCode || inEvent.which || 0;
      if (key === 13) {
        var cmd = inEvent.target.value.trim();
        var reloadUI = cmd == '';

        console_history[console_history.length] = cmd;
        console_history_idx += 1;
        /* empty input reloads UI */
        if (cmd != '') {
          r2.cmd(inColor(cmd), function(x) {
            var old_value = $("#cmd_output").text();
            $("#cmd_output").html(old_value + "\n> " + cmd + "\n" + x );
            $('#cmd_output').scrollTo($('#cmd_output')[0].scrollHeight);
          });
          if (cmd.indexOf("s ") === 0) {
            r2ui.history_push(r2ui._dis.selected_offset);
          }
        }
        inEvent.target.value = "";
        /* if command starts with :, do not reload */
        if (reloadUI) {
          r2.load_settings();
          r2ui.load_colors();
          r2ui.seek("$$", false);
          scroll_to_element(r2ui._dis.selected);
        }
      }
    });
    $("#command").keydown(function( inEvent ) {
      var key = inEvent.keyCode || inEvent.charCode || inEvent.which || 0;
      if (key === 40) {
        console_history_idx++;
        if (console_history_idx > console_history.length - 1) console_history_idx = console_history.length;
        inEvent.target.value = console_history[console_history_idx] === undefined ? "" : console_history[console_history_idx];
      }
      if (key === 38) {
        console_history_idx--;
        if (console_history_idx < 0) console_history_idx = 0;
        inEvent.target.value = console_history[console_history_idx] === undefined ? "" : console_history[console_history_idx];
      }
    });
  },
  // colorbar_create: function () {
  //   var self = this;
  //   r2.cmd ("pvj 24", function(x) {
  //     try {
  //       var y = JSON.parse (x);
  //     } catch (e) {
  //       alert (e);
  //       return;
  //     }
  //     // console.log (y);

  //     // TODO: use canvas api for faster rendering and smaller dom
  //     var c = "<table class='colorbar'>"+
  //         "<tr valign=top style='height:8px;border-spacing:0'>";
  //     var colors = {
  //       flags: "#c0c0c0",
  //       comments: "yellow",
  //       functions: "#5050f0",
  //       strings: "orange",
  //     };
  //     var off = "";
  //     var WIDTH = '100%';
  //     var HEIGHT = 16;
  //     for (var i=0; i< y.blocks.length; i++) {
  //       var block = y.blocks[i];
  //       var r = "<div style='overflow:hidden;width:12px;'>____</div>";
  //       if (block.offset) {  // Object.keys(block).length>1) {
  //         var r = "<table width='width:100%' height="+HEIGHT+" style='border-spacing:0px'>";
  //         var count = 0;
  //         for (var k in colors)
  //           if (block[k])
  //             count++;
   //  count++; // avoid 0div wtf
   //  if (count==1) break;
  //         var h = HEIGHT / count;
  //         for (var k in colors) {
  //           var color = colors[k];
  //           if (block[k])
  //             r += "<tr><td class='colorbar_item' style='background-color:"
  //                 + colors[k]+"'><div style='width:12px;overflow:"
  //                 + "hidden;height:"+h+"px'>____</div></td></tr>";
  //         }
  //         r += "</table>";
  //         off = "0x"+block.offset.toString (16);
  //       } else {
  //         off = "0x"+(y.from + (y.blocksize * i)).toString (16);
  //       }
  //       c += "<td onclick='r2ui.seek("+off+",true)' title='"+off
  //             + "' style='height:"+HEIGHT+"px' "
   //      + "width=15px>"+r+"</td>";
  //     }
  //     c += "</tr></table>";
  //     self.$.colorbar.setContent (c);
  //   });
  // }
});
