// DISASSEMBLKER PANEL
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
};
DisasmPanel.prototype.seek = function(addr, scroll) {
    var panel = this.panel;
    var error = false;
    if (this.display === "graph") {
      panel.innerHTML = "";
      r2.cmd("agj " + addr, function(x) {
        panel.innerHTML = "<div id='bb_canvas' class='bbcanvas enyo-selectable ec_gui_background'></div>";
        // If render fails (address does not belong to function) then switch to flat view
        if (render_graph(x) === false) error = true;
      });
    }
    if (error) this.display_flat();
    if (this.display === "flat") {
      this.min = this.max = 0;
      r2.get_disasm_before_after(addr, -49, 100, function(x) {
        panel.innerHTML = "<div id='flat_canvas' class='flatcanvas enyo-selectable ec_gui_background'></div>";
        render_instructions(x);
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
};
DisasmPanel.prototype.display_flat = function() {
  this.display = "flat";
  $("#main_panel").removeClass("ec_gui_alt_background");
  $("#main_panel").addClass("ec_gui_background");
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
    update_binary_details();
    r2ui.seek(address, false);
    scroll_to_address(address);
    document.getElementById("canvas").focus();
  }
};