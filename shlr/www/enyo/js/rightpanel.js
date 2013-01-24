enyo.kind ({
  name: "RightPanel",
  classes: "onyx-toolbar",
  kind: "Scroller",
  style: "width:25px",
  ra: null,
  components: [
    {kind: "FittableColumns", components: [
      {kind: "onyx.Button", content: "[", ontap: "closeSidebar", style: "padding:8px;margin-right:8px"},
      {kind: "onyx.MenuDecorator", fit:true,onSelect: "itemSelected", components: [
        {content: "List elements" },
        {kind: "onyx.Menu", maxHeight:290, style:"height:300px", components: [
          {content: "flags", value: "2"},
          {content: "flagspaces", value: "2"},
          {classes: "onyx-menu-divider"},
          {content: "symbols", value: "1"},
          {content: "imports", value: "1"},
          {content: "functions", value: "1"},
          {content: "comments", value: "1"},
          {classes: "onyx-menu-divider"},
          {content: "registers", value: "1"},
          {content: "stack", value: "2"},
          {content: "backtrace", value: "3"},
        ]}
      ]},
      {tag:"br"},
      {tag:"br"},
      {kind: "List", name: "list", style:"height:400px", realtimeFit:true, onSetupItem: "setupItem", components: [
        {kind: "onyx.Item", layoutKind: "HFlexLayout", style:"padding:0px", components: [
          {name:"separator", tag: "hr", style:"height:1px;visibility:hidden"},
          {kind: "onyx.Button", name: "msg", style: "width:100%", fit:true, active: true, ontap: "rowTap"}
        ]}
      ]},
      {tag: "pre", style:"font-size:10px", allowHtml:true, name: "output", content:".." }
    ]}
  ],
  rowTap: function () {
    /* do something here */
  },
  create: function() {
    this.inherited (arguments);
    this.$.list.setCount (3);
    this.$.list.refresh();
  },
  data: [],
  setupItem: function (inSender, inIndex) {
    var item = this.data[inIndex.index];
    if (!item)
      return false;
    var msg = item.name + " "+item.offset;
    console.log(msg);
    this.$.msg.setContent (msg);
    return true;
  },
  refresh: function () {
    this.$.list.setCount (this.data.length);
    this.$.list.refresh ();
  },
  itemSelected: function(inSender, inEvent) {
    var self = this;
    var selected = inEvent.originator.content;
    switch (selected) {
    case "functions":
      r2.cmd ("afl", function(x) {
	self.$.output.setContent (x);
      });
      break;
    case "flagspaces":
      r2.cmd("fs", function (x) {
	self.$.output.setContent (x);
      });
      break;
    case "sections":
      r2.bin_sections(function (imp) {
	var txt = "List of "+imp.length+"\n\n";
        for (var i = 0; i<imp.length; i++)
          txt += imp[i].offset + "  "+ imp[i].name+"\n";
	self.$.output.setContent (txt);
      });
      break;
    case "symbols":
      r2.bin_symbols(function (imp) {
	var txt = "List of "+imp.length+"\n\n";
        for (var i = 0; i<imp.length; i++)
          txt += imp[i].offset + "  "+ imp[i].name+"\n";
	self.$.output.setContent (txt);
      });
      break;
    case "imports":
      r2.bin_imports (function (imp) {
	var txt = "List of "+imp.length+"\n\n";
        for (var i = 0; i<imp.length; i++)
          txt += imp[i].offset + "  "+ imp[i].name+"\n";
	self.$.output.setContent (txt);
      });
      break;
    case "flags":
      r2.get_flags (function (flags) {
        self.data = flags;
        self.$.list.setCount (self.data.length);
	var txt = "List of "+self.data.length+"\n\n";
        for (var i = 0; i<flags.length; i++)
          txt += flags[i].offset + "  "+ flags[i].name+"\n";
	self.$.output.setContent (txt);
        self.$.list.refresh();
	self.refresh();
      });
      break;
    }
  },
  closeSidebar: function() {
    this.ra.setIndex (1);
  }
});
