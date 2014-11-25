function makelist(x) {
  var z = "List of "+x.length+"\n\n";
  for (var i = 0; i<x.length; i++)
    z += "<a style='color:yellow' href='javascript:r2ui.opendis("+
         x[i].offset+")'>0x"+x[i].offset.toString (16) + "</a>  "+ enyo.dom.escape(x[i].name)+"\n";
  return z;
}

enyo.kind ({
  name: "RightPanel",
  style:"background-color:#404040;",
  classes: "onyx-toolbar",
  kind: "FittableRows",
  ra: null,
  components: [
    {kind:"FittableColumns", style:"margin-bottom:5px", components:[
    {kind: "onyx.Button", content: "[", ontap: "closeSidebar", style: "padding:8px;margin-right:8px"},
      {onup:"toggleScroll", style:"position:absolute;left:40px;top:0px;", kind: "onyx.MenuDecorator", onSelect: "itemSelected", components: [
        {content: "List elements" },
        {kind: "onyx.Menu", showOnTop: true, maxHeight:290, name: "menu", style:"height:300px", components: [
          {content: "flags", value: "2"},
          {content: "flagspaces", value: "2"},
          {classes: "onyx-menu-divider"},
          {content: "strings", value: "1"},
          {content: "symbols", value: "1"},
          {content: "imports", value: "1"},
          {content: "relocs", value: "1"},
          {content: "functions", value: "1"},
          {content: "comments", value: "1"},
          {classes: "onyx-menu-divider"},
          {content: "registers", value: "1"},
          {content: "stack", value: "2"},
          {content: "backtrace", value: "3"},
        ]},
      ]},
    ]},
    {kind: "Scroller", animated: false, fit: true, horizontal: false, name: "scroll", components: [
/*
  {kind: "FittableColumns",components:[
      {kind: "List", name: "list", style:"height:400px", realtimeFit:true, onSetupItem: "setupItem", components: [
        {kind: "onyx.Item", layoutKind: "HFlexLayout", style:"padding:0px", components: [
          {name:"separator", tag: "hr", style:"height:1px;visibility:hidden"},
          {kind: "onyx.Button", name: "msg", style: "width:100%", fit:true, active: true, ontap: "rowTap"}
        ]}
      ]},
    ]},
*/
      {tag: "pre", style:"font-size:14px", allowHtml:true, name: "output", content:".." }
    ]}
  ],
  toggleScroll: function() {
    var is_visible = this.$.menu.getShowing ();
    this.$.scroll.setShowing (is_visible);
  },
  rowTap: function () {
    /* do something here */
  },
  create: function() {
    this.inherited (arguments);
/*
    this.$.list.setCount (3);
    this.$.list.refresh();
*/
  },
  data: [],
  setupItem: function (inSender, inIndex) {
    var item = this.data[inIndex.index];
    if (!item)
      return false;
    var msg = item.name + " "+item.offset;
    console.log (msg);
    this.$.msg.setContent (msg);
    return true;
  },
  refresh: function () {
    //this.$.list.setCount (this.data.length);
    //this.$.list.refresh ();
  },
  itemSelected: function (inSender, inEvent) {
    var self = this;
    var selected = inEvent.originator.content;
    var is_visible = this.$.menu.getShowing ();
    r2ui.rp = self;
    this.$.scroll.setShowing (!!! is_visible);
    this.$.menu.setShowing (false);
    this.$.scroll.scrollToTop();
    //this.$.output.scrollToTop();
    switch (selected) {
    case "comments":
      r2.cmd ("CC*", function(x) {
        x = x.replace (/0x([a-zA-Z0-9]*)/g, "<a style='color:yellow' href='javascript:r2ui.seek(\"0x$1\")'>0x$1</a>");
	self.$.output.setContent (x);
      });
      break;
    case "functions":
      r2.cmd ("afl", function(x) {
        x = x.replace (/0x([a-zA-Z0-9]*)/g, "<a style='color:yellow' href='javascript:r2ui.seek(\"0x$1\")'>0x$1</a>");
	self.$.output.setContent (x);
      });
      break;
    case "flagspaces":
      this.updateFlagspace ();
      break;
    case "strings":
      r2.cmd ("izj", function(x) {
	var s = JSON.parse (x);
        var h = '';
        for (var i in s) {
          var off = (+s[i]['offset']).toString(16);
          h += '<a style="color:yellow" href="javascript:r2ui.opendis(0x'+
          off+')">0x'+off+'</a> '+enyo.dom.escape(s[i]['string'])+'<br />';
        }
        self.$.output.setContent (h);
      });
      break;
    case "sections":
      r2.bin_sections(function (x) {
	self.$.output.setContent (makelist (x));
      });
      break;
    case "symbols":
      r2.bin_symbols(function (x) {
	self.$.output.setContent (makelist (x));
      });
      break;
    case "relocs":
      r2.bin_relocs (function (x) {
	self.$.output.setContent (makelist (x));
      });
      break;
    case "imports":
      r2.bin_imports (function (x) {
	self.$.output.setContent (makelist (x));
      });
      break;
    case "flags":
      r2.get_flags (function (flags) {
        self.data = flags;
	self.$.output.setContent (makelist (flags));
	self.refresh();
      });
      break;
    }
  },
  closeSidebar: function() {
    this.ra.setIndex (1);
  },
  selectFlagspace: function (x) {
    r2.cmd ('fs '+x, function(x) {
      r2ui.rp.updateFlagspace();
    });
  },
  updateFlagspace: function() {
      var self = r2ui.rp;
      r2.cmd ("fsj", function (x) {
        var s = JSON.parse (x);
        var h = '';
        for (var i in s) {
          var nam = s[i].name;
          var sel = s[i].selected;
          h += '<a style="color:yellow" href="javascript:r2ui.rp.selectFlagspace(\''+
            nam+'\')">'+nam+'</a> '+(sel?"  (selected)":"")+'<br />';
        }
        self.$.output.setContent (h);
      });
}
});
