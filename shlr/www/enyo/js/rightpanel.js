enyo.kind ({
  name: "RightPanel",
  classes: "onyx onyx-toolbar",
  kind: "Control",
  style: "width:25px",
  ra: null,
  components: [
{kind: "FittableColumns", components: [
    {kind: "onyx.Button", content: "[", ontap: "closeSidebar", style: "padding:8px;margin-right:8px"},
    {kind: "onyx.MenuDecorator", onSelect: "itemSelected", components: [
      {content: "List elements"},
      {kind: "onyx.Menu", components: [
        {content: "symbols", value: "1"},
        {content: "imports", value: "1"},
        {content: "functions", value: "1"},
        {content: "comments", value: "1"},
        {classes: "onyx-menu-divider"},
        {content: "registers", value: "1"},
        {content: "stack", value: "2"},
        {content: "backtrace", value: "3"},
        {classes: "onyx-menu-divider"},
        {content: "flags", value: "2"},
        {content: "flagspaces", value: "2"},
      ]}
    ]},
    {kind: "List", name: "list", style:"height:400px", realtimeFit:false, onSetupItem: "setupItem", components: [
      {kind: "onyx.Item", layoutKind: "HFlexLayout", style:"padding:0px", components: [
        {tag: "h3", style:"background-color:red",name: "msg", fit:true, active: true, ontap: "rowTap"}
      ]}
    ]}
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
    var idx = inIndex.index;
    this.$.msg.setContent (this.data[idx]);
    return true;
  },
  itemSelected: function(inSender, inEvent) {
    var self = this;
    var selected = inEvent.originator.content;
    switch (selected) {
    case "flags":
      r2.get_flags (function (flags) {
        // trycatch here or wtf
        self.data = JSON.parse (flags);
        self.$.list.setCount (self.data.length);
        self.$.list.refresh();
      });
      break;
    }
  },
  closeSidebar: function() {
    this.ra.setIndex (1);
  }
});
