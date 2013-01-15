enyo.kind ({
  name: "RightPanel",
  classes: "onyx onyx-toolbar",
  kind: enyo.Control,
  style: "width:25px",
  components: [
    {kind: "onyx.MenuDecorator", onSelect: "itemSelected", components: [
      {content: "List elements"},
      {kind: "onyx.Menu", onchange: "doSomething", components: [
        {content: "symbols", value: "1"},
        {content: "imports", value: "1"},
        {content: "functions", value: "1"},
        {content: "comments", value: "1"},
        {content: "registers", value: "1"},
        {content: "stack", value: "2"},
        {content: "backtrace", value: "3"},
        {classes: "onyx-menu-divider"},
        {content: "settings", value: "4"},
      ]}
    ]},
  ],
  doSomething: function() {
    alert("jaja");
  }
});

