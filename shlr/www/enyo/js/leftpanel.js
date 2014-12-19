enyo.kind ({
  name: "LeftPanel",
  classes: "onyx-toolbar",
  kind: "Scroller",
  /* touch:true, */
  style: "width: 200px;height:100%;margin:0px;",
  accelerated: true,
  horizontal: "hidden",
  //strategyKind: "TranslateScrollStrategy",
  create: function() {
    this.inherited (arguments);
    this.$.strategy.setTranslateOptimized = true;
  },
  components: [
    {tag: "center", components:[
      {tag: "h3", ontap: "openPanel2", content: "radare2", style: "margin:0px;margin-bottom:20px;" },
    {kind: "Group", onActivate:"buttonActivated", classes: "enyo-border-box group", defaultKind: "onyx.Button", highlander: true, components: [
      {content: "Disassembler", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Disassembler", active: true},
      {content: "Assembler", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Assembler" },
      {content: "Hexdump", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Hexdump" },
      {content: "Graph", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Graph" },
      {content: "Search", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Search" },
      {content: "Console", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Console" },
      {content: "Debugger", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Debugger" },
      {content: "Script", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Script" },
      {content: "Settings", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Settings" },
      {content: "Logs", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Logs" },
      {content: "About", classes: "onyx-dark menu-button" , ontap: "openPanel", name:"About"},
    ]}
    ]},
  ],
  openPanel2: function() {
    this.ra.setIndex (2);
  },
  openPanel: function (x) {
    if (enyo.Panels.isScreenNarrow())
      this.ra.setIndex (1);
    if (x.name == this.oname)
      this.ra.setIndex (1);
    this.oname = x.name;
    r2ui.selected_panel = this.oname;
    if (this.oname === "Logs")
       r2ui._log.connect();
    if (this.openCallback)
      this.openCallback (x.name);
  },
  oname: null,
  ra: null,
  oldSender: null,
  rowTap: function (inSender, inIndex) {
    if (this.oldSender)
      this.oldSender.setStyle ("width:100%"); // background of row
// TODO. use applystall
    //this.$.list.render ();
    inSender.setStyle ("background-color: #202020;width:100%"); // background of row
    this.oldSender = inSender;
    if (this.openCallback)
      this.openCallback (inIndex.index); //this.data[inIndex.index]);
  },
  openCallback: undefined,
  data: [],
  iter: 1,
  refresh: function () {
    this.iter++;
/*
    this.$.list.setCount (this.data.length);
    this.$.list.refresh ();
*/
  },
});
