enyo.kind ({
  name: "LeftPanel",
  classes: "onyx-toolbar",
  kind: "Scroller",
  fit:true,
  style: "width: 220px;height:100%",
  components: [
    {tag: "h2", content: "crackme01", style: "margin-left:12px; margin-top:0px;margin-bottom:50px;height:10px;width:190px,overflow:hidden" },
     {kind: "Group", onActivate:"buttonActivated", classes: "enyo-border-box group", defaultKind: "onyx.Button", highlander: true, components: [
       {content: "Disassembler", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Disassembler", active: true},
       {content: "Assembler", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Assembler" },
       {content: "Hexdump", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Hexdump" },
       {content: "Console", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Console" },
       {content: "Settings", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Settings" },
       {content: "About", classes: "onyx-dark menu-button" , ontap: "openPanel", name:"About"},
     ]}
  ],
  openPanel: function (x) {
    if (enyo.Panels.isScreenNarrow())
      this.ra.setIndex (1);
    if (this.openCallback)
      this.openCallback (x.name);
  },
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
