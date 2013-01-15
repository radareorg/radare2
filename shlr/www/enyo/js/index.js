enyo.kind ({
  name: "RadareApp",
  kind: "Panels",
  classes: "panels enyo-unselectable",
  realtimeFit: true,
  arrangerKind: "CollapsingArranger",
  components: [ 
    { name: "lp", kind: "LeftPanel" },
    { name: "mp", kind: "MainPanel" },
    { name: "rp", kind: "RightPanel" }
  ],
  setPanel0: function () {
    this.$.RadareApp.setIndex (1);
  },
  create: function() {
      this.inherited (arguments);
      var mp = this.$.mp;
      var ra = this.$.RadareApp;
      this.$.lp.openCallback = function (idx) {
        mp.openPage (idx);
      };
      this.$.lp.ra = this;
      var data = [
        { name: "Disassembler", active: true },
        { name: "Assembler" },
        { name: "Hexdump" },
        { name: "Console" },
        { name: "Settings", separator: true },
        { name: "About" }
      ];
      this.$.lp.data = data;
      this.$.mp.data = data;
      this.$.lp.refresh ();
  }
});

window.onload = function() {
  var obj = new RadareApp ().renderInto (document.body)
}
