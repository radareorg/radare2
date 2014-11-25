enyo.kind ({
  name: "RadareApp",
  kind: "Panels",
  classes: "panels enyo-unselectable",
  realtimeFit: true,
  fit: true,
  arrangerKind: "CollapsingArranger",
  components: [
    { name: "lp", kind: "LeftPanel" },
    { name: "mp", kind: "MainPanel" },
    { name: "rp", kind: "RightPanel" },
    { kind: enyo.Signals, onkeypress: "handleKeyPress" }
  ],
  setPanel0: function () {
    this.$.RadareApp.setIndex (1);
  },
  create: function() {
      r2.load_settings();
      this.inherited (arguments);
      var data = [
        { name: "Disassembler", active: true },
        { name: "Assembler" },
        { name: "Hexdump" },
        { name: "Graph" },
        { name: "Search" },
        { name: "Console" },
        { name: "Debugger" },
        { name: "Script" },
        { name: "Settings", separator: true },
        { name: "Logs" },
        { name: "About" }
      ];
      this.$.lp.data = data;
      this.$.mp.data = data;
      r2ui.ra =
      this.$.mp.ra =
      this.$.lp.ra =
      this.$.rp.ra = this;
      var mp = this.$.mp;
      r2ui.mp = mp;
      this.$.lp.openCallback = function (idx) {
        mp.openPage (idx);
      };
      this.$.lp.refresh ();
  },
  handleKeyPress: function(inSender, inEvent) {
    for (var key in Config.keys) {
      if (key.substring (0, 2) == "C-") {
        if (inEvent.ctrlKey) {
          var k = key.substring (2).charCodeAt (0);
          if (inEvent.charCode == k) {
            var cmd = Config.keys[key];
            eval (cmd+";");
          }
        }
      } else {
        var k = key.charCodeAt (0);
        if (inEvent.charCode == k) {
          var cmd = Config.keys[key];
          eval (cmd+";");
        }
      }
    }
    //dump (inEvent);
//alert (inEvent.ctrlKey);
    // Use inEvent.charCode to detect spacebar
/*
    if (inEvent.charCode === 32) {
      this.$.myContent.setContent("I thought");
    } else {
      var key = String.fromCharCode(inEvent.charCode).toUpperCase();
      this.$.myContent.setContent("Last key pressed: " + key);
    }
*/
  }
});

window.onload = function() {
  var obj = new RadareApp ().renderInto (document.body)
}
