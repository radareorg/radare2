enyo.kind({
  name: "Hexdump",
  kind: "Scroller",
  style: "background-color:#f0f0f0",
  components: [
    {tag: "center", components: [
      {tag: "h1", style: "color:#303030", content: "hexdump"},
      {tag: "pre", name: "output"}
    ]}
  ],
  create: function() {
    this.inherited (arguments);
    var output = this.$.output;
    r2.cmd ("px 8192", function(a) {
      output.setContent (a);
    });
  }
});
