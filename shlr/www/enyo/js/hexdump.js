enyo.kind ({
  name: "Hexdump",
  kind: "Scroller",
  style: "background-color:#c0c0c0;padding:8px",
  components: [
    {tag: "pre", allowHtml: true, name: "output"}
  ],
  create: function() {
    this.inherited (arguments);
    var output = this.$.output;
    r2.cmd ("px 8192", function(a) {
      output.setContent (r2.filter_asm (a, "px"));
    });
  }
});
