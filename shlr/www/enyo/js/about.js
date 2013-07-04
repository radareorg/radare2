enyo.kind ({
  name: "About",
  kind: "Scroller",
  style: "background-color:#303030",
  components: [
    {tag: "center", components: [
      {tag: "h1", style: "color:#f0f0f0", content: "r2wui"},
      {kind: "Image", src: "icon.png" },
      {tag: "h3", style: "color:#707070;margin-bottom:50px", content: "the web frontend for radare2"},
      {tag: "h2", style: "color:#a0a0a0", content: "author: pancake 2013"},
      {tag: "h2", style: "color:#a0a0a0", content: "version: 0.9.5git3", name: "version"}
    ]}
  ],
  create: function() {
    this.inherited (arguments);
    r2.cmd ("?V", function (version) {
      this.$.version.setContent ("version: "+version);
    });
  }
});
