enyo.kind ({
  name: "About",
  kind: "Scroller",
  style: "background-color:#303030",
  components: [
    {tag: "center", components: [
      {tag: "h1", style: "color:#f0f0f0", content: "r2wui"},
      {kind: "Image", src: "icon.png" },
      {tag: "h3", style: "color:#707070;margin-bottom:50px",
       content: "the web frontend for radare2"},
      {tag: "h2", style: "color:#a0a0a0", content: "author: pancake 2013-2014"},
      {tag: "h2", style: "color:#a0a0a0", content: "version: ???", name: "vertext"},
      {tag: "h2", style: "color:#a0a0a0", content: "revision: ???", name: "revtext"}
    ]}
  ],
  create: function() {
    this.inherited (arguments);
    (function(me) {
      setTimeout (function() {
      r2.cmd ("?V", function (v) {
        var version = v.split (" ")[0];
        var revision = v.split (" ")[2];
        me.$.vertext.setContent ("version: "+version);
        me.$.revtext.setContent ("revision: "+revision);
      });
      }, 1000);
    })(this);
  }
});
