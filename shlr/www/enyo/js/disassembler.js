enyo.kind ({
  name: "Disassembler",
  kind: "Scroller",
  tag: "div",
  style:"margin:0px;background-color:#a0a0a0",
  data: null,
  components: [
    {tag: "div", content: "^", classes: "moreless", ontap: "less"},
    {tag: "pre", allowHtml: true, name: "text", content: ".."},
    {tag: "div", content: "v", classes: "moreless", ontap: "more"},
/*
    {kind: "List", count:3, name: "list", style:"height:400px", realtimeFit:false, onSetupItem: "setupItem", components: [
      {kind: "onyx.Item", layoutKind: "HFlexLayout", style:"padding:0px", components: [
        {kind: "onyx.Button", name: "msg", fit:true, active: true, ontap: "rowTap"}
      ]}
    ]}
*/
  ],
  min: 0,
  max: 0,
  block: 512,
  base: "entry0",
  less: function() {
    var self = this;
    var text = this.$.text;
    this.min += this.block;
    r2.get_disasm (this.base+"-"+this.min, this.block, function (x) {
      x = r2.filter_asm (x, "pd");
      var oldy = r2ui._dis.getScrollBounds().height;
      text.setContent (x+text.getContent());
      var newy = r2ui._dis.getScrollBounds().height;
      r2ui._dis.scrollTo (0, newy-oldy);
    });
  },
  more: function() {
    var text = this.$.text;
    this.max += this.block;
    r2.get_disasm (this.base+"+"+this.max, this.block, function (x) {
      x = r2.filter_asm (x, "pd");
      text.setContent (text.getContent() + x);
    });
  },
  seek: function(addr) {
    var text = this.$.text;
    this.base = addr;
    this.min = this.max = 0;
    r2.get_disasm (addr, this.block, function (x) {
      x = r2.filter_asm (x, "pd");
      text.setContent (x);
    });
  },
  create: function() {
    this.inherited (arguments);
 //   this.$.list.setCount (this.data.length) ;
    var text = this.$.text;
    this.seek ("entry0");
    r2ui._dis = this;
    r2ui.history_push ("entry0");
    //this.refresh ();
  },
  setupItem: function (inSender, inIndex) {
      this.$.msg.setContent (this.data[inIndex.index]);
      return true;
  }
});
