enyo.kind({
  name: "Disassembler",
  kind: "Scroller",
  tag: "div",
  style:"margin-left:16px",
  data: [ "pop eax", "push ecx", "jmp 0x80040", "call 0x80404", "xor eax, eax", "int 0x80" ],
  components: [
    {tag: "pre", allowHtml: true, name: "text", content: "TODO : Disasm"},
/*
    {kind: "List", count:3, name: "list", style:"height:400px", realtimeFit:false, onSetupItem: "setupItem", components: [
      {kind: "onyx.Item", layoutKind: "HFlexLayout", style:"padding:0px", components: [
        {kind: "onyx.Button", name: "msg", fit:true, active: true, ontap: "rowTap"}
      ]}
    ]}
*/
  ],
  create: function() {
    this.inherited (arguments);
 //   this.$.list.setCount (this.data.length) ;
    var text = this.$.text;
    r2.get_disasm ("entry0", 1024, function (x) {
      x = r2.filter_asm (x, "pd");
      text.setContent (x);
    });
    //this.refresh ();
  },
  setupItem: function (inSender, inIndex) {
      this.$.msg.setContent (this.data[inIndex.index]); //"patata"); //item.name);
      return true;
  }
});
