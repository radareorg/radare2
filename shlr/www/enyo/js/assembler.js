enyo.kind({
  name: "Assembler",
//  kind: "Scroller",
  components: [
    {tag: "form", style:"margin-top:8px;margin-left:8px", attributes: {action:"javascript:#"}, components: [
      {kind: "FittableRows", fit: true, components: [
        {kind: "onyx.InputDecorator", classes: "r2ui-input", components: [
          {tag: "font", content: "opcode", style:"font-weight:bold;margin-right:20px"},
          {kind: "Input", value: '', style:"width:89%", onkeydown: "assembleOpcode", attributes: {autocapitalize:"off"}, name: "opcode"},
        ]},
        {kind: "onyx.InputDecorator", classes: "r2ui-input", components: [
          {tag: "font", content: "bytes", style:"margin-right:20px;font-weight:bold"},
          {kind: "Input", value: '', style:"width:120px", onkeydown: "assembleOpcode", attributes: {autocapitalize:"off"}, name: "bytes"},
        ]},
        {kind: "onyx.InputDecorator", classes: "r2ui-input", components: [
          {tag: "font", content: "offset", style:"margin-right:20px;font-weight:bold"},
          {kind: "Input", value: 'entry0', style:"width:120px", onkeydown: "assembleOpcode", attributes: {autocapitalize:"off"}, name: "offset"},
        ]}
      ]}
    ]}
  ],
  assembleOpcode: function(inSender, inEvent) {
    if (inEvent.keyCode === 13) {
      var arg = inSender.getValue ();
      var off = this.$.offset.getValue ();
      switch (inSender.name) {
      case 'opcode':
        var hex = this.$.bytes;
        r2.assemble (off, arg, function (bytes) {
          hex.setValue (bytes); // ? s/\n/;/g
        });
        break;
      case 'bytes':
        var op = this.$.opcode;
	//r2.cmd ("pi 1@b:"+arg, function (x) {
        r2.disassemble (off, arg, function (x) {
          op.setValue (x); // ? s/\n/;/g
        });
        break;
      case 'offset':
        break;
      }
    }
  }
});
