enyo.kind ({
  name: "Assembler",
  kind: "Scroller",
  classes: "r2panel",
  style: "background-color:#c0c0c0;",
  components: [
    {tag: "form", style:"margin-top:8px;margin-left:8px", attributes: {action:"javascript:#"}, components: [
      {kind: "FittableRows", fit: true, components: [
        {kind: "onyx.InputDecorator", classes: "r2ui-input", components: [
          {tag: "font", content: "opcode", classes:"r2ui-input", style: "width:64px;font-weight:bold"},
          {kind: "Input", value: '', style:"width:60%", onkeydown: "assembleOpcode", attributes: {autocapitalize:"off"}, name: "opcode"},
        ]},
        {kind: "onyx.InputDecorator", classes: "r2ui-input", components: [
          {tag: "font", content: "bytes", classes:"r2ui-input", style: "width:64px;font-weight:bold"},
          {kind: "Input", value: '', style:"width:120px", onkeydown: "assembleOpcode", attributes: {autocapitalize:"off"}, name: "bytes"},
        ]},
        {kind: "onyx.InputDecorator", classes: "r2ui-input", components: [
          {tag: "font", content: "offset", classes: "r2ui-input", style:"width:64px;font-weight:bold"},
          {kind: "Input", value: 'entry0', style:"width:120px", onkeydown: "assembleOpcode", attributes: {autocapitalize:"off"}, name: "offset"}
        ]},
      ]}
    ]},
    {tag: "form", style:"margin-top:8px;margin-left:8px", attributes: {action:"javascript:#"}, components: [
    {tag: "h2", content: "Calculator" },
        {kind: "onyx.InputDecorator", classes: "r2ui-input", components: [
          {tag: "font", name: "value", content: "0", classes: "r2ui-input", style:"width:200px;font-weight:bold"},
          {kind: "Input", name: "ivalue", value: '0', style:"width:300",
           onkeydown: "calculateValue", attributes: {autocapitalize:"off"} }
        ]}
      ]}
  ],
  calculateValue: function (inSender, inEvent) {
    if (inEvent.keyCode === 13) {
      var v = this.$.value;
      var val = inSender.getValue ();
      v.setContent ("...");
      r2.cmd ('?v '+val, function (x) {
        v.setContent (x);
      });
    }
  },
  assembleOpcode: function (inSender, inEvent) {
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
