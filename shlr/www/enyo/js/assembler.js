enyo.kind({
  name: "Assembler",
  kind: "Scroller",
  style: "background-color:#303030",
  components: [
    {tag: "center", components: [
      {tag: "h1", style: "color:#f0f0f0", content: "Assembler"},
    ]},
    {tag: "form", style:"margin-left:10px", attributes: {action:"javascript:#"}, components: [
      {kind: "FittableRows", fit: true, components: [
        {kind: "onyx.InputDecorator", classes: "r2ui-input", components: [
          {tag: "p", content: "opcode", style:"margin-right:20px"},
          {kind: "Input", value: '', onkeydown: "assembleOpcode", attributes: {autocapitalize:"off"}, name: "opcode"},
        ]},
        {kind: "onyx.InputDecorator", classes: "r2ui-input", components: [
          {tag: "p", content: "bytes", style:"margin-right:20px"},
          {kind: "Input", value: '', onkeydown: "assembleOpcode", attributes: {autocapitalize:"off"}, name: "bytes"},
        ]},
        {kind: "onyx.InputDecorator", classes: "r2ui-input", components: [
          {tag: "p", content: "offset", style:"margin-right:20px"},
          {kind: "Input", value: 'entry0', onkeydown: "assembleOpcode", attributes: {autocapitalize:"off"}, name: "offset"},
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
	r2.cmd ('"pa :'+arg+'"', function (x) {
          hex.setValue (x); // ? s/\n/;/g
        });
        break;
      case 'bytes':
        var op = this.$.opcode;
	r2.cmd ("pi 1@b:"+arg, function (x) {
          op.setValue (x); // ? s/\n/;/g
        });
        break;
      case 'offset':
        break;
      }
    }
  }
});
