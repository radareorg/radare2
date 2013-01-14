enyo.kind({
  name: "Console",
  kind: "Scroller",
  tag: "div",
  style:"margin-left:16px",
  components: [
    {tag: "form", attributes: {action:"javascript:#"}, components: [
      {kind: "FittableRows", fit: true, classes: "fittable-sample-shadow", components: [
        {kind: "onyx.InputDecorator", style: "width: 90%;display:inline-block", components: [
          {kind: "Input", style:"width:100%", value: '', onkeydown: "runCommand", attributes: {autocapitalize:"off"}, name: "input"},
        ]},
        {tag: "pre", classes:"r2ui-terminal", style:"width:90%;", fit: true, allowHtml: true, name:"output"}
      ]}
    ]}
  ],
  runCommand: function(inSender, inEvent) {
    if (inEvent.keyCode === 13) {
      var cmd = this.$.input.getValue ();;
      this.$.input.setValue ("");
      var out = this.$.output;
      r2.cmd (cmd, function(x) {
        out.setContent (x);
      });
      return false;
    }
  }
});
