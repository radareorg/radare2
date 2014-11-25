enyo.kind ({
  name: "Console",
  kind: "Scroller",
  classes: "r2panel",
  style: "background-color:#c0c0c0;padding-left:7px",
  components: [
    {tag: "form", attributes: {action:"javascript:#"}, components: [
      {kind: "FittableRows", fit: true, classes: "fittable-sample-shadow", components: [
        {kind: "onyx.InputDecorator", style: "margin-top:8px;background-color:#404040;width: 90%;display:inline-block", components: [
          {kind: "Input", style:"width:100%;color:white", value: '', onkeydown: "runCommand", attributes: {autocapitalize:"off"}, name: "input"},
        ]},
        {tag: "pre", classes:"r2ui-terminal", style:"width:90%;", fit: true, allowHtml: true, name:"output"}
      ]}
    ]}
  ],
  runCommand: function (inSender, inEvent) {
    if (inEvent.keyCode === 13) {
      var cmd = this.$.input.getValue ();
      this.$.input.setValue ("");
      (function (out) {
        r2.cmd (cmd, function (x) {
          out.setContent (x);
        });
      })(this.$.output);
    }
  }
});
