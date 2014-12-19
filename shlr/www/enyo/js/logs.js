enyo.kind ({
  name: "Logs",
  kind: "Scroller",
  style: "background-color:#c0c0c0;padding-left:8px",
  components: [
    {tag: "form", attributes: {action:"javascript:#"}, components: [
      {kind: "FittableRows", fit: true, classes: "fittable-sample-shadow", components: [
        {kind: "onyx.InputDecorator", style: "margin-top:8px;background-color:#404040;width: 90%;display:inline-block", components: [
          {kind: "Input", style:"width:100%;color:white", value: '', onkeydown: "sendMessage", attributes: {autocapitalize:"off"}, name: "input"},
        ]},
        {tag: "pre", classes:"r2ui-terminal", style:"width:90%;", fit: true, allowHtml: true, name:"output"}
      ]}
    ]}
  ],
  logger: null,
  create: function() {
    this.inherited (arguments);
    r2ui._log = this;
  },
  connect: function() {
    var out = this.$.output;
    this.logger = r2.getTextLogger ().on ("message", function (msg) {
      out.setContent (out.getContent() + msg.text + "\n");
    });
    this.logger.autorefresh (3);
  },
  sendMessage: function (inSender, inEvent) {
    if (inEvent.keyCode === 13) {
      var msg = this.$.input.getValue ();
      this.$.input.setValue ("");
      this.logger.send (msg);
    }
  }
});
