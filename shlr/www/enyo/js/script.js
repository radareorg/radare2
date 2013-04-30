enyo.kind ({
  name: "Script",
  kind: "Scroller",
  style: "background-color:#c0c0c0",
  clear: function () {
    with (this.$.input) { setContent (value = ''); render() };
  },
  demo: function () {
    with (this.$.input) {
      setContent (value = [
        'r2.disassemble (0, "9090", function(text) {',
        '  show (text)',
        '  show ()',
        '  r2.assemble (0, "mov eax, 33", function (text) {',
        '    show (text);',
        '  });',
        '  show (r2)',
        '});'].join ('\n'));
      render();
    }
  },
  run: function () {
    var code = this.$.input.value;
    var out = "";
/* helper functions */
  function show(x) {
    if (!x) out += "\n"; else
    if (typeof x == 'object') {
      out += "{";
      for (var y in x) {
        var v = x[y]; //(typeof x[y] == 'function')? 'function': x[y];
        out += y+": "+v+"\n , ";
      }
      out += "}";
    } else {
      out += x+"\n";
    }
  }
    try {
      eval (code);
      this.$.output.setContent (out);
    } catch (e) {
      alert (e);
    }
  },
  components: [
    {tag: "p", style:"margin-left:10px", components: [
      {kind: "onyx.Button", content: "Run", classes: "sourcebutton", ontap: "run" },
      {kind: "onyx.Button", content: "Clear", classes: "sourcebutton", ontap: "clear" },
      {kind: "onyx.Button", content: "Demo", classes: "sourcebutton", ontap: "demo" },
    ]},
    {kind: "onyx.TextArea", name: "input", classes: "sourcecode" },
    {tag: "pre", name: "output", style:"margin-left:12px" }
  ]
});
