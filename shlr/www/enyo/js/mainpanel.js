
enyo.kind ({
  name: "MainPanel",
  classes: "onyx",
  kind: "FittableRows",
  classes: "enyo-fit",
  //style: "background-color: #c0c0c0",
  data: null,
/*
  refresh: function () {
    this.$.list.setCount (this.data.length);
    this.$.list.refresh (); // necessary?? // inherit??
  },
*/
  buttonClicked: function (x) {
    alert ("let's play!");
  },
  cancelClicked: function (x) {
    alert ("nothing to see here! move along.");
  },
  inputKey: function (inSender, inEvent) {
    if (inEvent.keyCode === 13) {
      var off = this.$.input.getValue ();
     // this.$.input.setValue ("");
      r2ui.opendis (off);
    }
  },
  components: [
    {kind: "onyx.Toolbar", components: [
    //{kind: "onyx.MoreToolbar", components: [
      {kind: "onyx.Button", content: "[", ontap: "openSidebar", style: "padding:4px"},
/*
          {kind: "onyx.Button", content: "]", ontap: "openSidebar2", style: "padding:4px"},
*/
      {kind: "onyx.Button", content: "<", ontap: "prevSeek", style: "padding:8px"},
      {kind: "onyx.Button", content: ">", ontap: "nextSeek", style:"padding:8px"},
      {kind: "onyx.InputDecorator", style: "width: 200px;", components: [
        {kind: "onyx.Input", name:"input", value: 'entry0', onchange: "gotoSeek", onkeydown:"inputKey"}
      ]},
          //{kind: "onyx.Button", content: "Go", ontap: "gotoSeek"},
          {kind: "onyx.PickerDecorator", components: [
            {kind: "onyx.Button", content: "Actions"},
            {kind: "onyx.Picker", components: [
              {content: "Analyze"},
              {content: "Rename"},
              {content: "Comment"},
              {content: "Flag"},
              {content: "Copy"},
              {content: "Paste"}
            ]}
          ]},
          {kind: "onyx.PickerDecorator", components: [
            {kind: "onyx.Button", content: "Convert"},
            {kind: "onyx.Picker", components: [
              {content: "Data"},
              {content: "Code"},
              {content: "String"},
            ]}
          ]},
          {kind: "onyx.PickerDecorator", components: [
            {kind: "onyx.Button", content: "Write"},
            {kind: "onyx.Picker", components: [
              {content: "File"},
              {content: "Hexpair"},
              {content: "String"},
              {content: "Opcode"},
            ]}
          ]},
/*
          {kind: "onyx.Button", content: "Add", ontap: "addPanel"},
          {kind: "onyx.Button", content: "Delete", ontap: "deletePanel"}
*/
    ]},
    {kind: "Panels", name:"panels", fit:true, draggable: false,
        realtimeFit: true, components: [
      {kind:"Disassembler", name: "pageDisassembler"},
      {kind:"Assembler", name:"pageAssembler"},
      {kind:"Hexdump", name: "pageHexdump"},
      {kind:"Graph", name: "pageGraph"},
      {kind:"Search", name: "pageSearch"},
      {kind:"Console", name: "pageConsole"},
      {kind:"Logs", name: "pageLogs"},
      {kind:"Script", name: "pageScript"},
      {kind:"Settings", name:"pageSettings"},
      {kind:"About", name: "pageAbout"},
    ]}
  ],
  create: function() {
    this.inherited(arguments);
    r2ui.panels = this.$.panels;
       //this.$.panels.setArrangerKind ("CardArranger");
      // if (enyo.Panels.isScreenNarrow()) {
    this.$.panels.setIndex(0);
  },
  ra: null,
  openSidebar: function() {
    this.ra.setIndex (this.ra.index? 0:1);
  },
  openSidebar2: function() {
    this.ra.setIndex (2); //(this.ra.index<2)? 2:1);
  },
  rendered: function() {
    this.inherited(arguments);
  },
  openPage: function(idx) {
      var str, sp = this.$.panels;
      eval ("var x = this.$.page"+idx);
// TODO: this is just a hack
      switch (idx) {
	case "Disassembler": idx = 0; break;
	case "Assembler": idx = 1; break;
	case "Hexdump": idx = 2; break;
	case "Graph": idx = 3; break;
	case "Search": idx = 4; break;
	case "Console": idx = 5; break;
	case "Logs": idx = 6; break;
	case "Script": idx = 7; break;
	case "Settings": idx = 8; break;
	case "About": idx = 9; break;
      }
      //x.setContent (str);
      sp.setIndex (idx);
  },
  seekStack: [],
  nextSeek: function() {
    var addr = r2ui.history_next ()
    if (!addr) return;
    r2ui.seek (addr, true);
    //alert ("nxt "+addr);
  },
  prevSeek: function() {
    var addr = r2ui.history_prev()
    if (!addr) return;
    r2ui.seek (addr, true); //r2ui.history_prev (), true);
    //alert ("pop "+addr);
  },
  gotoSeek: function() {
    var addr = this.$.input.getValue();
    this.seekStack.push ();
/*
      var sp = this.$.panels;
      //this.openPage (this.$.input.getValue());
      //sp.components[3].setContent ("JAJAJ");
this.$.page3.setContent ("content-a");
alert (sp.components[3].content);
      sp.components[3].content = "JAJAJ";
sp.reflow();
sp.render ();
      sp.setIndex(3);
var i = 3;
  var p = sp.createComponent ({
                        style:"background: red",
                        content:i
                });
      p.render();
                sp.reflow();
                sp.setIndex(3);
*/
  }
});

