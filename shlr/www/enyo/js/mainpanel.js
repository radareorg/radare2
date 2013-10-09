enyo.kind ({
  name: "MainPanel",
  classes: "onyx",
  kind: "FittableRows",
  classes: "enyo-fit",
  style: "margin:0px;padding:0px;border:0px",
  //style: "background-color: #c0c0c0",
  data: null,
/*
  refresh: function () {
    this.$.list.setCount (this.data.length);
    this.$.list.refresh (); // necessary?? // inherit??
  },
*/
  /* callbacks */
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
  /* menu actions */
  goRename: function() {
   var msg = prompt ('New name?', '');
   if(msg)
   r2.cmd("afr "+msg, function() {
     r2ui.seek ("$$", true);
   });
  },
  goComment: function() {
   var msg = prompt ('Comment?', '');
   if(msg)
   r2.cmd("CC "+msg, function() {
     r2ui.seek ("$$", true);
   });
  },
  goFlag: function() {
   var msg = prompt ('Flag name?', '');
   if(msg)
   r2.cmd("f "+msg, function() {
     r2ui.seek ("$$", true);
   });
  },
  goUnflag: function() {
   r2.cmd("f-$$", function() {
     r2ui.seek ("$$", true);
   });
  },
  goAnalyze: function() {
   r2.cmd("af", function() {
   r2ui.seek ("$$", true);
   });
  },
  goCopy: function() {
   var msg = prompt ('How many bytes?', '');
   if(msg)
   r2.cmd("y "+msg, function() {
     r2ui.seek ("$$", true);
   });
  },
  goPaste: function() {
   r2.cmd("yy", function() {
     r2ui.seek ("$$", true);
   });
  },
  /*-- write */
  wrString: function() {
   var msg = prompt ('Text', '');
   if(msg)
   r2.cmd("w "+msg, function() {
     r2ui.seek ("$$", true);
   });
  },
  wrOpcode: function() {
   var msg = prompt ('Opcode', '');
   if(msg)
   r2.cmd ("wa "+msg, function() {
     r2ui.seek ("$$", true);
   });
  },
  wrFile: function() {
   var msg = prompt ('Filename', '');
   if(msg)
   r2.cmd("wf "+msg, function() {
     r2ui.seek ("$$", true);
   });
  },
  wrHex: function() {
   var msg = prompt ('Hexpair', '');
   if(msg)
   r2.cmd("wx "+msg, function() {
     r2ui.seek ("$$", true);
   });
  },
  /* -- convert */
  coCode: function() {
   var msg = prompt ('How many bytes?', '');
   if(msg)
   r2.cmd("y "+msg, function() {
     r2ui.seek ("$$", true);
   });
  },
  coString: function() {
   r2.cmd("Cz", function() {
     r2ui.seek ("$$", true);
   });
  },
  coData: function() {
   var msg = prompt ('How many bytes?', '');
   if(msg)
   r2.cmd("Cd "+msg, function() {
     r2ui.seek ("$$", true);
   });
  },
  setTitle: function (title) {
    if (title) {
      this.$.title.setContent (title);
      this.$.title.setStyle ("visibility:visible;top:8px");
      this.$.extra.setStyle ("visibility:hidden;");//position:absolute;left:48px;scroll:overflow");
    } else {
      this.$.title.setStyle ("visibility:hidden");
      this.$.extra.setStyle ("visibility:visible;");//position:absolute;left:48px;scroll:overflow");
    }
  },
  /* widgets dom */
  components: [
    {kind: "onyx.Toolbar", components: [
    //{kind: "onyx.MoreToolbar", components: [
      {kind: "onyx.Button", content: "[", ontap: "openSidebar", classes: "top" },
      {kind: "onyx.Button", content: "]", ontap: "openSidebar2", classes: "top" },
    {name: "title", tag: "h2", content: "Assembler", classes: "topbox", style: "visibility:hidden;" },
    {name: "extra", tag: "div", classes: "topbox", components: [
//style: "position:absolute;top:0px;left:48px;scroll:overflow;visibility:visible", components: [
/*
          {kind: "onyx.Button", content: "]", ontap: "openSidebar2", style: "padding:4px"},
*/
        {kind: "onyx.PickerDecorator", classes: "top", components: [
          {kind: "onyx.Button", content: "Actions"},
          {kind: "onyx.Picker", components: [
            {content: "Analyze", ontap: "goAnalyze"},
            {content: "Rename", ontap: "goRename"},
            {content: "Comment", ontap: "goComment"},
            {content: "Flag", ontap: "goFlag"},
            {content: "Unflag", ontap: "goUnflag"},
            {content: "Copy", ontap: "goCopy"},
            {content: "Paste", ontap: "goPaste"}
          ]}
        ]},
        {kind: "onyx.Button", content: "<", ontap: "prevSeek", classes: "top", style: "top:10px" },
        {kind: "onyx.Button", content: ">", ontap: "nextSeek", classes: "top", style: "top:10px" },
        {kind: "onyx.InputDecorator", style: "width: 200px;top:10px", classes: "top", components: [
          {kind: "onyx.Input", name:"input", value: 'entry0', onchange: "gotoSeek", onkeydown:"inputKey" }
        ]},
          {kind: "onyx.PickerDecorator", classes: "top", components: [
            {kind: "onyx.Button", content: "Convert"},
            {kind: "onyx.Picker", components: [
              {content: "Data", ontap: 'coData'},
              {content: "Code", ontap: 'coCode'},
              {content: "String", ontap: 'coString'},
            ]}
          ]},
          {kind: "onyx.PickerDecorator", classes: "top", components: [
            {kind: "onyx.Button", content: "Write"},
            {kind: "onyx.Picker", components: [
              {content: "File", ontap: 'wrFile'},
              {content: "Hexpair", ontap: 'wrHex'},
              {content: "String", ontap: 'wrString'},
              {content: "Opcode", ontap: 'wrOpcode'},
            ]}
          ]},
/*
          {kind: "onyx.Button", content: "Add", ontap: "addPanel"},
          {kind: "onyx.Button", content: "Delete", ontap: "deletePanel"}
*/
    ]},
    ]},
    {kind: "Panels", name:"panels", fit:true, draggable: false,
        realtimeFit: true, components: [
      {kind:"Disassembler", name: "pageDisassembler"},
      {kind:"Assembler", name:"pageAssembler"},
      {kind:"Hexdump", name: "pageHexdump"},
      {kind:"Graph", name: "pageGraph"},
      {kind:"Search", name: "pageSearch"},
      {kind:"Console", name: "pageConsole"},
      {kind:"Debugger", name: "pageDebugger"},
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
// TODO: this is just a hack
    var r = -1;
    switch (idx) {
	case "Disassembler": r = 0; break;
	case "Assembler": r = 1; break;
	case "Hexdump": r = 2; break;
	case "Graph": r = 3; break;
	case "Search": r = 4; break;
	case "Console": r = 5; break;
	case "Debugger": r = 6; break;
	case "Script": r = 7; break;
	case "Settings": r = 8; break;
	case "Logs": r = 9; break;
	case "About": r = 10; break;
      }
      if (r==-1) {
        // alert ("Unknown page");
        sp.setIndex (idx);
        return;
      }
      eval ("var x = this.$.page"+idx);
      switch (r) {
      case 0:
      case 2:
        this.setTitle ();
        break;
      default:
        this.setTitle (idx);
        break;
      }
      //x.setContent (str);
      sp.setIndex (r);
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
    if (addr[0]=='!') {
      r2.cmd (addr.slice (1), function (x) {
        alert (x);
      });
    } else {
      this.seekStack.push ();
    }
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
