function dump(obj) {
  var x = "";
  for (var a in obj) x += a+"\n";
  alert (x);
}

function Ajax (method, uri, body, fn) {
        var x = new XMLHttpRequest ();
        x.open (method, uri, false);
	x.setRequestHeader ('Accept', 'text/plain');
	x.setRequestHeader ('Accept', 'text/html');
	x.setRequestHeader ("Content-Type",
		"application/x-ww-form-urlencoded; charset=UTF-8");
        x.onreadystatechange = function (e) {
		if (x.status == 200) {
			if (fn) fn (x.responseText);
		} else {
			fn (null); //console.error ("ajax "+x.status)
		}
        }
        x.send (body);
}

function getfile(file, cb) {
	Ajax ("GET", file, null, cb);
}

//getfile ("myfile", function (x) { alert ("myfile: "+x); });

function objtostr(obj) {
  var str = "";
  for (var a in obj)
    str += a+": "+obj[a] + ",\n";
  return str;
}

enyo.kind({
  name: "About",
  kind: "Scroller",
  style: "background-color:#303030",
  components: [
    {tag: "center", components: [
      {tag: "h1", style: "color:#f0f0f0", content: "About r2wui"},
      {kind: "Image", src: "icon.png" },
      {tag: "h2", style: "color:#a0a0a0", content: "author: pancake 2013"},
      {tag: "h2", style: "color:#a0a0a0", content: "version: 0.9.3git"},
    ]}
  ]
});

enyo.kind({
  name: "Disassembler",
  kind: "Scroller",
  tag: "div",
  style:"margin-left:16px",
  data: [ "pop eax", "push ecx", "jmp 0x80040", "call 0x80404", "xor eax, eax", "int 0x80" ],
  components: [
    {tag: "h2",content: "TODO : Disasm"},
// 3
    {kind: "List", name:"list", style:"height:100%", realtimeFit:false, onSetupItem: "setupItem", components: [
      {kind: "List", name: "list", style:"height:400px", realtimeFit:false, onSetupItem: "setupItem", components: [
        {kind: "onyx.Item", layoutKind: "HFlexLayout", style:"padding:0px", components: [
          {name:"separator", tag: "hr", style:"height:1px;visibility:hidden"},
          {kind: "onyx.Button", name: "button", style: "width:100%", fit:true, active: true, ontap: "rowTap"}
        ]}
      ]}
    ]}
  ],
  setupItem: function (inSender, inIndex) {
      var item = this.data[inIndex.index];
      if (item.separator) {
        this.$.separator.setStyle("visibility:visible;border:0;background-color:#404040");
      } else {
        this.$.separator.setStyle("visibility:hidden");
      }
      this.$.button.setContent (item.name);
      return true;
  }
});
enyo.kind({
  name: "Console",
  kind: "Scroller",
  tag: "div",
  style:"margin-left:16px",
  components: [
    {tag: "h2",content: "TODO"},
                                        {kind: "onyx.InputDecorator", style: "width: 200px;", components: [
                                                {kind: "onyx.Input", value: 0, onchange: "gotoPanel"}
                                        ]},
  ]
});

enyo.kind({
  name: "Preferences",
  classes: "panels-sample-sliding-content",
  kind: "Scroller",
  tag: "div",
  style:"margin-left:16px",
  components: [
    {kind: "FittableRows", fit: false, components: [
      {tag: "h2", content: "CPU" }
      ,{kind: "onyx.InputDecorator", components: [
         {tag: "p", content: "Arch", classes:"rowline"},
         {kind: "onyx.PickerDecorator", components: [
           {},
           {kind: "onyx.Picker", components: [
             {content: "x86", active: true},
             {content: "arm"},
             {content: "ppc"},
             {content: "bf"}
           ]}
         ]}
      ]}
      ,{kind: "onyx.InputDecorator", components: [
         {tag: "p", content: "Bits", classes:"rowline"},
         {kind: "onyx.PickerDecorator", components: [
           {},
           {kind: "onyx.Picker", components: [
             {content: "8"},
             {content: "16"},
             {content: "32", active: true},
             {content: "64"}
           ]}
         ]}
      ]}
      ,{kind: "onyx.InputDecorator", components: [
         {tag: "p", content: "Endian", classes:"rowline"},
         {kind: "onyx.PickerDecorator", components: [
           {},
           {kind: "onyx.Picker", components: [
             {content: "little", active: true},
             {content: "big"},
           ]}
         ]}
      ]}
      ,{tag: "h2", content: "Disassembly" },
      {kind: "onyx.InputDecorator", components: [
        {tag: "p", content: "Show bytes", classes:"rowline", ontap: "nextPanel"},
        {kind: "onyx.ToggleButton", name: "toggle_bytes "},
      ]}
      ,{kind: "onyx.InputDecorator",components: [
        {tag: "p", content: "Show offsets", classes:"rowline", ontap: "nextPanel"},
        {kind: "onyx.ToggleButton", name: "toggle_offset" },
      ]}
      ,{kind: "onyx.InputDecorator",components: [
        {tag: "p", content: "Show lines", classes:"rowline", ontap: "nextPanel"},
        {kind: "onyx.ToggleButton", name: "toggle_lines" },
      ]}
      ,{kind: "onyx.InputDecorator",components: [
        {tag: "p", content: "Pseudo", classes:"rowline", ontap: "nextPanel"},
        {kind: "onyx.ToggleButton", name: "toggle_pseudo" },
      ]}
    ]}
    ,{tag: "h2", content: "Save changes?" }
    ,{tag: "div",style:"margin-left:50px", components: [
      {kind: "onyx.Button", style: "position:relative;left:0px", content: "Reset"},
      {kind: "onyx.Button", style: "position:relative;left:50px", content: "Save", classes: "onyx-affirmative"}
    ]}
    ,{tag: "div", style: "height:64px"}
  ]
});

enyo.kind({
  name: "MainPanel",
  classes: "onyx",
  //kind: enyo.Control,
  kind: "FittableRows",
  tag: "div",
  classes: "enyo-fit",
  style: "background-color: #c0c0c0",
  data: null,
  refresh: function () {
    this.$.list.setCount (this.data.length);
    this.$.list.refresh ();
  },
  buttonClicked: function (x) {
    alert ("let's play!");
  },
  cancelClicked: function (x) {
    alert ("nothing to see here! move along.");
  },
  components: [
                {kind: "FittableColumns", noStretch: true, classes: "onyx-toolbar onyx-toolbar-inline", components: [
                        {kind: "Scroller", thumb: false, fit: true, touch: false, vertical: "hidden", style: "margin: 0;", components: [
                                {classes: "onyx-toolbar-inline", style: "white-space: nowrap;", components: [
                                    {kind: "onyx.PickerDecorator", components: [
                                          {kind: "onyx.Button", content: "Actions"},
                                          {kind: "onyx.Picker", components: [
                                            {content: "Analyze"},
                                            {content: "Rename"},
                                            {content: "Comment"},
                                            {content: "Flag"}
                                          ]}
                                        ]},
                                        {kind: "onyx.Button", content: "<", ontap: "prevPanel"},
                                        {kind: "onyx.Button", content: ">", ontap: "nextPanel"},
                                        {kind: "onyx.InputDecorator", style: "width: 200px;", components: [
                                                {kind: "onyx.Input", value: 0, onchange: "gotoPanel"}
                                        ]},
                                        {kind: "onyx.Button", content: "Go", ontap: "gotoPanel"},
/*
                                        {kind: "onyx.Button", content: "Add", ontap: "addPanel"},
                                        {kind: "onyx.Button", content: "Delete", ontap: "deletePanel"}
*/
                                ]}
                        ]}
                ]},
                {kind: "Panels", name:"samplePanels", fit:true, draggable: false,
				realtimeFit: true, classes: "panels-sample-panels enyo-border-box", components: [
                        {kind:"Disassembler", name: "pageDisassembler"},
                        {kind:"Assembler", name:"pageAssembler"},
                        {kind:"Hexdump", name: "pageHexdump"},
                        {kind:"Console", name: "pageConsole"},
                        {kind:"Preferences", name:"pagePreferences"},
                        {kind:"About", name: "pageAbout"},
                ]}
    ],
    create: function() {
      this.inherited(arguments);
      // this.$.samplePanels.setArrangerKind ("CardArranger");
      // if (enyo.Panels.isScreenNarrow()) {
      this.$.samplePanels.setIndex(0);
    },
    rendered: function() {
      this.inherited(arguments);
    },
    openPage: function(idx) {
      var str, sp = this.$.samplePanels;
      eval ("var x = this.$.page"+idx);
  
// TODO. simplify
      switch (idx) {
	case "Disassembler": idx = 1; break;
	case "Assembler": idx = 2; break;
	case "Hexdump": idx = 3; break;
	case "Console": idx = 4; break;
	case "Settings": idx = 4; break;
	case "About": idx = 5; break;
      }
      //x.setContent (str);
      sp.setIndex (idx-2);
    },
    gotoPanel: function() {
      this.openPage (this.$.input.getValue());
/*
      var sp = this.$.samplePanels;
      //sp.components[3].setContent ("JAJAJ");
this.$.page3.setContent ("PUTA");
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

/*
    { tag: "h2", content: "Menu", style: "margin-left:12px" },
    { layoutKind: "FittableRowsLayout", components: [
      { kind: "onyx.Toolbar", title:"jaja", components: [
*/
enyo.kind({
  name: "RightPanel",
  classes: "onyx onyx-toolbar",
  kind: enyo.Control,
  style: "width:25px",
  components: [
    {kind: "onyx.MenuDecorator", onSelect: "itemSelected", components: [
      {content: "List elements"},
      {kind: "onyx.Menu", components: [
        {content: "symbols", value: "1"},
        {content: "imports", value: "1"},
        {content: "functions", value: "1"},
        {content: "comments", value: "1"},
        {content: "registers", value: "1"},
        {content: "stack", value: "2"},
        {content: "backtrace", value: "3"},
        {classes: "onyx-menu-divider"},
        {content: "settings", value: "4"},
      ]}
    ]},
  ]
});

enyo.kind({
  name: "LeftPanel",
  classes: "onyx-toolbar",
  kind: "Scroller", //enyo.Control,
  fit:true,
  style: "width: 220px;height:100%",
  components: [
    {tag: "h2", content: "crackme01", style: "margin-left:12px; margin-top:0px;margin-bottom:50px;height:10px;width:190px,overflow:hidden" },
     {kind: "Group", onActivate:"buttonActivated", classes: "enyo-border-box group", defaultKind: "onyx.Button", highlander: true, components: [
       {content: "Disassembler", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Disassembler", active: true},
       {content: "Assembler", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Assembler" },
       {content: "Hexdump", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Hexdump" },
       {content: "Console", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Console" },
       {content: "Settings", classes: "onyx-dark menu-button", ontap:"openPanel", name: "Settings" },
       {content: "About", classes: "onyx-dark menu-button" , ontap: "openPanel", name:"About"},
     ]}
  ],
  openPanel: function (x) {
    if (enyo.Panels.isScreenNarrow())
      this.ra.setIndex (1);
    if (this.openCallback)
      this.openCallback (x.name);
  },
  ra: null,
  oldSender: null,
  rowTap: function (inSender, inIndex) {
    if (this.oldSender)
      this.oldSender.setStyle ("width:100%"); // background of row
// TODO. use applystall
    //this.$.list.render ();
    inSender.setStyle ("background-color: #202020;width:100%"); // background of row
    this.oldSender = inSender;
    if (this.openCallback)
      this.openCallback (inIndex.index); //this.data[inIndex.index]);
  },
  openCallback: undefined,
  data: [],
  iter: 1,
  refresh: function () {
    this.iter++;
/*
    this.$.list.setCount (this.data.length);
    this.$.list.refresh ();
*/
  },
});

enyo.kind ({
  name: "RadareApp",
  kind: "Panels",
  classes: "panels enyo-unselectable",
  realtimeFit: true,
  arrangerKind: "CollapsingArranger",
  components: [ 
    { name: "lp", kind: "LeftPanel" },
    { name: "mp", kind: "MainPanel" },
    { name: "rp", kind: "RightPanel" }
  ],
  setPanel0: function () {
    this.$.RadareApp.setIndex (1);
  },
  create: function() {
      this.inherited (arguments);
      var mp = this.$.mp;
      var ra = this.$.RadareApp;
      this.$.lp.openCallback = function (idx) {
        mp.openPage (idx);
      };
      this.$.lp.ra = this;
      var data = [
        { name: "Disassembler", active: true },
        { name: "Assembler" },
        { name: "Hexdump" },
        { name: "Console" },
        { name: "Settings", separator: true },
        { name: "About" }
      ];
      this.$.lp.data = data;
      this.$.mp.data = data;
      this.$.lp.refresh ();
  }
});

window.onload = function() {
  var obj = new RadareApp ().renderInto (document.body)
}
