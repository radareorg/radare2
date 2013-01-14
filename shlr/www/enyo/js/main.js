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
       //this.$.samplePanels.setArrangerKind ("CardArranger");
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
	case "Disassembler": idx = 0; break;
	case "Assembler": idx = 1; break;
	case "Hexdump": idx = 2; break;
	case "Console": idx = 3; break;
	case "Settings": idx = 4; break;
	case "About": idx = 5; break;
      }
      //x.setContent (str);
      sp.setIndex (idx);
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
