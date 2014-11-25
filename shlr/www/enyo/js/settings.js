enyo.kind ({
  name: "Settings",
  classes: "panels-sample-sliding-content r2panel",
  kind: "Scroller",
  tag: "div",
  data: null,
  style:"background-color:#c0c0c0; color:black !important;padding:0px;margin:0px;border:0px;overflow:hidden",
  components: [
    {kind: "FittableRows", fit: false, components: [
      {tag: "h2", content: "General" },
      {kind: "onyx.InputDecorator", components: [
        {tag: "p", content: "Two panels", classes:"rowline" },
        {kind: "onyx.ToggleButton", name: "twopanels"},
      ]},
      {kind: "onyx.InputDecorator", components: [
        {tag: "p", content: "Edit keybindings", classes:"rowline" },
        {kind: "onyx.Button", content: '+'},
      ]}
    ]},
    {kind: "FittableRows", fit: false, components: [
      {tag: "h2", content: "Target" }
      ,{kind: "onyx.InputDecorator", components: [
         {tag: "p", content: "Arch", classes:"rowline"},
         {kind: "onyx.PickerDecorator", components: [
           {},
           {kind: "onyx.Picker", name: "arch", components: [
/* TODO: construct from code */
             {content: "arc"},
             {content: "arm"},
             {content: "avr"},
             {content: "ppc"},
             {content: "bf"},
             {content: "dalvik"},
             {content: "dcpu16"},
             {content: "i8080"},
             {content: "java"},
             {content: "m68k"},
             {content: "mips"},
             {content: "msil"},
             {content: "rar"},
             {content: "sh"},
             {content: "sparc"},
             {content: "x86", active: true},
             {content: "z80"},
           ]}
         ]}
      ]}
      ,{kind: "onyx.InputDecorator", components: [
         {tag: "p", content: "Bits", classes:"rowline"},
         {kind: "onyx.PickerDecorator", components: [
           {},
           {kind: "onyx.Picker", name: "bits", components: [
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
      ,{kind: "onyx.InputDecorator", components: [
         {tag: "p", content: "OS", classes:"rowline"},
         {kind: "onyx.PickerDecorator", components: [
           {},
           {kind: "onyx.Picker", components: [
             {content: "linux", active: true},
             {content: "darwin"},
             {content: "w32"},
             {content: "dos"},
           ]}
         ]}
      ]}
      ,{tag: "h2", content: "Disassembly" },
      {kind: "onyx.InputDecorator", components: [
        {tag: "p", content: "Show new view", classes:"rowline", ontap: "nextPanel"},
        {kind: "onyx.ToggleButton", name: "use_new_view"},
      ]},
      {kind: "onyx.InputDecorator", components: [
        {tag: "p", content: "Show bytes", classes:"rowline", ontap: "nextPanel"},
        {kind: "onyx.ToggleButton", name: "toggle_bytes"},
      ]}
      ,{kind: "onyx.InputDecorator",components: [
        {tag: "p", content: "Show offsets", classes:"rowline", ontap: "nextPanel"},
        {kind: "onyx.ToggleButton", name: "toggle_offset" },
      ]}
      ,{kind: "onyx.InputDecorator",components: [
        {tag: "p", content: "Show flags", classes:"rowline", ontap: "nextPanel"},
        {kind: "onyx.ToggleButton", name: "toggle_flags" },
      ]}
      ,{kind: "onyx.InputDecorator",components: [
        {tag: "p", content: "Show xrefs", classes:"rowline", ontap: "nextPanel"},
        {kind: "onyx.ToggleButton", name: "toggle_xrefs" },
      ]}
      ,{kind: "onyx.InputDecorator",components: [
        {tag: "p", content: "Show comments on right", classes:"rowline", ontap: "nextPanel"},
        {kind: "onyx.ToggleButton", name: "toggle_cmtright" },
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
      {ontap:"reset", kind: "onyx.Button", style: "position:relative;left:0px", content: "Reset"},
      {ontap:"save", kind: "onyx.Button", style: "position:relative;left:50px", content: "Save", classes: "onyx-affirmative"}
    ]}
    ,{tag: "div", style: "height:64px"}
  ],
  load: function() {
    var self = this;
    self.$.twopanels.setActive (document.referrer.indexOf ("/two") != -1);
    self.$.toggle_bytes.setActive(r2.settings['asm.bytes']);
    self.$.toggle_pseudo.setActive(r2.settings['asm.pseudo']);
    self.$.toggle_flags.setActive(r2.settings['asm.flags']);
    self.$.toggle_xrefs.setActive(r2.settings['asm.xrefs']);
    self.$.toggle_cmtright.setActive(r2.settings['asm.cmtright']);
    self.$.toggle_offset.setActive(r2.settings['asm.offset']);
    self.$.toggle_lines.setActive(r2.settings['asm.lines']);
    var mode = readCookie('r2_view_mode');
    if (!mode) mode = "old";
    self.$.use_new_view.setActive(mode == "new");
  },

  create: function () {
    this.inherited (arguments);
    this.load();
  },
  save: function() {
    var use_new_view = this.$.use_new_view.active;
    var show_offset = this.$.toggle_offset.active;
    var arch = this.$.arch.selected.content;
    var bits = this.$.bits.selected.content;
    var show_bytes = this.$.toggle_bytes.active;
    var show_pseudo = this.$.toggle_pseudo.active;
    var show_flags = this.$.toggle_flags.active;
    var show_lines = this.$.toggle_lines.active;
    var show_xrefs = this.$.toggle_xrefs.active;
    var comments_on_right = this.$.toggle_cmtright.active;
    var twopanels = this.$.twopanels.active;
    r2.cmds ([
      "e asm.offset="+show_offset,
      "e asm.arch="+arch,
      "e asm.bits="+bits,
      "e asm.lines="+show_lines,
      "e asm.bytes="+show_bytes,
      "e asm.flags="+show_flags,
      "e asm.xrefs="+show_xrefs,
      "e asm.cmtright="+comments_on_right,
      "e asm.pseudo="+show_pseudo
    ]);
    r2.settings = {
      "use_new_view": use_new_view,
      "asm.arch":arch,
      "asm.bits":bits,
      "asm.bytes":show_bytes,
      "asm.flags":show_flags,
      "asm.xrefs":show_xrefs,
      "asm.cmtright":comments_on_right,
      "asm.lines":show_lines,
      "asm.pseudo":show_pseudo
    }

    if (use_new_view) createCookie('r2_view_mode', "new", 7);
    else createCookie('r2_view_mode', "old", 7);

    if (twopanels) {
      window.parent.location ="/enyo/two";
    } else {
      window.parent.location ="/enyo/";
    }
    r2ui.seek("$$", false);
  },
  reset: function() {
    this.load ();
  }
});
