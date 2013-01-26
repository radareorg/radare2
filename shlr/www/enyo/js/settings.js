enyo.kind ({
  name: "Settings",
  classes: "panels-sample-sliding-content r2panel",
  kind: "Scroller",
  tag: "div",
  style:"padding-left:16px",
  components: [
    {kind: "FittableRows", fit: false, components: [
      {tag: "h2", content: "CPU" }
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
      {ontap:"reset", kind: "onyx.Button", style: "position:relative;left:0px", content: "Reset"},
      {ontap:"save", kind: "onyx.Button", style: "position:relative;left:50px", content: "Save", classes: "onyx-affirmative"}
    ]}
    ,{tag: "div", style: "height:64px"}
  ],
  save: function() {
    var arch = this.$.arch.selected.content;
    var bits = this.$.bits.selected.content;
    r2.cmds (["e asm.arch="+arch, "e asm.bits="+bits]);
    alert ("save");
  },
  reset: function() {
    r2.cmd ("e asm.arch", function (x) {
      alert ("arch = "+x);
    });
  }
});
