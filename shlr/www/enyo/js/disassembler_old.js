function docss(x) {
  return '<font color=black>'+x+'</font>';
}

enyo.kind ({
  name: "DisassemblerOld",
  kind: "Scroller",
  tag: "div",
  style:"margin:0px;background-color:#c0c0c0",
  data: null,
  components: [
    {tag: "div", allowHtml: true, classes: "colorbar", name: "colorbar" },
    {tag: "br" },
    {tag: "div", content: "^", classes: "moreless", ontap: "less"},
    {tag: "pre", allowHtml: true, name: "text", content: "..", style:"margin-left:5px"},
    {tag: "div", content: "v", classes: "moreless", ontap: "more"},
  ],
  min: 0,
  max: 0,
  block: 512,
  base: "entry0",
  less: function() {
    var self = this;
    var text = this.$.text;
    this.min += this.block;
    r2.get_disasm (this.base+"-"+this.min, this.block, function (x) {
      x = docss (r2.filter_asm (x, "pd"));
      var oldy = r2ui._dis.getScrollBounds().height;
      text.setContent ("<div class='enyo-selectable'>" + x + text.getContent() + "</div>");
      var newy = r2ui._dis.getScrollBounds().height;
      r2ui._dis.scrollTo (0, newy-oldy);
    });
  },
  more: function() {
    var text = this.$.text;
    this.max += this.block;
    r2.get_disasm (this.base+"+"+this.max, this.block, function (x) {
      x = docss (r2.filter_asm (x, "pd"));
      text.setContent ("<div class='enyo-selectable'>" + text.getContent() + x + "</div>");
    });
  },
  seek: function(addr) {
    var text = this.$.text;
    this.base = addr;
    this.min = this.max = 0;
    r2.get_disasm (addr, this.block, function (x) {
      x = docss (r2.filter_asm (x, "pd"));
      text.setContent("<div class='enyo-selectable'>" + x + "</div>");
    });
    this.scrollTo (0, 0);
    //this.colorbar_create ();
  },
  create: function() {
    this.inherited (arguments);
 //   this.$.list.setCount (this.data.length) ;
    var text = this.$.text;
    r2.cmd("e asm.lineswidth = 20", function(x){});
    this.seek ("entry0");
    r2ui._dis = this;
    r2ui.history_push ("entry0");

    //this.colorbar_create ();
    //this.refresh ();
  },
  colorbar_create: function () {
    var self = this;
    r2.cmd ("pvj 24", function(x) {
      try {
        var y = JSON.parse (x);
      } catch (e) {
        alert (e);
        return;
      }
      console.log (y);

// TODO: use canvas api for faster rendering and smaller dom
      var c = "<table class='colorbar'>"+
          "<tr valign=top style='height:8px;border-spacing:0'>";
      var colors = {
        flags: "#c0c0c0",
        comments: "yellow",
        functions: "#5050f0",
        strings: "orange",
      };
      var off = "";
      var WIDTH = '100%';
      var HEIGHT = 16;
      for (var i=0; i< y.blocks.length; i++) {
        var block = y.blocks[i];
        var r = "<div style='overflow:hidden;width:12px;'>____</div>";
        if (block.offset) {  // Object.keys(block).length>1) {
          var r = "<table width='width:100%' height="+HEIGHT+" style='border-spacing:0px'>";
          var count = 0;
          for (var k in colors)
            if (block[k])
              count++;
	  count++; // avoid 0div wtf
	  if (count==1) break;
          var h = HEIGHT / count;
          for (var k in colors) {
            var color = colors[k];
            if (block[k])
              r += "<tr><td class='colorbar_item' style='background-color:"
                  + colors[k]+"'><div style='width:12px;overflow:"
                  + "hidden;height:"+h+"px'>____</div></td></tr>";
          }
          r += "</table>";
          off = "0x"+block.offset.toString (16);
        } else {
          off = "0x"+(y.from + (y.blocksize * i)).toString (16);
        }
        c += "<td onclick='r2ui.seek("+off+",true)' title='"+off
              + "' style='height:"+HEIGHT+"px' "
	      + "width=15px>"+r+"</td>";
      }
      c += "</tr></table>";
      self.$.colorbar.setContent (c);
    });
  }
});
