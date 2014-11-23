function docss(x) {
  return '<font color=black>'+x+'</font>';
}

enyo.kind ({
  name: "Hexdump",
  kind: "Scroller",
  tag: "div",
  style:"margin:0px;background-color:#c0c0c0;color:black",
  data: null,
  components: [
    {tag: "div", allowHtml: true, classes: "colorbar", name: "colorbar" },
    {tag: "div", content: "^", classes: "moreless", ontap: "less"},
    {tag: "pre", allowHtml: true, name: "text", content: "..", style:"margin-left:5px;color:black"},
    {tag: "div", content: "v", classes: "moreless", ontap: "more"},
/*
    {kind: "List", count:3, name: "list", style:"height:400px", realtimeFit:false, onSetupItem: "setupItem", components: [
      {kind: "onyx.Item", layoutKind: "HFlexLayout", style:"padding:0px", components: [
        {kind: "onyx.Button", name: "msg", fit:true, active: true, ontap: "rowTap"}
      ]}
    ]}
*/
  ],
  min: 0,
  max: 0,
  block: 1024,
  base: "entry0",
  less: function() {
    var self = this;
    var text = this.$.text;
    this.min += this.block;
    r2.get_hexdump (this.base+"-"+this.min, this.block, function (x) {
      x = css (r2.filter_asm (x, "px"));
      var oldy = r2ui._hex.getScrollBounds().height;
      text.setContent ("<div class='enyo-selectable'>" + x + text.getContent() + "</div>");
      var newy = r2ui._hex.getScrollBounds().height;
      r2ui._hex.scrollTo (0, newy-oldy);
    });
  },
  more: function() {
    var text = this.$.text;
    this.max += this.block;
    r2.get_hexdump (this.base+"+"+this.max, this.block, function (x) {
      x = docss (r2.filter_asm (x, "px"));
      text.setContent ("<div class='enyo-selectable'>" + text.getContent() + x + "</div>");
    });
  },
  seek: function(addr) {
    var text = this.$.text;
    this.base = addr;
    this.min = this.max = 0;
    r2.get_hexdump (addr, this.block, function (x) {
      x = docss (r2.filter_asm (x, "px"));
      text.setContent ("<div class='enyo-selectable'>" + x + "</div>");
    });
    this.colorbar_create ();
  },
  create: function() {
    this.inherited (arguments);
    // this.$.list.setCount (this.data.length) ;
    var text = this.$.text;
    this.seek ("entry0");
    r2ui._hex = this;
    // r2ui.history_push("entry0");

    this.colorbar_create();
    //this.refresh ();
  },
  setupItem: function (inSender, inIndex) {
      this.$.msg.setContent (this.data[inIndex.index]);
      return true;
  },
/* TODO: spaggety. see disassemble.js . must be a separate kind */
  colorbar_create: function () {
    var self = this;
    r2.cmd ("pvj", function(x) {
      try {
        var y = JSON.parse (x);
      } catch (e) {
        alert (e);
        return;
      }
      // console.log (y);

// TODO: use canvas api for faster rendering and smaller dom
      var c = "<table class='colorbar'><tr valign=top style='height:20px;border-spacing:0'>";
      var colors = {
       flags: "#c0c0c0",
       comments: "yellow",
       functions: "#5050f0",
       strings: "orange",
      };

      var off = "";
      var WIDTH = 10;
      var HEIGHT = 30;
      for (var i=0; i< y.blocks.length; i++) {
        var block = y.blocks[i];
        var r = "<div style='overflow:hidden;background-color:#404040;width:"
              + WIDTH+"px;'>&nbsp;</div>";
        if (block.offset) {  // Object.keys(block).length>1) {
          var r = "<table height="+HEIGHT+" style='color:black;border-spacing:0px'>";
          var count = 0;
          for (var k in colors) {
            if (block[k])
              count++;
          }
	  count++; // avoid 0div wtf
	  if (count==1) break;
          var h = HEIGHT / count;
          for (var k in colors) {
            var color = colors[k];
            if (block[k])
              r += "<tr><td style='width:"+WIDTH+"px;background-color:"
                  + colors[k]+"'><div style='width:"+WIDTH+"px;overflow:"
                  + "hidden;height:"+h+"px'>&nbsp;</div></td></tr>";
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
