enyo.kind ({
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
