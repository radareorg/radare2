enyo.kind ({
  name: "Graph",
  kind: "Scroller",
  style: "background-color:#c0c0c0",
  components: [
    {tag: "h2", content: "Open graph", style:"margin-left:10px;"},
    {kind: "Group", classes: "enyo-border-box group", defaultKind: "onyx.Button", components: [
      {content: "Basic blocks", classes: "onyx-dark menu-button", ontap:"openGraphBB" },
      {content: "Callgraph", classes: "onyx-dark menu-button", ontap:"openGraphCG" }
    ]}
  ],
  openGraphBB: function () {
    window.open ('/graph/', '_self');
  },
  openGraphCG: function () {
    window.open ('/d3/', '_self');
  }
});
