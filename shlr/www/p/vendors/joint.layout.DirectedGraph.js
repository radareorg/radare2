if (typeof exports === 'object') {

    var graphlib = require('graphlib');
    var dagre = require('dagre');
}

// In the browser, these variables are set to undefined because of JavaScript hoisting.
// In that case, should grab them from the window object.
graphlib = graphlib || (typeof window !== 'undefined' && window.graphlib);
dagre = dagre || (typeof window !== 'undefined' && window.dagre);

joint.layout.DirectedGraph = {

    layout: function(graphOrCells, opt) {

        var graph;

        if (graphOrCells instanceof joint.dia.Graph) {
            graph = graphOrCells;
        } else {
            graph = (new joint.dia.Graph()).resetCells(graphOrCells);
        }

        // This is not needed anymore.
        graphOrCells = null;

        opt = _.defaults(opt || {}, {
            resizeClusters: true,
            clusterPadding: 10
        });

        // create a graphlib.Graph that represents the joint.dia.Graph
        var glGraph = graph.toGraphLib({
            directed: true,
            // We are about to use edge naming feature.
            multigraph: true,
            // We are able to layout graphs with embeds.
            compound: true,
            setNodeLabel: function(element) {
                return {
                    width: element.get('size').width,
                    height: element.get('size').height,
                    rank: element.get('rank')
                };
            },
            setEdgeLabel: function(link) {
                return {
                    minLen: link.get('minLen') || 1
                };
            },
            setEdgeName: function(link) {
                // Graphlib edges have no ids. We use edge name property
                // to store and retrieve ids instead.
                return link.id;
            }
        });

        var glLabel = {};

        // Dagre layout accepts options as lower case.
        // Direction for rank nodes. Can be TB, BT, LR, or RL
        if (opt.rankDir) glLabel.rankdir = opt.rankDir;
        // Alignment for rank nodes. Can be UL, UR, DL, or DR
        if (opt.align) glLabel.align = opt.align;
        // Number of pixels that separate nodes horizontally in the layout.
        if (opt.nodeSep) glLabel.nodesep = opt.nodeSep;
        // Number of pixels that separate edges horizontally in the layout.
        if (opt.edgeSep) glLabel.edgesep = opt.edgeSep;
        // Number of pixels between each rank in the layout.
        if (opt.rankSep) glLabel.ranksep = opt.rankSep;
        // Number of pixels to use as a margin around the left and right of the graph.
        if (opt.marginX) glLabel.marginx = opt.marginX;
        // Number of pixels to use as a margin around the top and bottom of the graph.
        if (opt.marginY) glLabel.marginy = opt.marginY;

        // Set the option object for the graph label.
        glGraph.setGraph(glLabel);

        // Executes the layout.
        dagre.layout(glGraph, { debugTiming: !!opt.debugTiming });

        // Wrap all graph changes into a batch.
        graph.startBatch('layout');

        // Update the graph.
        graph.fromGraphLib(glGraph, {
            importNode: function(v, gl) {

                var element = this.getCell(v);
                var glNode = gl.node(v);

                if (opt.setPosition) {
                    opt.setPosition(element, glNode);
                } else {
                    element.set('position', {
                        x: glNode.x - glNode.width / 2,
                        y: glNode.y - glNode.height / 2
                    });
                }
            },
            importEdge: function(edgeObj, gl) {

                var link = this.getCell(edgeObj.name);
                var glEdge = gl.edge(edgeObj);
                var points = glEdge.points || [];

                if (opt.setLinkVertices) {
                    if (opt.setVertices) {
                        opt.setVertices(link, points);
                    } else {
                        // Remove the first and last point from points array.
                        // Those are source/target element connection points
                        // ie. they lies on the edge of connected elements.
                        link.set('vertices', points.slice(1, points.length - 1));
                    }
                }
            }
        });

        if (opt.resizeClusters) {
            // Resize and reposition cluster elements (parents of other elements)
            // to fit their children.
            // 1. filter clusters only
            // 2. map id on cells
            // 3. sort cells by their depth (the deepest first)
            // 4. resize cell to fit their direct children only.
            _.chain(glGraph.nodes())
                .filter(function(v) { return glGraph.children(v).length > 0; })
                .map(graph.getCell, graph)
                .sortBy(function(cluster) { return -cluster.getAncestors().length; })
                .invoke('fitEmbeds', { padding: opt.clusterPadding })
                .value();
        }

        graph.stopBatch('layout');

        // Return an object with height and width of the graph.
        return glGraph.graph();
    },

    fromGraphLib: function(glGraph, opt) {

        opt = opt || {};

        var importNode = opt.importNode || _.noop;
        var importEdge = opt.importEdge || _.noop;
        var graph = this instanceof joint.dia.Graph ? this : new joint.dia.Graph;

        // Import all nodes.
        glGraph.nodes().forEach(function(node) {
            importNode.call(graph, node, glGraph, graph, opt);
        });

        // Import all edges.
        glGraph.edges().forEach(function(edge) {
            importEdge.call(graph, edge, glGraph, graph, opt);
        });

        return graph;
    },

    // Create new graphlib graph from existing JointJS graph.
    toGraphLib: function(graph, opt) {

        opt = opt || {};

        var glGraphType = _.pick(opt, 'directed', 'compound', 'multigraph');
        var glGraph = new graphlib.Graph(glGraphType);
        var setNodeLabel = opt.setNodeLabel || _.noop;
        var setEdgeLabel = opt.setEdgeLabel || _.noop;
        var setEdgeName = opt.setEdgeName || _.noop;

        graph.get('cells').each(function(cell) {

            if (cell.isLink()) {

                var source = cell.get('source');
                var target = cell.get('target');

                // Links that end at a point are ignored.
                if (!source.id || !target.id) return;

                // Note that if we are creating a multigraph we can name the edges. If
                // we try to name edges on a non-multigraph an exception is thrown.
                glGraph.setEdge(source.id, target.id, setEdgeLabel(cell), setEdgeName(cell));

            } else {

                glGraph.setNode(cell.id, setNodeLabel(cell));

                // For the compound graphs we have to take embeds into account.
                if (glGraph.isCompound() && cell.has('parent')) {
                    glGraph.setParent(cell.id, cell.get('parent'));
                }
            }
        });

        return glGraph;
    }
};

joint.dia.Graph.prototype.toGraphLib = function(opt) {

    return joint.layout.DirectedGraph.toGraphLib(this, opt);
};

joint.dia.Graph.prototype.fromGraphLib = function(glGraph, opt) {

    return joint.layout.DirectedGraph.fromGraphLib.call(this, glGraph, opt);
};
