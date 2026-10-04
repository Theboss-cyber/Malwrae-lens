(function () {
    'use strict';

    var GRAPH_DATA = window.GRAPH_DATA;
    var svgEl = document.getElementById('graphSvg');
    if (!svgEl || !GRAPH_DATA || !GRAPH_DATA.nodes || GRAPH_DATA.nodes.length === 0) {
        if (svgEl) {
            svgEl.innerHTML = '<text x="450" y="240" text-anchor="middle" fill="#8a8a8a">No relationships to visualize</text>';
        }
        return;
    }

    var W = 900;
    var H = 480;
    var nodes = GRAPH_DATA.nodes.map(function (n) { return { id: n.id, label: n.label, kind: n.kind, severity: n.severity, detail: n.detail || '' }; });
    var edges = GRAPH_DATA.edges.map(function (e) { return { source: e.source, target: e.target }; });
    var nodeMap = {};
    nodes.forEach(function (n) { nodeMap[n.id] = n; });

    var colors = {
        file: '#0f3460',
        url: '#2980b9',
        ip: '#e74c3c',
        api: '#e67e22',
        pattern: '#8e44ad',
        permission: '#16a085',
        command: '#f39c12',
        dll: '#c0392b',
        magic: '#7f8c8d',
        dflt: '#95a5a6'
    };

    var severityColors = { critical: '#9d0208', high: '#e74c3c', medium: '#e67e22', low: '#25a244', info: '#3498db' };

    function nodeColor(n) {
        if (n.kind === 'file') return colors.file;
        if (severityColors[n.severity]) return severityColors[n.severity];
        return colors[n.kind] || colors.dflt;
    }

    function nodeRadius(n) {
        if (n.kind === 'file') return 22;
        if (n.kind === 'ip') return 12;
        return 9;
    }

    // Initial layout: radial around center
    nodes.forEach(function (n, i) {
        if (n.kind === 'file') { n.x = W / 2; n.y = H / 2; }
        else {
            var angle = (i / Math.max(nodes.length, 1)) * 2 * Math.PI;
            var r = 150 + (i % 3) * 60;
            n.x = W / 2 + r * Math.cos(angle);
            n.y = H / 2 + r * Math.sin(angle);
        }
        n.vx = 0; n.vy = 0;
    });

    var alpha = 1.0;
    var alphaMin = 0.02;
    var alphaDecay = 0.02;
    var velocityDecay = 0.5;
    var div2 = Math.pow(W / 2, 2) + Math.pow(H / 2, 2);

    function tick() {
        alpha *= (1 - alphaDecay);
        if (alpha < alphaMin) return false;

        // Repulsion between nodes
        for (var i = 0; i < nodes.length; i++) {
            for (var j = i + 1; j < nodes.length; j++) {
                var a = nodes[i], b = nodes[j];
                var dx = a.x - b.x, dy = a.y - b.y;
                var dist2 = dx * dx + dy * dy;
                if (dist2 < 1) { dx = (Math.random() - 0.5); dy = (Math.random() - 0.5); dist2 = 1; }
                var dist = Math.sqrt(dist2);
                var force = 2200 / dist2; // inverse-square repulsion
                var fx = dx / dist * force;
                var fy = dy / dist * force;
                a.vx += fx; a.vy += fy;
                b.vx -= fx; b.vy -= fy;
            }
        }

        // Spring attraction along edges
        for (var e = 0; e < edges.length; e++) {
            var sa = edges[e].source, ta = edges[e].target;
            if (!nodeMap[sa] || !nodeMap[ta]) continue;
            var s = nodeMap[sa], t = nodeMap[ta];
            var ex = t.x - s.x, ey = t.y - s.y;
            var edist = Math.max(Math.sqrt(ex * ex + ey * ey), 1);
            var targetLen = 110;
            var force = (edist - targetLen) / edist * 0.02 * alpha * 10;
            var efx = ex * force, efy = ey * force;
            s.vx += efx; s.vy += efy;
            t.vx -= efx; t.vy -= efy;
        }

        // Center gravity
        for (var k = 0; k < nodes.length; k++) {
            var n = nodes[k];
            n.vx += (W / 2 - n.x) * 0.001 * alpha;
            n.vy += (H / 2 - n.y) * 0.001 * alpha;
            n.x += n.vx;
            n.y += n.vy;
            n.x = Math.max(30, Math.min(W - 30, n.x));
            n.y = Math.max(30, Math.min(H - 30, n.y));
            n.vx *= velocityDecay;
            n.vy *= velocityDecay;
        }
        return true;
    }

    var ns = 'http://www.w3.org/2000/svg';
    function mk(tag, attrs) {
        var el = document.createElementNS(ns, tag);
        for (var k in attrs) el.setAttribute(k, attrs[k]);
        return el;
    }

    // Build SVG elements
    var edgeG = mk('g', {});
    var nodeG = mk('g', {});
    svgEl.appendChild(edgeG);
    svgEl.appendChild(nodeG);

    var edgeEls = edges.map(function (e) {
        var line = mk('line', {
            'stroke': '#3a3a5a', 'stroke-width': 1, 'opacity': 0.6
        });
        edgeG.appendChild(line);
        return line;
    });

    var nodeEls = nodes.map(function (n, idx) {
        var g = mk('g', { class: 'graph-node', 'data-idx': idx });
        var circle = mk('circle', {
            r: nodeRadius(n),
            fill: nodeColor(n),
            opacity: 0.9,
            'stroke': '#ffffff', 'stroke-width': n.kind === 'file' ? 2 : 1
        });
        var text = mk('text', {
            'text-anchor': 'middle',
            'dy': n.kind === 'file' ? 34 : 22,
            'fill': '#eaeaea', 'font-size': n.kind === 'file' ? 13 : 10,
            'font-family': 'Consolas, monospace'
        });
        var label = n.label;
        if (label.length > 22) label = label.slice(0, 20) + '...';
        text.textContent = label;
        g.appendChild(circle);
        g.appendChild(text);
        if (n.detail) {
            var title = mk('title', {});
            title.textContent = n.label + (n.detail ? '\n' + n.detail : '');
            g.appendChild(title);
        }
        nodeG.appendChild(g);
        return { g: g, circle: circle, text: text };
    });

    // Pan/zoom with wheel
    var viewScale = 1, viewTx = 0, viewTy = 0;
    var svgOuter = svgEl;

    function applyView() {
        svgOuter.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
        // We scale by adjusting globalAlpha-drawn elements via transform on groups
        edgeG.setAttribute('transform', 'translate(' + viewTx + ',' + viewTy + ') scale(' + viewScale + ')');
        nodeG.setAttribute('transform', 'translate(' + viewTx + ',' + viewTy + ') scale(' + viewScale + ')');
    }

    svgOuter.addEventListener('wheel', function (ev) {
        ev.preventDefault();
        var delta = ev.deltaY > 0 ? 0.9 : 1.1;
        viewScale = Math.max(0.3, Math.min(3, viewScale * delta));
        applyView();
    }, { passive: false });

    // Simple drag
    var dragging = null, dragOffset = null;
    svgOuter.addEventListener('mousedown', function (ev) {
        var target = ev.target;
        var g = target.closest ? target.closest('.graph-node') : null;
        if (!g) return;
        var idx = g.getAttribute('data-idx');
        dragging = nodes[idx];
        var pt = toLocal(ev);
        dragOffset = { x: dragging.x - pt.x, y: dragging.y - pt.y };
    });
    svgOuter.addEventListener('mousemove', function (ev) {
        if (!dragging) return;
        var pt = toLocal(ev);
        dragging.x = pt.x + dragOffset.x;
        dragging.y = pt.y + dragOffset.y;
        dragging.vx = dragging.vy = 0;
    });
    svgOuter.addEventListener('mouseup', function () { dragging = null; });

    function toLocal(ev) {
        var rect = svgOuter.getBoundingClientRect();
        var x = (ev.clientX - rect.left) / rect.width * W / viewScale - viewTx / viewScale;
        var y = (ev.clientY - rect.top) / rect.height * H / viewScale - viewTy / viewScale;
        return { x: x, y: y };
    }

    // Render loop
    function render() {
        for (var i = 0; i < nodes.length; i++) {
            var n = nodes[i];
            var el = nodeEls[i];
            el.g.setAttribute('transform', 'translate(' + n.x + ',' + n.y + ')');
        }
        for (var j = 0; j < edges.length; j++) {
            var s = nodeMap[edges[j].source], t = nodeMap[edges[j].target];
            if (!s || !t) continue;
            edgeEls[j].setAttribute('x1', s.x);
            edgeEls[j].setAttribute('y1', s.y);
            edgeEls[j].setAttribute('x2', t.x);
            edgeEls[j].setAttribute('y2', t.y);
        }
    }

    function loop() {
        var updated = tick();
        render();
        if (updated) requestAnimationFrame(loop);
    }
    loop();
})();