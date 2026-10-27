"""交互依赖图谱：首次力导向布局，之后缓存坐标，滑杆只切换显示。"""
import hashlib
import json
from pathlib import Path

import networkx as nx


def build_graph_html(graph_path: str) -> str:
    graph = nx.read_graphml(graph_path)
    ranked = sorted(
        graph.nodes(data=True),
        key=lambda item: (
            0 if item[1].get("source_code") else 1,
            -graph.degree(item[0]),
        ),
    )
    rank_by_id = {str(node_id): rank for rank, (node_id, _) in enumerate(ranked)}
    nodes = []
    for rank, (node_id, attrs) in enumerate(ranked):
        desc = str(attrs.get("desc") or "")
        if len(desc) > 180:
            desc = desc[:180] + "..."
        node_key = str(node_id)
        nodes.append({
            "id": node_key,
            "label": attrs.get("source_name") or node_key,
            "title": (
                f"文件: {attrs.get('name', '')}<br>"
                f"路径: {attrs.get('path', '')}<br>"
                f"描述: {desc}<br>"
                f"行号: {attrs.get('start_code_line', '')}-{attrs.get('end_code_line', '')}"
            ),
            "group": attrs.get("name", "default"),
            "shape": "dot",
            "size": 16 if attrs.get("source_code") else 9,
            "rank": rank,
        })
    node_ids = {node["id"] for node in nodes}
    edges = []
    for index, (source, target) in enumerate(graph.edges()):
        source_id, target_id = str(source), str(target)
        if source_id in node_ids and target_id in node_ids:
            edges.append({
                "id": f"e{index}",
                "from": source_id,
                "to": target_id,
                "arrows": "to",
                "rank": max(rank_by_id.get(source_id, 0), rank_by_id.get(target_id, 0)),
            })
    graph_id = hashlib.sha1(str(Path(graph_path).resolve()).encode("utf-8")).hexdigest()[:16]
    iterations = 80 if len(nodes) > 1200 else 180
    payload = json.dumps({"nodes": nodes, "edges": edges}, ensure_ascii=False).replace("<", "\\u003c")
    return f"""
    <div style="display:flex;align-items:center;gap:12px;padding:8px 12px;color:#475569;font-family:Microsoft YaHei;">
      <label for="draw-range" style="white-space:nowrap;">绘制范围</label>
      <input id="draw-range" type="range" min="10" max="100" step="5" value="30" style="flex:1;">
      <strong id="draw-pct" style="min-width:48px;">30%</strong>
      <span id="graph-status">图谱加载中...</span>
    </div>
    <div id="graph" style="width:100%;height:740px;border-radius:18px;border:1px solid #e6e8ef;background:linear-gradient(180deg,#fbfbfd 0%,#f4f6fb 100%);"></div>
    <script src="https://cdn.jsdelivr.net/npm/vis-network@9.1.2/dist/vis-network.min.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/vis-network@9.1.2/dist/dist/vis-network.min.css"/>
    <script>
      const DATA = {payload};
      const GRAPH_ID = "{graph_id}";
      const status = document.getElementById("graph-status");
      const slider = document.getElementById("draw-range");
      const pctLabel = document.getElementById("draw-pct");
      const total = DATA.nodes.length;
      let network = null;
      let nodesDS = null;
      let edgesDS = null;
      let shown = 0;
      let started = false;
      let saved = null;
      try {{ saved = JSON.parse(localStorage.getItem("aica-graph-pos:" + GRAPH_ID) || "null"); }} catch (e) {{}}

      const limitFor = (percent) => Math.max(1, Math.round(total * percent / 100));
      const statusText = (percent, limit, extra) => {{
        return "当前 " + percent + "%，" + limit + " / " + total + " 个节点。" + (extra || "");
      }};

      const applyRange = (percent) => {{
        const limit = Math.min(total, limitFor(percent));
        pctLabel.textContent = percent + "%";
        if (!nodesDS) {{
          DATA.nodes.forEach((node) => {{ node.hidden = node.rank >= limit; }});
          DATA.edges.forEach((edge) => {{ edge.hidden = edge.rank >= limit; }});
          shown = limit;
          return;
        }}
        if (limit === shown) return;
        const start = Math.min(shown, limit);
        const end = Math.max(shown, limit);
        const hide = limit < shown;
        const nodeUpdates = [];
        for (let i = start; i < end; i++) nodeUpdates.push({{ id: DATA.nodes[i].id, hidden: hide }});
        const edgeUpdates = [];
        DATA.edges.forEach((edge) => {{
          if (edge.rank >= start && edge.rank < end) edgeUpdates.push({{ id: edge.id, hidden: hide }});
        }});
        if (nodeUpdates.length) nodesDS.update(nodeUpdates);
        if (edgeUpdates.length) edgesDS.update(edgeUpdates);
        shown = limit;
        status.innerText = statusText(percent, limit, saved ? "已使用缓存布局，拖动只切换显示。" : "布局已缓存，拖动只切换显示。");
      }};

      const freeze = () => {{
        network.storePositions();
        const map = {{}};
        nodesDS.get().forEach((node) => {{ map[node.id] = [Math.round(node.x), Math.round(node.y)]; }});
        try {{ localStorage.setItem("aica-graph-pos:" + GRAPH_ID, JSON.stringify(map)); }} catch (e) {{}}
        saved = map;
        nodesDS.getIds().forEach((id) => nodesDS.update({{ id, fixed: {{ x: true, y: true }} }}));
        network.setOptions({{ physics: {{ enabled: false }} }});
      }};

      const renderGraph = () => {{
        if (typeof vis === "undefined") {{
          status.innerText = "图谱脚本加载失败。";
          return;
        }}
        if (started) return;
        started = true;
        if (saved) {{
          DATA.nodes.forEach((node) => {{
            const pos = saved[node.id];
            if (!pos) return;
            node.x = pos[0];
            node.y = pos[1];
            node.fixed = {{ x: true, y: true }};
          }});
        }}
        applyRange(saved ? 30 : 100);
        nodesDS = new vis.DataSet(DATA.nodes);
        edgesDS = new vis.DataSet(DATA.edges);
        network = new vis.Network(document.getElementById("graph"), {{ nodes: nodesDS, edges: edgesDS }}, {{
          autoResize: true,
          interaction: {{ hover: true, navigationButtons: true, keyboard: true }},
          physics: {{
            enabled: !saved,
            solver: "forceAtlas2Based",
            forceAtlas2Based: {{
              gravitationalConstant: -70,
              centralGravity: 0.01,
              springLength: 140,
              springConstant: 0.04,
              avoidOverlap: 0.5
            }},
            stabilization: {{ iterations: {iterations} }}
          }},
          layout: {{ improvedLayout: false }},
          nodes: {{
            borderWidth: 1,
            font: {{ color: "#1f2a44", size: 13, face: "Microsoft YaHei" }}
          }},
          edges: {{
            color: {{ color: "#94a3b8", highlight: "#f97316" }},
            smooth: {{ type: "dynamic" }}
          }}
        }});
        if (saved) {{
          network.fit({{ animation: false }});
          status.innerText = statusText(30, shown, "已使用缓存布局，拖动只切换显示。");
        }} else {{
          status.innerText = "首次计算布局，完成后会缓存。这一次会稍慢。";
          network.once("stabilizationIterationsDone", () => {{
            freeze();
            applyRange(30);
            network.fit({{ animation: false }});
            status.innerText = statusText(30, shown, "布局已缓存，之后拖动只切换显示。");
          }});
        }}
        slider.addEventListener("input", () => {{
          pctLabel.textContent = slider.value + "%";
          applyRange(Number(slider.value));
        }});
      }};
      window.addEventListener("load", renderGraph);
      setTimeout(renderGraph, 300);
    </script>
    """


def cached_graph_html(graph_path: str) -> Path:
    source = Path(graph_path)
    html_path = source.parent / "_graph_preview_atlas.html"
    if html_path.exists() and html_path.stat().st_mtime >= source.stat().st_mtime:
        return html_path
    html_path.write_text(build_graph_html(graph_path), encoding="utf-8")
    return html_path

