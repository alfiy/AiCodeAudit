"""交互依赖图谱：全局布局缓存，点击节点进入直接相连的局部视图。"""
import hashlib
import json
import math
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
      <button id="back-global" type="button" style="display:none;border:1px solid #d0d5dd;background:#fff;border-radius:8px;padding:4px 10px;cursor:pointer;">返回全局</button>
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
      const backBtn = document.getElementById("back-global");
      const total = DATA.nodes.length;
      const nodeById = Object.fromEntries(DATA.nodes.map((node) => [node.id, node]));
      const neighbors = {{}};
      DATA.edges.forEach((edge) => {{
        (neighbors[edge.from] ||= []).push(edge.to);
        (neighbors[edge.to] ||= []).push(edge.from);
      }});
      let network = null;
      let nodesDS = null;
      let edgesDS = null;
      let shown = 0;
      let started = false;
      let ready = false;
      let focusId = null;
      let globalPos = null;
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
        if (!focusId) status.innerText = statusText(percent, limit, saved ? "已使用缓存布局。点击节点可查看直接相连。" : "布局已缓存。点击节点可查看直接相连。");
      }};

      const focusNode = (nodeId) => {{
        if (!ready || !nodesDS) return;
        const related = [...new Set(neighbors[nodeId] || [])];
        const keep = new Set([nodeId, ...related]);
        focusId = nodeId;
        if (!globalPos) {{
          globalPos = {{}};
          nodesDS.get().forEach((node) => {{ globalPos[node.id] = [node.x, node.y]; }});
        }}
        const radius = Math.max(220, 70 + related.length * 16);
        const nodeUpdates = DATA.nodes.map((node) => {{
          if (node.id === nodeId) {{
            return {{
              id: node.id,
              label: node.label,
              hidden: false,
              x: 0,
              y: 0,
              fixed: false,
              size: 24,
              font: {{ size: 16, color: "#1f2a44", face: "Microsoft YaHei", strokeWidth: 3, strokeColor: "#ffffff", vadjust: 8 }},
            }};
          }}
          if (!keep.has(node.id)) return {{ id: node.id, hidden: true }};
          const index = related.indexOf(node.id);
          const angle = (Math.PI * 2 * index) / Math.max(related.length, 1);
          return {{
            id: node.id,
            label: node.label,
            hidden: false,
            x: Math.round(Math.cos(angle) * radius),
            y: Math.round(Math.sin(angle) * radius),
            fixed: false,
            font: {{ size: 14, color: "#1f2a44", face: "Microsoft YaHei", strokeWidth: 3, strokeColor: "#ffffff", vadjust: 6 }},
          }};
        }});
        nodesDS.update(nodeUpdates);
        edgesDS.update(DATA.edges.map((edge) => ({{
          id: edge.id,
          hidden: !(keep.has(edge.from) && keep.has(edge.to)),
          smooth: false,
        }})));
        nodeUpdates.forEach((node) => {{
          if (!node.hidden && node.x !== undefined) network.moveNode(node.id, node.x, node.y);
        }});
        network.setOptions({{
          physics: {{ enabled: false }},
          nodes: {{ scaling: {{ label: {{ enabled: false }} }} }},
          edges: {{ smooth: false }},
        }});
        backBtn.style.display = "inline-block";
        slider.disabled = true;
        network.fit({{ animation: {{ duration: 250 }} }});
        const label = nodeById[nodeId] ? nodeById[nodeId].label : nodeId;
        status.innerText = "局部视图：" + label + "，直接相连 " + related.length + " 个。可拖动，本次不保存。";
      }};

      const restoreGlobal = () => {{
        if (!nodesDS) return;
        focusId = null;
        const limit = Math.min(total, limitFor(Number(slider.value)));
        nodesDS.update(DATA.nodes.map((node) => {{
          const pos = (globalPos && globalPos[node.id]) || (saved && saved[node.id]);
          const item = {{
            id: node.id,
            hidden: node.rank >= limit,
            fixed: {{ x: true, y: true }},
            size: node.size,
            font: {{ size: 13, color: "#1f2a44" }},
          }};
          if (pos) {{
            item.x = pos[0];
            item.y = pos[1];
          }}
          return item;
        }}));
        edgesDS.update(DATA.edges.map((edge) => ({{ id: edge.id, hidden: edge.rank >= limit, smooth: {{ type: "dynamic" }} }})));
        shown = limit;
        globalPos = null;
        network.setOptions({{
          nodes: {{ scaling: {{ label: {{ enabled: true, min: 10, max: 16 }} }} }},
          edges: {{ smooth: {{ type: "dynamic" }} }},
        }});
        backBtn.style.display = "none";
        slider.disabled = false;
        network.fit({{ animation: false }});
        status.innerText = statusText(Number(slider.value), limit, "已返回全局。点击节点可查看直接相连。");
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
          ready = true;
          status.innerText = statusText(30, shown, "已使用缓存布局。点击节点可查看直接相连。");
        }} else {{
          status.innerText = "首次计算布局，完成后会缓存。这一次会稍慢。";
          network.once("stabilizationIterationsDone", () => {{
            freeze();
            applyRange(30);
            ready = true;
            network.fit({{ animation: false }});
            status.innerText = statusText(30, shown, "布局已缓存。点击节点可查看直接相连。");
          }});
        }}
        network.on("click", (params) => {{
          if (!ready || !params.nodes.length) return;
          focusNode(params.nodes[0]);
        }});
        backBtn.addEventListener("click", restoreGlobal);
        slider.addEventListener("input", () => {{
          if (focusId) return;
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
    html_path = source.parent / "_graph_preview_focus_v2.html"
    if html_path.exists() and html_path.stat().st_mtime >= source.stat().st_mtime:
        return html_path
    html_path.write_text(build_graph_html(graph_path), encoding="utf-8")
    return html_path


def _static_positions(graph: nx.DiGraph) -> dict[str, list[float]]:
    count = graph.number_of_nodes()
    if count == 0:
        return {}
    if count <= 400:
        raw = nx.spring_layout(graph, seed=42, k=1.6 / math.sqrt(count), iterations=40)
        return {
            str(node_id): [round(float(xy[0]) * 900, 1), round(float(xy[1]) * 900, 1)]
            for node_id, xy in raw.items()
        }
    groups: dict[str, list] = {}
    for node_id, attrs in graph.nodes(data=True):
        groups.setdefault(str(attrs.get("name") or "default"), []).append(node_id)
    keys = sorted(groups, key=lambda key: (-len(groups[key]), key))
    positions: dict[str, list[float]] = {}
    cols = max(1, math.ceil(math.sqrt(max(len(keys), 1))))
    for index, key in enumerate(keys):
        members = groups[key]
        cx = (index % cols) * 520
        cy = (index // cols) * 520
        radius = 50 + 18 * math.sqrt(max(len(members), 1))
        for member_index, node_id in enumerate(members):
            angle = 2 * math.pi * member_index / max(len(members), 1)
            positions[str(node_id)] = [
                round(cx + math.cos(angle) * radius, 1),
                round(cy + math.sin(angle) * radius, 1),
            ]
    return positions


def build_static_graph_html(graph_path: str) -> str:
    graph = nx.read_graphml(graph_path)
    ranked = sorted(
        graph.nodes(data=True),
        key=lambda item: (
            0 if item[1].get("source_code") else 1,
            -graph.degree(item[0]),
        ),
    )[:120]
    preview = graph.subgraph([node_id for node_id, _ in ranked]).copy()
    positions = _static_positions(preview)
    nodes = []
    for node_id, attrs in ranked:
        node_key = str(node_id)
        x, y = positions.get(node_key, [0, 0])
        desc = str(attrs.get("desc") or "")
        if len(desc) > 180:
            desc = desc[:180] + "..."
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
            "x": x,
            "y": y,
            "fixed": True,
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
                "smooth": False,
            })
    payload = json.dumps({"nodes": nodes, "edges": edges}, ensure_ascii=False).replace("<", "\\u003c")
    return f"""
    <div style="display:flex;align-items:center;gap:12px;padding:8px 12px;color:#475569;font-family:Microsoft YaHei;">
      <button id="back-global" type="button" style="display:none;border:1px solid #d0d5dd;background:#fff;border-radius:8px;padding:4px 10px;cursor:pointer;">返回全局</button>
      <span id="graph-status">静态预览：只显示前 120 个高优先级节点。可滚轮缩放，点击节点查看直接相连。</span>
    </div>
    <div id="graph" style="width:100%;height:740px;border-radius:18px;border:1px solid #e6e8ef;background:linear-gradient(180deg,#fbfbfd 0%,#f4f6fb 100%);"></div>
    <script src="https://cdn.jsdelivr.net/npm/vis-network@9.1.2/dist/vis-network.min.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/vis-network@9.1.2/dist/dist/vis-network.min.css"/>
    <script>
      const DATA = {payload};
      const status = document.getElementById("graph-status");
      const backBtn = document.getElementById("back-global");
      const nodeById = Object.fromEntries(DATA.nodes.map((node) => [node.id, node]));
      const neighbors = {{}};
      DATA.edges.forEach((edge) => {{
        (neighbors[edge.from] ||= []).push(edge.to);
        (neighbors[edge.to] ||= []).push(edge.from);
      }});
      let network = null;
      let nodesDS = null;
      let edgesDS = null;
      let focusId = null;
      let started = false;

      const focusNode = (nodeId) => {{
        const related = [...new Set(neighbors[nodeId] || [])];
        const keep = new Set([nodeId, ...related]);
        focusId = nodeId;
        const radius = Math.max(220, 70 + related.length * 16);
        const nodeUpdates = DATA.nodes.map((node) => {{
          if (node.id === nodeId) {{
            return {{
              id: node.id,
              label: node.label,
              hidden: false,
              x: 0,
              y: 0,
              fixed: false,
              size: 24,
              font: {{ size: 16, color: "#1f2a44", face: "Microsoft YaHei", strokeWidth: 3, strokeColor: "#ffffff" }},
            }};
          }}
          if (!keep.has(node.id)) return {{ id: node.id, hidden: true }};
          const index = related.indexOf(node.id);
          const angle = (Math.PI * 2 * index) / Math.max(related.length, 1);
          return {{
            id: node.id,
            label: node.label,
            hidden: false,
            x: Math.round(Math.cos(angle) * radius),
            y: Math.round(Math.sin(angle) * radius),
            fixed: false,
            font: {{ size: 14, color: "#1f2a44", face: "Microsoft YaHei", strokeWidth: 3, strokeColor: "#ffffff" }},
          }};
        }});
        nodesDS.update(nodeUpdates);
        edgesDS.update(DATA.edges.map((edge) => ({{
          id: edge.id,
          hidden: !(keep.has(edge.from) && keep.has(edge.to)),
          smooth: false,
        }})));
        nodeUpdates.forEach((node) => {{
          if (!node.hidden && node.x !== undefined) network.moveNode(node.id, node.x, node.y);
        }});
        backBtn.style.display = "inline-block";
        network.fit({{ animation: {{ duration: 250 }} }});
        const label = nodeById[nodeId] ? nodeById[nodeId].label : nodeId;
        status.innerText = "局部视图：" + label + "，直接相连 " + related.length + " 个。可缩放、拖动，返回全局后恢复。";
      }};

      const restoreGlobal = () => {{
        focusId = null;
        nodesDS.update(DATA.nodes.map((node) => ({{
          id: node.id,
          label: node.label,
          hidden: false,
          x: node.x,
          y: node.y,
          fixed: {{ x: true, y: true }},
          size: node.size,
          font: {{ size: 12, color: "#1f2a44", face: "Microsoft YaHei", strokeWidth: 2, strokeColor: "#ffffff" }},
        }})));
        edgesDS.update(DATA.edges.map((edge) => ({{ id: edge.id, hidden: false, smooth: false }})));
        DATA.nodes.forEach((node) => network.moveNode(node.id, node.x, node.y));
        backBtn.style.display = "none";
        network.fit({{ animation: false }});
        status.innerText = "已返回全局。可滚轮缩放，点击节点查看直接相连。";
      }};

      const renderGraph = () => {{
        if (typeof vis === "undefined") {{
          status.innerText = "图谱脚本加载失败。";
          return;
        }}
        if (started) return;
        started = true;
        nodesDS = new vis.DataSet(DATA.nodes.map((node) => ({{
          ...node,
          font: {{ size: 12, color: "#1f2a44", face: "Microsoft YaHei", strokeWidth: 2, strokeColor: "#ffffff" }},
        }})));
        edgesDS = new vis.DataSet(DATA.edges);
        network = new vis.Network(document.getElementById("graph"), {{ nodes: nodesDS, edges: edgesDS }}, {{
          autoResize: true,
          interaction: {{ hover: true, navigationButtons: true, keyboard: true, zoomView: true }},
          physics: {{ enabled: false }},
          layout: {{ improvedLayout: false }},
          nodes: {{
            borderWidth: 1,
            scaling: {{ label: {{ enabled: false }} }},
            font: {{ color: "#1f2a44", size: 12, face: "Microsoft YaHei" }}
          }},
          edges: {{
            color: {{ color: "#94a3b8", highlight: "#f97316" }},
            smooth: false
          }}
        }});
        network.fit({{ animation: false }});
        network.on("click", (params) => {{
          if (!params.nodes.length) return;
          focusNode(params.nodes[0]);
        }});
        backBtn.addEventListener("click", restoreGlobal);
      }};
      window.addEventListener("load", renderGraph);
      setTimeout(renderGraph, 300);
    </script>
    """


def cached_static_graph_html(graph_path: str) -> Path:
    source = Path(graph_path)
    html_path = source.parent / "_graph_static_focus_v2.html"
    if html_path.exists() and html_path.stat().st_mtime >= source.stat().st_mtime:
        return html_path
    html_path.write_text(build_static_graph_html(graph_path), encoding="utf-8")
    return html_path

