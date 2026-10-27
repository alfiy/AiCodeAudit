"""依赖图谱：默认展示漏洞相关节点，回退时只保留项目源码。"""
import hashlib
import json
import math
import re
from pathlib import Path

import networkx as nx

_THIRD_PARTY_MARKERS = (
    "/node_modules/",
    "/vendor/",
    "/dist/",
    "/third-party/",
    "/bower_components/",
    "/site-packages/",
    "/.venv/",
    "/public/js/app.js",
    "/public/laravel-u-editor/",
    "/min.js",
)
_RISK_COLORS = {
    "高危": "#dc2626",
    "中危": "#f97316",
    "低危": "#eab308",
    "可疑": "#2563eb",
    "信息": "#64748b",
}


def is_project_source_node(node_id: str, attrs: dict) -> bool:
    if not str(attrs.get("source_code") or "").strip():
        return False
    source_name = str(attrs.get("source_name") or "")
    if source_name.startswith("import:") or source_name in {"无外部依赖", "配置项"}:
        return False
    path = "/" + str(attrs.get("path") or "").replace("\\", "/").lower()
    name = str(attrs.get("name") or "").lower()
    if any(marker in path for marker in _THIRD_PARTY_MARKERS):
        return False
    if name in {"vendor.js", "bundle.js", "app.js"} or name.endswith(".min.js"):
        return False
    return True


def project_source_ids(graph: nx.DiGraph) -> set[str]:
    return {str(node_id) for node_id, attrs in graph.nodes(data=True) if is_project_source_node(node_id, attrs)}


def _normalize_path(value: str) -> str:
    return str(value or "").replace("\\", "/").lower()


def _paths_match(node_path: str, finding_path: str) -> bool:
    left = _normalize_path(node_path)
    right = _normalize_path(finding_path)
    if not left or not right or right in {"未知文件", "当前审计上下文", "当前审计任务"}:
        return False
    return left == right or left.endswith("/" + right) or right.endswith("/" + left) or left.endswith(Path(right).name)


def _risk_level(finding: dict) -> str:
    text = f"{finding.get('type', '')} {finding.get('location', '')}"
    for level in ("高危", "中危", "低危"):
        if level in text:
            return level
    if "可疑" in text:
        return "可疑"
    return "信息"


def _line_overlap(location: str, start: int, end: int) -> bool:
    numbers = [int(item) for item in re.findall(r"\d+", location or "")]
    if not numbers or not start:
        return False
    if len(numbers) == 1:
        return start <= numbers[0] <= max(end, start)
    return not (max(numbers) < start or min(numbers) > max(end, start))


def match_vulnerability_nodes(graph: nx.DiGraph, sections: list[dict]) -> dict[str, str]:
    risks: dict[str, str] = {}
    file_fallbacks: dict[str, str] = {}
    for section in sections or []:
        findings = [
            finding for finding in section.get("findings", [])
            if finding.get("type") not in {"审计通过", "结构化审计通过结果", "审核通过", "审计不完整"}
        ]
        if not findings:
            continue
        finding_path = section.get("file_path") or ""
        matched_file = False
        for node_id, attrs in graph.nodes(data=True):
            if not _paths_match(attrs.get("path", ""), finding_path):
                continue
            if not is_project_source_node(node_id, attrs):
                continue
            source_name = str(attrs.get("source_name") or "")
            start = int(attrs.get("start_code_line") or 0)
            end = int(attrs.get("end_code_line") or 0)
            for finding in findings:
                location = str(finding.get("location") or "")
                feature = str(finding.get("feature") or "")
                level = _risk_level(finding)
                if (source_name and (source_name in location or source_name in feature)) or _line_overlap(location, start, end):
                    risks[str(node_id)] = level
                    matched_file = True
            file_fallbacks.setdefault(str(node_id), _risk_level(findings[0]))
        if not matched_file:
            for node_id, level in file_fallbacks.items():
                if _paths_match(graph.nodes[node_id].get("path", ""), finding_path):
                    risks.setdefault(node_id, level)
    return risks


def resolve_project_graph(graph: nx.DiGraph, allowed: set[str] | None = None) -> nx.DiGraph:
    """把“调用方 -> 无源码占位节点”解析成“项目函数 -> 项目函数”。"""
    allowed = allowed or project_source_ids(graph)
    resolved = nx.DiGraph()
    by_name: dict[str, list[str]] = {}
    for node_id in allowed:
        if node_id not in graph:
            continue
        attrs = dict(graph.nodes[node_id])
        resolved.add_node(node_id, **attrs)
        name = str(attrs.get("source_name") or "").strip()
        if name:
            by_name.setdefault(name, []).append(node_id)

    generic_names = {"get", "set", "index", "main", "init", "run", "call", "handle", "execute"}
    for node_id in allowed:
        if node_id not in graph:
            continue
        caller = graph.nodes[node_id]
        caller_path = _normalize_path(caller.get("path", ""))
        for target in graph.successors(node_id):
            target_attrs = graph.nodes[target]
            callee_name = str(target_attrs.get("source_name") or "").strip()
            if not callee_name or callee_name.startswith("import:") or callee_name in {"无外部依赖", "配置项"}:
                continue
            candidates = [item for item in by_name.get(callee_name, []) if item != node_id]
            if not candidates:
                continue
            same_file = [item for item in candidates if _normalize_path(graph.nodes[item].get("path", "")) == caller_path]
            if same_file:
                chosen = same_file
            elif len(candidates) == 1 and callee_name.lower() not in generic_names:
                chosen = candidates
            else:
                continue
            for callee in chosen:
                resolved.add_edge(node_id, callee)
    return resolved


_UTILITY_NAMES = {
    "apireturn", "getes", "success", "fail", "error", "json", "response",
    "ajaxreturn", "returnjson", "ret", "ok", "result", "output",
}


def low_value_hubs(graph: nx.DiGraph, risks: dict[str, str], degree_limit: int = 12) -> set[str]:
    """排除被大量调用的公共节点，例如 apiReturn、getEs。"""
    hubs = set()
    for node_id, attrs in graph.nodes(data=True):
        node_key = str(node_id)
        if node_key in risks:
            continue
        name = str(attrs.get("source_name") or "").strip().lower()
        short = name.split(".")[-1]
        if name in _UTILITY_NAMES or short in _UTILITY_NAMES or graph.degree(node_id) >= degree_limit:
            hubs.add(node_key)
    return hubs


def expand_related_nodes(graph: nx.DiGraph, seeds: set[str], hops: int = 2, skip: set[str] | None = None) -> set[str]:
    skip = skip or set()
    seen = set(seeds) & set(graph.nodes)
    frontier = set(seen)
    for _ in range(hops):
        nxt = set()
        for node_id in frontier:
            if node_id in skip:
                continue
            for neighbor in list(graph.predecessors(node_id)) + list(graph.successors(node_id)):
                neighbor = str(neighbor)
                if neighbor not in seen and neighbor not in skip:
                    nxt.add(neighbor)
        seen |= nxt
        frontier = nxt
    return seen


def select_visualization_nodes(graph: nx.DiGraph, sections: list[dict]) -> tuple[set[str], dict[str, str], str, nx.DiGraph]:
    resolved = resolve_project_graph(graph)
    risks = match_vulnerability_nodes(graph, sections)
    hubs = low_value_hubs(resolved, risks)
    if risks:
        related = expand_related_nodes(resolved, set(risks), hops=2, skip=hubs)
        related -= hubs
        if not related:
            related = set(risks)
        cleaned = resolved.copy()
        cleaned.remove_nodes_from([node for node in hubs if node in cleaned])
        return related, risks, "漏洞相关", cleaned
    kept = set(resolved.nodes) - hubs
    cleaned = resolved.copy()
    cleaned.remove_nodes_from([node for node in hubs if node in cleaned])
    return kept, {}, "项目源码", cleaned


def _file_color(name: str) -> str:
    colors = ["#64748b", "#0ea5e9", "#8b5cf6", "#14b8a6", "#6366f1", "#84cc16", "#f59e0b", "#ec4899"]
    return colors[abs(hash(str(name or ""))) % len(colors)]


def _disk_centers(count: int, radius: float) -> list[tuple[float, float]]:
    if count <= 1:
        return [(0.0, 0.0)]
    centers = []
    for index in range(count):
        ring = radius * math.sqrt(index / (count - 1))
        angle = index * 2.399963
        centers.append((ring * math.cos(angle), ring * math.sin(angle)))
    return centers


def _focus_positions(graph: nx.DiGraph, risks: dict[str, str]) -> tuple[dict[str, list[float]], dict[str, int]]:
    """按依赖聚簇，并把簇铺进圆内，避免全部贴在圆周上。"""
    if graph.number_of_nodes() == 0:
        return {}, {}
    undirected = graph.to_undirected()
    try:
        from networkx.algorithms.community import greedy_modularity_communities
        communities = [set(item) for item in greedy_modularity_communities(undirected)]
    except Exception:
        communities = [set(item) for item in nx.connected_components(undirected)]
    isolates = [item for item in communities if len(item) == 1]
    clusters = [item for item in communities if len(item) > 1]
    if isolates:
        clusters.append(set().union(*isolates))
    if not clusters:
        clusters = [set(graph.nodes())]
    clusters.sort(key=lambda item: (-len(item), 0 if any(str(node) in risks for node in item) else 1))
    positions: dict[str, list[float]] = {}
    cluster_of: dict[str, int] = {}
    centers = _disk_centers(len(clusters), 260 + 28 * math.sqrt(len(clusters)))
    for index, cluster in enumerate(clusters):
        cx, cy = centers[index]
        members = list(cluster)
        for node_id in members:
            cluster_of[str(node_id)] = index
        if len(members) == 1:
            positions[str(members[0])] = [round(cx, 1), round(cy, 1)]
            continue
        local = nx.spring_layout(
            graph.subgraph(members),
            seed=42,
            k=1.8 / math.sqrt(len(members)),
            iterations=50,
        )
        scale = 28 + 10 * math.sqrt(len(members))
        for node_id, xy in local.items():
            positions[str(node_id)] = [round(cx + float(xy[0]) * scale, 1), round(cy + float(xy[1]) * scale, 1)]
    return positions, cluster_of


def build_graph_html(graph_path: str, keep_ids: set[str] | None = None, risks: dict[str, str] | None = None, resolved: nx.DiGraph | None = None) -> str:
    graph = resolved if resolved is not None else nx.read_graphml(graph_path)
    if keep_ids is not None:
        graph = graph.subgraph([node for node in graph.nodes if str(node) in keep_ids]).copy()
    risks = risks or {}
    positions, cluster_of = _focus_positions(graph, risks)
    ranked = sorted(
        graph.nodes(data=True),
        key=lambda item: (
            0 if str(item[0]) in risks else 1,
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
        level = risks.get(node_key, "")
        x, y = positions.get(node_key, [0, 0])
        full_label = str(attrs.get("source_name") or node_key)
        if len(full_label) > 22:
            full_label = full_label[:20] + "…"
        nodes.append({
            "id": node_key,
            "label": "",
            "fullLabel": full_label,
            "showLabel": False,
            "title": f"{level + ' ' if level else ''}{full_label} | {attrs.get('name', '')}",
            "group": attrs.get("name", "default"),
            "shape": "dot",
            "size": 5,
            "scaling": {"min": 10, "max": 10, "label": {"enabled": False, "min": 11, "max": 11}},
            "x": x,
            "y": y,
            "fixed": True,
            "rank": rank,
            "color": _RISK_COLORS.get(level) or _file_color(attrs.get("name", "")),
            "font": {"size": 11, "vadjust": 0},
            "cluster": cluster_of.get(node_key, 0),
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
                "arrows": "",
                "width": 0.6,
                "smooth": False,
                "cross": cluster_of.get(source_id, -1) != cluster_of.get(target_id, -2),
                "hidden": cluster_of.get(source_id, -1) != cluster_of.get(target_id, -2),
                "rank": max(rank_by_id.get(source_id, 0), rank_by_id.get(target_id, 0)),
            })
    graph_id = hashlib.sha1(("v17-util|" + str(Path(graph_path).resolve())).encode("utf-8")).hexdigest()[:16]
    default_pct = 15 if len(nodes) > 300 else 30
    for node in nodes:
        if not node.get("color"):
            node.pop("color", None)
    payload = json.dumps({"nodes": nodes, "edges": edges}, ensure_ascii=False).replace("<", "\\u003c")
    return f"""
    <div style="display:flex;align-items:center;gap:12px;padding:8px 12px;color:#475569;font-family:Microsoft YaHei;">
      <label for="draw-range" style="white-space:nowrap;">绘制范围</label>
      <input id="draw-range" type="range" min="10" max="100" step="5" value="{default_pct}" style="flex:1;">
      <strong id="draw-pct" style="min-width:48px;">{default_pct}%</strong>
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
          DATA.edges.forEach((edge) => {{ edge.hidden = edge.cross || edge.rank >= limit; }});
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
          if (edge.rank >= start && edge.rank < end) edgeUpdates.push({{ id: edge.id, hidden: hide || edge.cross }});
        }});
        if (nodeUpdates.length) nodesDS.update(nodeUpdates);
        if (edgeUpdates.length) edgesDS.update(edgeUpdates);
        shown = limit;
        if (!focusId) status.innerText = statusText(percent, limit, "悬停看名称，点击查看直接相连。");
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
              label: node.fullLabel || node.label,
              hidden: false,
              x: 0,
              y: 0,
              fixed: false,
              size: 12,
              font: {{ size: 12, color: "#1f2a44", face: "Microsoft YaHei", strokeWidth: 2, strokeColor: "#ffffff" }},
            }};
          }}
          if (!keep.has(node.id)) return {{ id: node.id, hidden: true }};
          const index = related.indexOf(node.id);
          const angle = (Math.PI * 2 * index) / Math.max(related.length, 1);
          return {{
            id: node.id,
            label: node.fullLabel || node.label,
            hidden: false,
            x: Math.round(Math.cos(angle) * radius),
            y: Math.round(Math.sin(angle) * radius),
            fixed: false,
            font: {{ size: 11, color: "#1f2a44", face: "Microsoft YaHei", strokeWidth: 2, strokeColor: "#ffffff" }},
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
        const label = nodeById[nodeId] ? (nodeById[nodeId].fullLabel || nodeById[nodeId].label) : nodeId;
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
            label: node.showLabel ? node.fullLabel : "",
          }};
          if (pos) {{
            item.x = pos[0];
            item.y = pos[1];
          }}
          return item;
        }}));
        edgesDS.update(DATA.edges.map((edge) => ({{ id: edge.id, hidden: edge.cross || edge.rank >= limit, smooth: false, width: 0.4 }})));
        shown = limit;
        globalPos = null;
        network.setOptions({{
          nodes: {{ scaling: {{ label: {{ enabled: true, min: 10, max: 16 }} }} }},
          edges: {{ smooth: false, width: 0.4 }},
        }});
        backBtn.style.display = "none";
        slider.disabled = false;
        network.fit({{ animation: false }});
        status.innerText = statusText(Number(slider.value), limit, "已返回全局。悬停看名称，点击查看直接相连。");
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
        applyRange({default_pct});
        nodesDS = new vis.DataSet(DATA.nodes);
        edgesDS = new vis.DataSet(DATA.edges);
        network = new vis.Network(document.getElementById("graph"), {{ nodes: nodesDS, edges: edgesDS }}, {{
          autoResize: true,
          interaction: {{ hover: true, hoverConnectedEdges: false, selectConnectedEdges: false, navigationButtons: true, keyboard: true }},
          physics: {{ enabled: false }},
          layout: {{ improvedLayout: false }},
          nodes: {{
            borderWidth: 1,
            size: 5,
            scaling: {{ min: 5, max: 5, label: {{ enabled: false, min: 11, max: 11 }} }},
            font: {{ color: "#1f2a44", size: 11, face: "Microsoft YaHei" }}
          }},
          edges: {{
            width: 0.4,
            hoverWidth: 0,
            selectionWidth: 0,
            color: {{ color: "#d6dde8", highlight: "#d6dde8", hover: "#d6dde8" }},
            smooth: false,
            arrows: {{ to: {{ enabled: false }} }}
          }}
        }});
        network.fit({{ animation: false }});
        ready = true;
        let hoverId = null;
        const edgeWidth = () => 0.4 / Math.max(network.getScale(), 0.05);
        const showRelated = (nodeId) => {{
          hoverId = nodeId;
          const related = new Set([nodeId, ...(neighbors[nodeId] || [])]);
          const limit = Math.min(total, limitFor(Number(slider.value)));
          const width = edgeWidth();
          nodesDS.update(DATA.nodes.map((node) => ({{
            id: node.id,
            hidden: !(related.has(node.id) || node.rank < limit),
            label: node.id === nodeId ? (node.fullLabel || "") : "",
          }})));
          edgesDS.update(DATA.edges.map((edge) => {{
            const linked = edge.from === nodeId || edge.to === nodeId;
            return {{
              id: edge.id,
              hidden: !(linked || (!edge.cross && edge.rank < limit)),
              width,
              color: linked ? "#f97316" : "#d6dde8",
            }};
          }}));
        }};
        const hideRelated = () => {{
          hoverId = null;
          const limit = Math.min(total, limitFor(Number(slider.value)));
          const width = edgeWidth();
          nodesDS.update(DATA.nodes.map((node) => ({{ id: node.id, hidden: node.rank >= limit, label: "" }})));
          edgesDS.update(DATA.edges.map((edge) => ({{
            id: edge.id,
            hidden: edge.cross || edge.rank >= limit,
            width,
            color: "#d6dde8",
          }})));
        }};
        const lockVisualSize = () => {{
          if (!nodesDS) return;
          const scale = Math.max(network.getScale(), 0.05);
          const size = 5 / scale;
          const fontSize = 11 / scale;
          nodesDS.update(DATA.nodes.map((node) => ({{
            id: node.id,
            size,
            font: {{ size: fontSize, color: "#1f2a44", face: "Microsoft YaHei" }},
          }})));
          edgesDS.update(DATA.edges.map((edge) => ({{ id: edge.id, width: edgeWidth() }})));
        }};
        network.on("zoom", lockVisualSize);
        lockVisualSize();
        const nearestNode = (domPoint) => {{
          if (!domPoint || !network) return null;
          const positions = network.getPositions();
          let best = null;
          let bestDist = 22;
          Object.keys(positions).forEach((id) => {{
            const node = nodesDS.get(id);
            if (!node || node.hidden) return;
            const dom = network.canvasToDOM(positions[id]);
            const dist = Math.hypot(dom.x - domPoint.x, dom.y - domPoint.y);
            if (dist < bestDist) {{
              bestDist = dist;
              best = id;
            }}
          }});
          return best;
        }};
        const canvas = document.getElementById("graph").querySelector("canvas");
        const pointerOf = (event) => {{
          const rect = canvas.getBoundingClientRect();
          return {{ x: event.clientX - rect.left, y: event.clientY - rect.top }};
        }};
        canvas.addEventListener("mousemove", (event) => {{
          if (!ready || focusId) return;
          const nodeId = nearestNode(pointerOf(event));
          if (nodeId === hoverId) return;
          if (nodeId) showRelated(nodeId);
          else hideRelated();
        }});
        canvas.addEventListener("mouseleave", () => {{
          if (!focusId) hideRelated();
        }});
        canvas.addEventListener("click", (event) => {{
          if (!ready || focusId) return;
          const nodeId = nearestNode(pointerOf(event)) || hoverId;
          if (!nodeId) return;
          focusNode(nodeId);
        }});
        status.innerText = statusText({default_pct}, shown, "悬停按屏幕距离识别节点，放大后也能点中。");
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


def cached_graph_html(graph_path: str, keep_ids: set[str] | None = None, risks: dict[str, str] | None = None, resolved: nx.DiGraph | None = None) -> Path:
    source = Path(graph_path)
    signature = hashlib.sha1(("v17-util|" + ",".join(sorted(keep_ids or []))).encode("utf-8")).hexdigest()[:10]
    html_path = source.parent / f"_graph_preview_focus_{signature}.html"
    if html_path.exists() and html_path.stat().st_mtime >= source.stat().st_mtime:
        return html_path
    html_path.write_text(build_graph_html(graph_path, keep_ids, risks, resolved), encoding="utf-8")
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


def build_static_graph_html(graph_path: str, keep_ids: set[str] | None = None, risks: dict[str, str] | None = None, resolved: nx.DiGraph | None = None) -> str:
    graph = resolved if resolved is not None else nx.read_graphml(graph_path)
    if keep_ids is not None:
        graph = graph.subgraph([node for node in graph.nodes if str(node) in keep_ids]).copy()
    risks = risks or {}
    ranked = sorted(
        graph.nodes(data=True),
        key=lambda item: (
            0 if str(item[0]) in risks else 1,
            -graph.degree(item[0]),
        ),
    )
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
            "size": 22 if risks.get(node_key, "") else (16 if attrs.get("source_code") else 9),
            "x": x,
            "y": y,
            "fixed": True,
            "color": _RISK_COLORS.get(risks.get(node_key, ""), ""),
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
    for node in nodes:
        if not node.get("color"):
            node.pop("color", None)
    payload = json.dumps({"nodes": nodes, "edges": edges}, ensure_ascii=False).replace("<", "\\u003c")
    return f"""
    <div style="display:flex;align-items:center;gap:12px;padding:8px 12px;color:#475569;font-family:Microsoft YaHei;">
      <button id="back-global" type="button" style="display:none;border:1px solid #d0d5dd;background:#fff;border-radius:8px;padding:4px 10px;cursor:pointer;">返回全局</button>
      <span id="graph-status">静态预览：当前范围可滚轮缩放，点击节点查看直接相连。</span>
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


def cached_static_graph_html(graph_path: str, keep_ids: set[str] | None = None, risks: dict[str, str] | None = None, resolved: nx.DiGraph | None = None) -> Path:
    source = Path(graph_path)
    signature = hashlib.sha1(("v4|" + ",".join(sorted(keep_ids or []))).encode("utf-8")).hexdigest()[:10]
    html_path = source.parent / f"_graph_static_focus_{signature}.html"
    if html_path.exists() and html_path.stat().st_mtime >= source.stat().st_mtime:
        return html_path
    html_path.write_text(build_static_graph_html(graph_path, keep_ids, risks, resolved), encoding="utf-8")
    return html_path

