import json
import os
import re
import shutil
import zipfile
from datetime import datetime
from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
import streamlit as st
import yaml
from matplotlib import font_manager

from audit.agent import refresh_llm_client
from audit.service import run_audit
from config import C


st.set_page_config(
    page_title="AI Code Audit",
    page_icon=":mag:",
    layout="wide",
)


def inject_global_styles():
    css_path = Path(__file__).parent / "static" / "styles.css"
    css = css_path.read_text(encoding="utf-8")
    st.markdown(f"<style>\n{css}\n</style>", unsafe_allow_html=True)


def render_page_hero(title: str, description: str, eyebrow: str):
    st.markdown(
        f"""
        <div class="hero-panel">
          <h1 class="hero-title">{title}</h1>
          <p class="hero-copy">{description}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_stat_strip(items: list[tuple[str, str]]):
    columns = st.columns(len(items))
    for column, (label, value) in zip(columns, items):
        with column:
            st.metric(label, value)


def get_finding_badge_class(finding_type: str) -> str:
    lowered = finding_type.lower()
    if "高危" in finding_type or "critical" in lowered or "high" in lowered:
        return "high"
    if "中危" in finding_type or "medium" in lowered:
        return "medium"
    if "低危" in finding_type or "low" in lowered:
        return "low"
    return "info"


def get_finding_level_label(finding_type: str) -> str:
    badge_class = get_finding_badge_class(finding_type)
    return {
        "high": "高危",
        "medium": "中危",
        "low": "低危",
        "info": "信息",
    }.get(badge_class, "信息")


def get_finding_priority(finding_type: str) -> int:
    badge_class = get_finding_badge_class(finding_type)
    return {
        "high": 0,
        "medium": 1,
        "low": 2,
        "info": 3,
    }.get(badge_class, 4)


def get_chinese_font_family() -> str | None:
    candidates = [
        "Microsoft YaHei",
        "SimHei",
        "Noto Sans CJK SC",
        "Source Han Sans SC",
        "WenQuanYi Zen Hei",
        "Arial Unicode MS",
        "Noto Sans CJK JP",
        "Droid Sans Fallback",
    ]
    available_fonts = {font.name for font in font_manager.fontManager.ttflist}
    for candidate in candidates:
        if candidate in available_fonts:
            return candidate
    # 再按文件名探测常见中文字体
    for font_path in font_manager.findSystemFonts():
        lower = font_path.lower()
        if any(key in lower for key in ("noto", "cjk", "wqy", "sourcehan", "simhei", "msyh")):
            try:
                font_manager.fontManager.addfont(font_path)
                return font_manager.FontProperties(fname=font_path).get_name()
            except Exception:
                continue
    return None


def ensure_workspace() -> Path:
    workspace = Path("output") / "streamlit_runs"
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


def ensure_streamlit_subdirs(workspace: Path) -> dict[str, Path]:
    subdirs = {
        "uploads": workspace / "uploads",
        "extracted": workspace / "extracted",
        "results": workspace / "results",
    }
    for path in subdirs.values():
        path.mkdir(parents=True, exist_ok=True)
    return subdirs


def sanitize_name(name: str) -> str:
    normalized = re.sub(r"[^\w.-]+", "_", name.strip(), flags=re.UNICODE).strip("._")
    return normalized or "project"


def save_uploaded_zip(uploaded_file, upload_dir: Path) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = sanitize_name(Path(uploaded_file.name).stem)
    target = upload_dir / f"{safe_name}_{timestamp}.zip"
    with target.open("wb") as f:
        f.write(uploaded_file.getbuffer())
    return target


def extract_zip(zip_path: Path, extract_root: Path):
    extract_dir = extract_root / zip_path.stem
    extract_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(extract_dir)

    children = [item for item in extract_dir.iterdir() if item.name != "__MACOSX"]
    if len(children) == 1 and children[0].is_dir():
        return extract_dir, children[0]
    return extract_dir, extract_dir


def read_text_file(file_path: str) -> str:
    with open(file_path, "r", encoding="utf-8") as f:
        return f.read()


def discover_results(workspace: Path):
    results_root = workspace / "results"
    if not results_root.exists():
        return []

    results = []
    for result_dir in sorted(results_root.iterdir(), key=lambda path: path.stat().st_mtime, reverse=True):
        if not result_dir.is_dir():
            continue
        graph_files = sorted(result_dir.glob("*.graphml"))
        report_files = sorted(result_dir.glob("*_审计结果.log"))
        if not graph_files:
            continue
        graph_path = graph_files[0]
        report_path = report_files[0] if report_files else None
        project_hash = graph_path.stem
        results.append({
            "label": f"{result_dir.name} | {datetime.fromtimestamp(result_dir.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')}",
            "project_hash": project_hash,
            "graph_path": str(graph_path),
            "report_path": str(report_path) if report_path else "",
            "output_dir": str(result_dir),
        })
    return results


def parse_report(report_text: str):
    sections = [section.strip() for section in report_text.split("--------------------------------") if section.strip()]
    if not sections and report_text.strip():
        sections = [report_text.strip()]

    parsed = []
    for section in sections:
        structured = parse_structured_report_section(section)
        if structured:
            parsed.extend(structured)
            continue
        legacy = parse_legacy_report_section(section)
        if legacy.get("findings"):
            parsed.append(legacy)
            continue
        recovered = _recover_from_reasoning(section)
        if recovered:
            parsed.append(recovered)
    return parsed


def _recover_from_reasoning(section: str) -> dict | None:
    text = section.strip()
    if not text:
        return None

    file_path = "未知文件"
    path_match = re.search(r"(?:路径|文件)[:：]\s*([^\s\n]+)", text)
    if path_match:
        file_path = path_match.group(1).strip()
    else:
        path_like = re.search(r"(/[\w./\-]+\.(?:php|py|js|java|go|c|cpp|cs))", text)
        if path_like:
            file_path = path_like.group(1)

    vuln_type = "可疑风险"
    for candidate in ("SQL注入", "命令注入", "路径遍历", "任意文件读写", "SSRF", "XXE", "反序列化", "XSS", "任意代码执行", "认证绕过", "敏感信息泄露"):
        if candidate in text:
            vuln_type = candidate
            break

    level = "信息"
    for candidate in ("高危", "中危", "低危"):
        if candidate in text:
            level = candidate
            break

    verdict = "确认风险" if "确认风险" in text else "可疑风险"
    feature = ""
    code_match = re.search(r"(?:代码特征|关键代码)[:：]\s*(.+)", text)
    if code_match:
        feature = code_match.group(1).strip()[:500]
    else:
        # 取一段较短代码风格行作为证据
        code_lines = [line.strip() for line in text.splitlines() if any(tok in line for tok in ("=", "->", "fopen", "fwrite", "$_", "exec", "query"))]
        feature = "\n".join(code_lines[:6])

    return {
        "file_path": file_path,
        "findings": [{
            "type": format_finding_title(vuln_type, verdict, level),
            "location": "-",
            "feature": feature or text[:800],
            "vector": _pick_sentence(text, ("攻击", "可控", "输入")),
            "impact": _pick_sentence(text, ("影响", "导致", "泄露")),
            "fix": _pick_sentence(text, ("建议", "修复", "改为")),
        }],
        "raw": section,
    }


def _pick_sentence(text: str, keywords: tuple[str, ...]) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and any(key in stripped for key in keywords) and len(stripped) < 200:
            return stripped
    return ""


def is_pass_finding(finding: dict) -> bool:
    finding_type = (finding.get("type") or "").strip()
    return finding_type in {"审计通过", "结构化审计通过结果", "审核通过"}


def is_incomplete_finding(finding: dict) -> bool:
    finding_type = (finding.get("type") or "").strip()
    return finding_type == "审计不完整"


def format_finding_title(vuln_type: str, verdict: str, level: str) -> str:
    parts = [part for part in [vuln_type, verdict, level] if part]
    if not parts:
        return "未命名风险"
    if len(parts) == 1:
        return parts[0]
    return f"{parts[0]}（{' / '.join(parts[1:])}）"


def has_non_pass_findings(section: dict) -> bool:
    return any(not is_pass_finding(finding) for finding in section.get("findings", []))


def extract_tag_content(text: str, tag: str) -> str:
    match = re.search(rf"<{tag}>\s*(.*?)\s*</{tag}>", text, re.DOTALL)
    return match.group(1).strip() if match else ""


def extract_line_value(text: str, field_name: str) -> str:
    match = re.search(rf"^{re.escape(field_name)}\s*:\s*(.+)$", text, re.MULTILINE)
    return match.group(1).strip() if match else ""


def parse_structured_report_section(section: str):
    if "<审计报告>" not in section:
        return []

    files = re.findall(r"<文件>\s*(.*?)\s*</文件>", section, re.DOTALL)
    parsed = []

    for file_block in files:
        file_path = extract_line_value(file_block, "路径") or "未知文件"
        conclusion = extract_line_value(file_block, "结论")
        findings = []

        for vuln_block in re.findall(r"<漏洞>\s*(.*?)\s*</漏洞>", file_block, re.DOTALL):
            vuln_type = extract_line_value(vuln_block, "类型")
            verdict = extract_line_value(vuln_block, "判定")
            level = extract_line_value(vuln_block, "等级")
            location = extract_line_value(vuln_block, "位置")
            findings.append({
                "type": format_finding_title(vuln_type, verdict, level),
                "location": location or "-",
                "feature": extract_tag_content(vuln_block, "代码特征"),
                "vector": extract_tag_content(vuln_block, "攻击向量"),
                "impact": extract_tag_content(vuln_block, "潜在影响"),
                "fix": extract_tag_content(vuln_block, "修复建议"),
            })

        if conclusion in {"审计通过", "结构化审计通过结果", "审核通过"} and not findings:
            findings.append({
                "type": "审计通过",
                "location": "-",
                "feature": "当前文件在本次上下文中未识别到明确漏洞",
                "vector": "",
                "impact": "",
                "fix": "",
            })

        parsed.append({
            "file_path": file_path,
            "findings": findings,
            "raw": section,
        })

    if parsed:
        return parsed

    if "<结论>审计通过</结论>" in section:
        return [{
            "file_path": "当前审计上下文",
            "findings": [{
                "type": "审计通过",
                "location": "-",
                "feature": "当前上下文未识别到明确漏洞",
                "vector": "",
                "impact": "",
                "fix": "",
            }],
            "raw": section,
        }]

    if "<结论>审计不完整</结论>" in section:
        summary = extract_tag_content(section, "统计")
        explanation = extract_tag_content(section, "说明")
        return [{
            "file_path": "当前审计任务",
            "findings": [{
                "type": "审计不完整",
                "location": "-",
                "feature": summary or "Agent_2 失败率过高，当前结果不应视为审计通过",
                "vector": explanation,
                "impact": "当前审计结果可能遗漏真实风险，请优先修复网络或代理问题后重试。",
                "fix": "建议降低并发、检查代理稳定性，并重新执行审计。",
            }],
            "raw": section,
        }]

    return []


def parse_legacy_report_section(section: str):
    lines = [line.rstrip("\n") for line in section.splitlines() if line.strip()]
    file_path = "未知文件"
    findings = []
    current = None
    current_field = None

    for line in lines:
        stripped = line.strip()

        if stripped.startswith("// "):
            file_path = stripped[3:].strip()
        elif stripped.startswith("// 文件路径:"):
            file_path = stripped.replace("// 文件路径:", "", 1).strip()
        elif stripped.startswith("// 文件路径："):
            file_path = stripped.replace("// 文件路径：", "", 1).strip()
        elif stripped.startswith("■ 漏洞类型："):
            if current:
                findings.append(current)
            current = {
                "type": stripped.replace("■ 漏洞类型：", "", 1).strip(),
                "location": "",
                "feature": "",
                "vector": "",
                "impact": "",
                "fix": "",
            }
            current_field = None
        elif current and stripped.startswith("▶ 位置："):
            current["location"] = stripped.replace("▶ 位置：", "", 1).strip()
            current_field = "location"
        elif current and stripped.startswith("▶ 代码特征："):
            current["feature"] = stripped.replace("▶ 代码特征：", "", 1).strip()
            current_field = "feature"
        elif current and stripped.startswith("▶ 攻击向量："):
            current["vector"] = stripped.replace("▶ 攻击向量：", "", 1).strip()
            current_field = "vector"
        elif current and stripped.startswith("▶ 潜在影响："):
            current["impact"] = stripped.replace("▶ 潜在影响：", "", 1).strip()
            current_field = "impact"
        elif current and stripped.startswith("▶ 修复建议："):
            current["fix"] = stripped.replace("▶ 修复建议：", "", 1).strip()
            current_field = "fix"
        elif current and not stripped.startswith("<") and current_field:
            existing = current.get(current_field, "")
            if current_field == "feature":
                current[current_field] = (existing + "\n" + line.strip()) if existing else line.strip()
            else:
                current[current_field] = (existing + " " + stripped).strip() if existing else stripped

    if current:
        findings.append(current)

    if ("<审计通过>" in section or "<结论>审计通过</结论>" in section) and not findings:
        findings.append({
            "type": "审计通过",
            "location": "-",
            "feature": "当前上下文未识别到明确漏洞",
            "vector": "",
            "impact": "",
            "fix": "",
        })

    return {
        "file_path": file_path,
        "findings": findings,
        "raw": section,
    }


def build_graph_html(graph_path: str) -> str:
    graph = nx.read_graphml(graph_path)
    nodes = []
    edges = []

    for node_id, attrs in graph.nodes(data=True):
        label = attrs.get("source_name") or str(node_id)
        title = (
            f"文件: {attrs.get('name', '')}<br>"
            f"路径: {attrs.get('path', '')}<br>"
            f"描述: {attrs.get('desc', '')}<br>"
            f"行号: {attrs.get('start_code_line', '')}-{attrs.get('end_code_line', '')}"
        )
        nodes.append({
            "id": str(node_id),
            "label": label,
            "title": title,
            "group": attrs.get("name", "default"),
            "shape": "dot",
            "size": 14 if attrs.get("source_code") else 8,
        })

    for source, target in graph.edges():
        edges.append({
            "from": str(source),
            "to": str(target),
            "arrows": "to",
        })

    return f"""
    <div id="graph-status" style="padding:8px 12px;color:#475569;font-family:Microsoft YaHei;">图谱加载中...</div>
    <div id="graph" style="width:100%;height:760px;border-radius:18px;border:1px solid #e6e8ef;background:linear-gradient(180deg,#fbfbfd 0%,#f4f6fb 100%);"></div>
    <script src="https://cdn.jsdelivr.net/npm/vis-network@9.1.2/dist/vis-network.min.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/vis-network@9.1.2/dist/dist/vis-network.min.css"/>
    <script>
      const status = document.getElementById("graph-status");
      const renderGraph = () => {{
        if (typeof vis === "undefined") {{
          status.innerText = "图谱脚本加载失败，页面已回退到下方列表视图。";
          return;
        }}
        const nodes = new vis.DataSet({json.dumps(nodes, ensure_ascii=False)});
        const edges = new vis.DataSet({json.dumps(edges, ensure_ascii=False)});
        const container = document.getElementById("graph");
        const data = {{ nodes, edges }};
        const options = {{
          autoResize: true,
          interaction: {{
            hover: true,
            navigationButtons: true,
            keyboard: true
          }},
          physics: {{
            enabled: true,
            solver: "forceAtlas2Based",
            stabilization: {{ iterations: 300 }}
          }},
          layout: {{
            improvedLayout: true
          }},
          nodes: {{
            borderWidth: 1,
            borderWidthSelected: 2,
            color: {{
              background: "#ff8a65",
              border: "#d85d3c",
              highlight: {{ background: "#ff7043", border: "#b94722" }}
            }},
            font: {{
              color: "#1f2a44",
              size: 14,
              face: "Microsoft YaHei"
            }}
          }},
          edges: {{
            color: {{ color: "#94a3b8", highlight: "#f97316" }},
            smooth: {{ type: "dynamic" }}
          }},
          groups: {{
            default: {{ color: {{ background: "#ff8a65", border: "#d85d3c" }} }}
          }}
        }};
        const network = new vis.Network(container, data, options);
        network.once("stabilizationIterationsDone", function () {{
          network.fit({{ animation: true }});
          status.innerText = "图谱加载完成，可拖拽、缩放和悬停查看详情。";
        }});
      }};
      window.addEventListener("load", renderGraph);
      setTimeout(renderGraph, 400);
    </script>
    """


def render_graph_fallback(graph: nx.DiGraph):
    font_family = get_chinese_font_family()
    if font_family:
        plt.rcParams["font.sans-serif"] = [font_family]
    plt.rcParams["axes.unicode_minus"] = False
    sample_nodes = list(graph.nodes())[:120]
    subgraph = graph.subgraph(sample_nodes).copy()
    fig, ax = plt.subplots(figsize=(14, 9))
    pos = nx.spring_layout(subgraph, seed=42, k=0.9)
    nx.draw_networkx(
        subgraph,
        pos=pos,
        ax=ax,
        with_labels=False,
        node_size=70,
        width=0.6,
        arrows=False,
        node_color="#ff8a65",
        edge_color="#94a3b8",
    )
    title = "依赖图谱静态预览（前120个节点）" if font_family else "Dependency graph preview (first 120 nodes)"
    ax.set_title(title, fontsize=14, fontfamily=font_family or "DejaVu Sans")
    ax.axis("off")
    st.pyplot(fig, clear_figure=True)


def build_node_dataframe(graph: nx.DiGraph):
    rows = []
    for node_id, attrs in graph.nodes(data=True):
        rows.append({
            "节点ID": str(node_id),
            "文件": attrs.get("name", ""),
            "路径": attrs.get("path", ""),
            "代码单元": attrs.get("source_name", ""),
            "被调用目标": attrs.get("target_name", ""),
            "开始行": attrs.get("start_code_line", ""),
            "结束行": attrs.get("end_code_line", ""),
            "摘要": attrs.get("desc", ""),
        })
    return pd.DataFrame(rows)


def build_edge_dataframe(graph: nx.DiGraph):
    rows = []
    for source, target in graph.edges():
        rows.append({
            "源节点": str(source),
            "目标节点": str(target),
        })
    return pd.DataFrame(rows)


def render_analysis_page(workspace: Path):
    subdirs = ensure_streamlit_subdirs(workspace)
    render_page_hero(
        "项目分析工作台",
        "上传项目压缩包后，系统会自动完成源码扫描、依赖图构建与安全审计，并把结构化结果整理到可视化页面中。",
        "Analysis Studio",
    )
    render_stat_strip([
        ("结果目录", str(subdirs["results"])),
        ("每批任务数", str(st.session_state.batch_size)),
        ("文件保留策略", "保留" if st.session_state.keep_files else "分析后清理"),
    ])
    st.caption("推荐上传完整项目的 `zip` 压缩包。系统会自动解压、扫描源码、提取依赖，再生成结构化审计报告与 GraphML 图谱。")

    uploaded_file = st.file_uploader("上传项目压缩包", type=["zip"])
    if uploaded_file is None:
        st.info("请上传一个 zip 压缩包。")
        return

    analyzing = st.session_state.get("analyzing", False)
    analysis_done = st.session_state.get("analysis_done", False)
    button_label = "分析中..." if analyzing else ("重新分析" if analysis_done else "开始分析")
    clicked = st.button(button_label, type="primary", width="stretch", disabled=analyzing)

    if clicked and not analyzing:
        st.session_state.analyzing = True
        st.rerun()

    if analyzing:
        zip_path = save_uploaded_zip(uploaded_file, subdirs["uploads"])
        try:
            with st.status("正在解压并分析项目...", expanded=True) as status:
                st.write("保存上传文件")
                run_root, project_dir = extract_zip(zip_path, subdirs["extracted"])
                st.write(f"解压完成: `{project_dir}`")

                batch_name = f"{sanitize_name(project_dir.name)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                output_dir = subdirs["results"] / batch_name
                st.write("开始执行 AI 审计")
                result = run_audit(str(project_dir), str(output_dir), batch_size=st.session_state.batch_size)
                st.session_state.latest_result = result
                status.update(label="分析完成", state="complete")

            st.success("分析完成，请从侧边栏进入“结果可视化”或“依赖可视化”查看。")
            st.session_state.analysis_done = True
        except zipfile.BadZipFile:
            st.error("上传文件不是有效的 zip 压缩包。")
        except Exception as exc:
            st.exception(exc)
        finally:
            st.session_state.analyzing = False
            if not st.session_state.keep_files:
                if zip_path.exists():
                    zip_path.unlink()
                if "run_root" in locals() and run_root.exists():
                    shutil.rmtree(run_root, ignore_errors=True)
                if "output_dir" in locals() and output_dir.exists():
                    shutil.rmtree(output_dir, ignore_errors=True)
            st.rerun()


def get_selected_result(workspace: Path):
    results = discover_results(workspace)
    latest = st.session_state.get("latest_result")
    if latest and all(item.get("project_hash") != latest.get("project_hash") for item in results):
        results.insert(0, {
            "label": f"{Path(latest['output_dir']).name} | 当前会话",
            **latest,
        })
    return results


def _render_result_selector(results: list[dict], session_key: str = "selected_result_label") -> dict | None:
    """以卡片列表形式展示历史分析结果，每条自带查看与删除操作。"""
    if not results:
        return None

    # 默认选中最新一条
    if st.session_state.get(session_key) not in {item["label"] for item in results}:
        st.session_state[session_key] = results[0]["label"]

    st.markdown("#### 历史分析结果")
    st.caption("点击「查看」切换当前结果，点击「下载」保存审计日志，点击「删除」可移除该次审计记录。")

    pending = st.session_state.get("pending_delete_label")

    for item in results:
        is_selected = item["label"] == st.session_state.get(session_key)
        with st.container(border=True):
            c1, c2, c3, c4 = st.columns([5.2, 1.1, 1.1, 1.1])
            with c1:
                title = item["label"]
                if is_selected:
                    title = f"**{title}**（当前）"
                st.markdown(title)
                hash_short = (item.get("project_hash") or "")[:12]
                st.caption(f"哈希：`{hash_short}`　·　目录：`{Path(item['output_dir']).name}`")
            with c2:
                if st.button("查看", key=f"view_{session_key}_{item['label']}", width="stretch", disabled=is_selected):
                    st.session_state[session_key] = item["label"]
                    st.rerun()
            with c3:
                report_path = item.get("report_path") or ""
                if report_path and os.path.exists(report_path):
                    report_name = Path(report_path).name
                    st.download_button(
                        "下载",
                        data=Path(report_path).read_bytes(),
                        file_name=report_name,
                        mime="text/plain",
                        key=f"download_{session_key}_{item['label']}",
                        width="stretch",
                    )
                else:
                    st.button("下载", key=f"download_disabled_{session_key}_{item['label']}", width="stretch", disabled=True)
            with c4:
                if st.button("删除", key=f"del_{session_key}_{item['label']}", width="stretch", type="secondary"):
                    st.session_state.pending_delete_label = item["label"]
                    st.rerun()

            # 该条目的删除确认
            if pending == item["label"]:
                st.warning("确认永久删除此分析结果？此操作不可恢复。")
                cy, cn = st.columns(2)
                with cy:
                    if st.button("确认删除", key=f"confirm_{session_key}_{item['label']}", type="primary", width="stretch"):
                        output_dir = Path(item["output_dir"])
                        try:
                            if output_dir.exists():
                                shutil.rmtree(output_dir, ignore_errors=True)
                            latest = st.session_state.get("latest_result")
                            if latest and latest.get("output_dir") == str(output_dir):
                                st.session_state.latest_result = None
                            st.session_state.pending_delete_label = None
                            if st.session_state.get(session_key) == item["label"]:
                                st.session_state[session_key] = None
                            st.success("已删除。")
                            st.rerun()
                        except Exception as e:
                            st.error(f"删除失败：{e}")
                with cn:
                    if st.button("取消", key=f"cancel_{session_key}_{item['label']}", width="stretch"):
                        st.session_state.pending_delete_label = None
                        st.rerun()

    selected_label = st.session_state.get(session_key)
    return next((item for item in results if item["label"] == selected_label), None)


def render_result_list_page(workspace: Path):
    render_page_hero(
        "审计结果可视化",
        "聚焦查看结构化风险项、攻击向量与修复建议。默认会隐藏纯“审计通过”块，让你把注意力留给真正需要处理的结果。",
        "Result Review",
    )
    results = get_selected_result(workspace)
    if not results:
        st.info("还没有可展示的结果，请先在“分析”页面执行一次审计。")
        return

    selected = _render_result_selector(results, session_key="selected_result_label")
    if not selected:
        st.info("请从上方列表中选择一个分析结果。")
        return

    st.divider()

    render_stat_strip([
        ("项目哈希", selected["project_hash"][:12]),
        ("GraphML", os.path.basename(selected["graph_path"])),
        ("报告日志", os.path.basename(selected["report_path"]) if selected["report_path"] else "未生成"),
    ])

    if not selected["report_path"] or not os.path.exists(selected["report_path"]):
        st.warning("当前结果没有可用的审计日志。")
        return

    report_text = read_text_file(selected["report_path"])
    parsed_sections = parse_report(report_text)
    show_passed = st.toggle("显示审计通过结果", value=False, help="默认隐藏仅包含“审计通过”的审计块")
    show_raw_blocks = st.toggle("显示原始审计块", value=False, help="关闭可减少大量结果时的页面卡顿")
    selected_levels = st.multiselect(
        "风险等级筛选",
        ["高危", "中危", "低危", "信息"],
        default=["高危", "中危", "低危", "信息"],
        help="只显示选中的风险等级",
    )
    sort_mode = st.selectbox(
        "排序方式",
        ["按风险等级（高到低）", "按文件顺序"],
        index=0,
        help="控制结果的展示顺序",
    )

    if not parsed_sections:
        st.text_area("原始报告", report_text, height=400)
        return

    visible_sections = []
    for section in parsed_sections:
        filtered_findings = []
        for finding in section["findings"]:
            if not show_passed and is_pass_finding(finding):
                continue
            if is_pass_finding(finding):
                filtered_findings.append(finding)
                continue
            if is_incomplete_finding(finding):
                filtered_findings.append(finding)
                continue
            if get_finding_level_label(finding["type"]) in selected_levels:
                filtered_findings.append(finding)

        if filtered_findings:
            visible_sections.append({
                **section,
                "findings": filtered_findings,
            })

    total_findings = sum(len(section["findings"]) for section in parsed_sections)
    visible_findings = sum(len(section["findings"]) for section in visible_sections)

    render_stat_strip([
        ("当前展示审计块", str(len(visible_sections))),
        ("当前展示结果数", str(visible_findings)),
        ("原始结果总数", str(total_findings)),
    ])

    if not visible_sections:
        st.info("当前筛选条件下没有可展示结果。你可以调整风险等级筛选，或打开“显示审计通过结果”查看完整输出。")
        return

    if sort_mode == "按风险等级（高到低）":
        visible_sections = sorted(
            visible_sections,
            key=lambda section: min(
                (get_finding_priority(finding["type"]) for finding in section["findings"] if not is_pass_finding(finding)),
                default=99,
            ),
        )

    for section in visible_sections:
        st.markdown(f"#### {section['file_path']}")
        if not section["findings"]:
            st.code(section["raw"], language="text")
            continue

        findings_to_render = section["findings"]
        if sort_mode == "按风险等级（高到低）":
            findings_to_render = sorted(findings_to_render, key=lambda finding: get_finding_priority(finding["type"]))

        for finding in findings_to_render:
            badge_class = get_finding_badge_class(finding["type"])
            level_label = get_finding_level_label(finding["type"])
            st.markdown(
                f"""
                <div class="finding-card {badge_class}">
                  <div class="finding-header">
                    <h4 class="finding-title {badge_class}">{finding['type']}</h4>
                    <div class="finding-meta">
                      <span class="badge {badge_class}">{level_label}</span>
                      <span class="badge">{finding['location'] or '-'}</span>
                    </div>
                  </div>
                  <div class="field-label">代码特征</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
            if finding["feature"]:
                st.code(finding["feature"], language="text")
            else:
                st.markdown('<div class="field-text">-</div>', unsafe_allow_html=True)
            if finding["vector"]:
                st.markdown('<div class="field-label">攻击向量</div>', unsafe_allow_html=True)
                st.markdown(f'<div class="field-text">{finding["vector"]}</div>', unsafe_allow_html=True)
            if finding["impact"]:
                st.markdown('<div class="field-label">潜在影响</div>', unsafe_allow_html=True)
                st.markdown(f'<div class="field-text">{finding["impact"]}</div>', unsafe_allow_html=True)
            if finding["fix"]:
                st.markdown('<div class="field-label">修复建议</div>', unsafe_allow_html=True)
                st.markdown(f'<div class="field-text">{finding["fix"]}</div>', unsafe_allow_html=True)
            if show_raw_blocks:
                raw_preview = section["raw"]
                if len(raw_preview) > 4000:
                    raw_preview = raw_preview[:4000] + "\n\n...（原始审计块过长，已截断显示）"
                with st.expander("查看本文件原始审计块"):
                    st.code(raw_preview, language="text")
        st.divider()


def render_graph_page(workspace: Path):
    render_page_hero(
        "依赖图谱可视化",
        "从交互图谱、静态预览和节点明细三个视角查看项目依赖结构，快速定位高耦合节点与关键调用单元。",
        "Dependency Atlas",
    )
    results = get_selected_result(workspace)
    if not results:
        st.info("还没有可展示的图谱，请先在“分析”页面执行一次审计。")
        return

    selected = _render_result_selector(results, session_key="selected_graph_label")
    if not selected:
        st.info("请从上方列表中选择一个分析结果。")
        return

    st.divider()

    if not os.path.exists(selected["graph_path"]):
        st.warning("当前结果没有可用的 graphml 文件。")
        return

    graph = nx.read_graphml(selected["graph_path"])
    render_stat_strip([
        ("节点数", str(graph.number_of_nodes())),
        ("边数", str(graph.number_of_edges())),
        ("结果目录", Path(selected["output_dir"]).name),
    ])

    graph_tab, static_tab, node_tab, edge_tab = st.tabs(["交互图谱", "静态预览", "节点列表", "边列表"])

    with graph_tab:
        html_path = Path(selected["output_dir"]) / "_graph_preview.html"
        html_path.write_text(build_graph_html(selected["graph_path"]), encoding="utf-8")
        st.iframe(html_path, height=820)

    with static_tab:
        render_graph_fallback(graph)

    with node_tab:
        node_df = build_node_dataframe(graph)
        search_text = st.text_input("搜索节点 / 文件 / 路径", key="node_search").strip().lower()
        if search_text:
            node_df = node_df[
                node_df.astype(str).apply(lambda col: col.str.lower().str.contains(search_text, na=False))
                .any(axis=1)
            ]
        st.dataframe(node_df, width="stretch", height=520)

    with edge_tab:
        edge_df = build_edge_dataframe(graph)
        st.dataframe(edge_df, width="stretch", height=520)


def _cfg_int(name: str, default: int) -> int:
    return int(getattr(C.project, name, default))


def _cfg_openai(name: str, default):
    return getattr(C.openai, name, default)


def _update_yaml_scalar(text: str, section: str, key: str, value) -> str:
    """只替换已有标量，尽量保留注释和格式。"""
    lines = text.splitlines()
    in_section = False
    section_indent = None
    key_pattern = re.compile(rf"^(\s*){re.escape(key)}\s*:")
    rendered = yaml.safe_dump({key: value}, allow_unicode=True, sort_keys=False).strip().split(":", 1)[1].strip()
    replaced = False
    for idx, line in enumerate(lines):
        if re.match(rf"^{re.escape(section)}\s*:", line):
            in_section = True
            section_indent = len(line) - len(line.lstrip(" "))
            continue
        if in_section and line.strip() and not line.strip().startswith("#"):
            indent = len(line) - len(line.lstrip(" "))
            if section_indent is not None and indent <= section_indent:
                in_section = False
        if in_section:
            match = key_pattern.match(line)
            if match:
                lines[idx] = f"{match.group(1)}{key}: {rendered}"
                replaced = True
                break
    if not replaced:
        insert_at = len(lines)
        for idx, line in enumerate(lines):
            if re.match(rf"^{re.escape(section)}\s*:", line):
                insert_at = idx + 1
                break
        lines.insert(insert_at, f"  {key}: {rendered}")
    return "\n".join(lines) + "\n"


def _save_settings(project_values: dict, openai_values: dict):
    config_path = Path("config.yaml")
    if config_path.exists():
        text = config_path.read_text(encoding="utf-8")
    else:
        text = "openai:\nproject:\n"
    for key, value in openai_values.items():
        text = _update_yaml_scalar(text, "openai", key, value)
        try:
            setattr(C.openai, key, value)
        except (ValueError, AttributeError):
            pass
    for key, value in project_values.items():
        text = _update_yaml_scalar(text, "project", key, value)
        try:
            setattr(C.project, key, value)
        except (ValueError, AttributeError):
            pass
    config_path.write_text(text, encoding="utf-8")
    try:
        refresh_llm_client()
    except Exception:
        pass


def render_settings_page():
    render_page_hero(
        "审计配置",
        "在这里调整大项目覆盖、依赖树规模和任务上限。保存后立即作用于下一次审计，无需重启。",
        "Settings",
    )
    st.info("页面读取的是当前目录的 config.yaml，不是 config.example.yaml。保存只更新对应字段，并尽量保留原有注释。")

    with st.form("audit_settings_form"):
        st.markdown("### 模型连接")
        st.caption("只需配置接口地址和密钥。模型名、并发、超时仍使用 config.yaml 中的现有值。")
        base_url = st.text_input(
            "接口地址 openai.base_url",
            value=str(_cfg_openai("base_url", "http://127.0.0.1:8000/v1")),
            help="OpenAI 兼容接口地址。本地 llama-server 填 http://127.0.0.1:8000/v1。",
        )
        api_key = st.text_input(
            "接口密钥 openai.api_key",
            value=str(_cfg_openai("api_key", "")),
            type="password",
            help="调用模型接口的密钥。本地 llama-server 可填任意非空值。",
        )

        st.markdown("### 覆盖与规模")
        st.caption("大项目建议：建树上限 600，保留依赖树 120，完整上下文 80，轻量审计 200。0 表示自动或不限制。")
        c1, c2 = st.columns(2)
        with c1:
            tree_build_limit = st.number_input(
                "建树节点上限 agent2_tree_build_limit",
                min_value=0,
                max_value=20000,
                value=_cfg_int("agent2_tree_build_limit", 0),
                help="大项目建完整依赖树前的候选上限。0=自动：节点超过 800 时只对前 600 个高价值节点建树。调大更全，但建树更慢。",
            )
            st.caption("建议大项目填 600。先筛有安全信号的节点再建树，避免扫几千个节点。")
            max_trees = st.number_input(
                "保留依赖树数量 agent2_max_trees",
                min_value=0,
                max_value=5000,
                value=_cfg_int("agent2_max_trees", 0),
                help="最终进入树审计的依赖树数量。0=按项目规模自动取 80～160，并按文件均衡。调大可覆盖更多调用链。",
            )
            st.caption("建议 120。这些树带上下游调用链，用来发现跨函数漏洞。")
        with c2:
            full_fit_limit = st.number_input(
                "完整上下文节点数 agent2_full_fit_limit",
                min_value=0,
                max_value=5000,
                value=_cfg_int("agent2_full_fit_limit", 80),
                help="对多少个高分节点做完整局部上下文适配。0=不限制。这部分最慢，但上下文最完整。",
            )
            st.caption("建议 80。这部分最准，也最耗时。")
            light_fit_limit = st.number_input(
                "轻量审计节点数 agent2_light_fit_limit",
                min_value=0,
                max_value=10000,
                value=_cfg_int("agent2_light_fit_limit", 200),
                help="对其余通过预筛的节点做单节点轻量审计的上限。0=不限制。用于补覆盖，成本低于完整上下文。",
            )
            st.caption("建议 200。只审函数自身，用来补覆盖。")

        st.markdown("### 任务上限")
        c3, c4 = st.columns(2)
        with c3:
            max_payloads = st.number_input(
                "最终任务数上限 agent2_max_payloads",
                min_value=0,
                max_value=20000,
                value=_cfg_int("agent2_max_payloads", 0),
                help="送入模型的最终任务数上限。0=不截断，保证覆盖。设为正数可限制总耗时。",
            )
            st.caption("建议保持 0，去重后的任务全部送审。")
        with c4:
            max_per_file = st.number_input(
                "单文件任务上限 agent2_max_per_file",
                min_value=0,
                max_value=100,
                value=_cfg_int("agent2_max_per_file", 0),
                help="仅在设置了最终任务数上限时生效。每个文件最多保留多少个任务。0=不限制单文件。",
            )
            st.caption("建议保持 0。只有设置了总上限时才需要限制单文件。")

        st.markdown("### 预筛与上下文")
        c5, c6, c7 = st.columns(3)
        with c5:
            score_threshold = st.number_input(
                "预筛分数阈值 agent2_candidate_score_threshold",
                min_value=-1,
                max_value=100,
                value=_cfg_int("agent2_candidate_score_threshold", 8),
                help="节点进入审计候选的最低分。-1=关闭预筛，所有节点都进入候选。值越大越快，但可能漏掉边缘风险。",
            )
            st.caption("你当前是 16。想覆盖更全可改为 8；-1 关闭预筛。")
        with c6:
            context_depth = st.number_input(
                "上下文深度 audit_context_depth",
                min_value=1,
                max_value=6,
                value=_cfg_int("audit_context_depth", 2),
                help="局部子图向上/向下扩展的最大层数。越大越容易拼出完整漏洞链路，上下文也更长。",
            )
            st.caption("建议 2。")
        with c7:
            max_audit_nodes = st.number_input(
                "单次最大节点数 max_audit_nodes",
                min_value=1,
                max_value=50,
                value=_cfg_int("max_audit_nodes", 12),
                help="一次局部审计最多纳入多少个相关节点。越大覆盖越广，提示词也越长。",
            )
            st.caption("建议 8～12。")

        submitted = st.form_submit_button("保存并启用", type="primary", width="stretch")
        if submitted:
            project_values = {
                "agent2_tree_build_limit": int(tree_build_limit),
                "agent2_max_trees": int(max_trees),
                "agent2_full_fit_limit": int(full_fit_limit),
                "agent2_light_fit_limit": int(light_fit_limit),
                "agent2_max_payloads": int(max_payloads),
                "agent2_max_per_file": int(max_per_file),
                "agent2_candidate_score_threshold": int(score_threshold),
                "audit_context_depth": int(context_depth),
                "max_audit_nodes": int(max_audit_nodes),
            }
            openai_values = {
                "base_url": base_url.strip(),
                "api_key": api_key.strip(),
            }
            _save_settings(project_values, openai_values)
            st.success("已写入当前 config.yaml，并已对当前进程生效。下一次审计会使用新参数。")


def init_session_state():
    st.session_state.setdefault("batch_size", 10)
    st.session_state.setdefault("analysis_done", False)
    st.session_state.setdefault("analyzing", False)
    st.session_state.setdefault("keep_files", True)
    st.session_state.setdefault("latest_result", None)
    st.session_state.setdefault("pending_delete_label", None)
    st.session_state.setdefault("selected_result_label", None)
    st.session_state.setdefault("selected_graph_label", None)


def main():
    workspace = ensure_workspace()
    init_session_state()
    inject_global_styles()

    with st.sidebar:
        st.markdown("## AI Code Audit")
        st.caption("上传项目、生成依赖图、查看审计结果")
        st.markdown("---")
        st.markdown("## 运行参数")
        st.session_state.batch_size = st.slider("每批任务数", min_value=1, max_value=30, value=st.session_state.batch_size)
        st.session_state.keep_files = st.checkbox("保留上传与解压文件", value=st.session_state.keep_files)
        st.markdown("---")
        st.markdown("## 功能导航")
        page = st.radio(
            "功能导航",
            ["分析", "结果可视化", "依赖可视化", "配置"],
            label_visibility="collapsed",
        )

    if page == "分析":
        render_analysis_page(workspace)
    elif page == "结果可视化":
        render_result_list_page(workspace)
    elif page == "配置":
        render_settings_page()
    else:
        render_graph_page(workspace)


if __name__ == "__main__":
    main()
