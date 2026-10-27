import json
import os
import re
import shutil
import zipfile
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
import yaml
from matplotlib import font_manager

from audit.agent import refresh_llm_client
from audit.service import run_audit
from config import C
from graph_atlas import cached_graph_html, cached_static_graph_html
import base64


st.set_page_config(
    page_title="AI Code Audit",
    page_icon=":mag:",
    layout="wide",
)


def _render_download_anchor(label: str, data: bytes, file_name: str,
                            mime: str = "text/plain", auto_click: bool = False):
    """在 iframe 内渲染原生 <a download> 按钮，点击即下载，无 Streamlit toast。
    auto_click=True 时渲染后立即自动触发下载（用于已点过下载图标的回调场景）。
    """
    import base64
    b64 = base64.b64encode(data).decode("ascii")
    href = f"data:{mime};base64,{b64}"
    click_js = ("<script>document.getElementById('dl_anchor').click();</script>"
                if auto_click else "")
    html = f"""
        <a id="dl_anchor" href="{href}" download="{file_name}"
           style="display:inline-flex;align-items:center;justify-content:center;
                  width:100%;min-height:38px;padding:0 14px;border-radius:8px;
                  border:1px solid #d0d5dd;background:#fff;color:#344054;
                  font-size:14px;font-weight:600;text-decoration:none;
                  font-family:-apple-system,'Segoe UI',sans-serif;cursor:pointer;"
           onmouseover="this.style.background='#f3f4f6';this.style.borderColor='#98a2b3'"
           onmouseout="this.style.background='#fff';this.style.borderColor='#d0d5dd'">
          {label}
        </a>
        {click_js}
    """
    components.html(html, height=48)


def download_report_button(label: str, report_path: str):
    """可见的下载按钮（替换卡片视图里的 st.download_button）。"""
    path = Path(report_path) if report_path else None
    if not path or not path.exists():
        st.button(label, disabled=True, icon=":material/download:", width="stretch")
        return
    _render_download_anchor(label, path.read_bytes(), path.name)


def _trigger_file_download(item: dict):
    """历史扫描表格点击"下载"图标后，直接触发浏览器原生下载。"""
    report_path = item.get("report_path") or ""
    path = Path(report_path) if report_path else None
    if not path or not path.exists():
        st.error("报告文件不存在。")
        return
    # auto_click=True：用户已在表格里点过下载图标，这里直接落盘
    _render_download_anchor("下载报告", path.read_bytes(), path.name, auto_click=True)


def inject_global_styles():
    css_path = Path(__file__).parent / "static" / "styles.css"
    css = css_path.read_text(encoding="utf-8")
    st.markdown(
        """
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
        """,
        unsafe_allow_html=True,
    )
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


def render_graph_fallback(graph: nx.DiGraph):
    font_family = get_chinese_font_family()
    if font_family:
        plt.rcParams["font.sans-serif"] = [font_family]
    plt.rcParams["axes.unicode_minus"] = False
    sample_nodes = list(graph.nodes())[:120]
    subgraph = graph.subgraph(sample_nodes).copy()
    fig, ax = plt.subplots(figsize=(16, 10))
    pos = nx.spring_layout(subgraph, seed=42, k=1.4)
    labels = {
        node_id: (attrs.get("source_name") or str(node_id))
        for node_id, attrs in subgraph.nodes(data=True)
    }
    nx.draw_networkx_edges(subgraph, pos=pos, ax=ax, width=0.6, arrows=False, edge_color="#94a3b8")
    nx.draw_networkx_nodes(subgraph, pos=pos, ax=ax, node_size=180, node_color="#ff8a65")
    nx.draw_networkx_labels(
        subgraph,
        pos=pos,
        labels=labels,
        ax=ax,
        font_size=8,
        font_color="#1f2a44",
        font_family=font_family or "DejaVu Sans",
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
    enable_thinking = st.checkbox(
        "开启模型思考",
        value=st.session_state.get("enable_thinking", False),
        help="默认关闭。关闭时更快，并已加强常见漏洞覆盖。开启后模型会先简短推理再出报告，覆盖可能更全，但耗时会明显增加。",
        disabled=st.session_state.get("analyzing", False),
    )
    st.session_state.enable_thinking = enable_thinking
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
                result = run_audit(
                    str(project_dir),
                    str(output_dir),
                    batch_size=st.session_state.batch_size,
                    enable_thinking=bool(st.session_state.get("enable_thinking", False)),
                )
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


def _render_pager(total: int, page_size: int, page_state_key: str, widget_suffix: str = "") -> tuple[int, int]:
    total_pages = max(1, (total + page_size - 1) // page_size)
    current = int(st.session_state.get(page_state_key, 1) or 1)
    if current > total_pages:
        current = total_pages
    if current < 1:
        current = 1
    st.session_state[page_state_key] = current

    start = (current - 1) * page_size
    end = min(start + page_size, total)
    widget_key = f"{page_state_key}{widget_suffix}"

    prev_col, info_col, next_col, jump_col = st.columns([1, 1.6, 1, 1.6])
    with prev_col:
        if st.button("上一页", key=f"{widget_key}_prev", icon=":material/chevron_left:", disabled=current <= 1, width="stretch"):
            st.session_state[page_state_key] = current - 1
            st.rerun()
    with info_col:
        st.markdown(
            f"<div style='text-align:center;padding-top:0.45rem'>第 {current} / {total_pages} 页</div>",
            unsafe_allow_html=True,
        )
    with next_col:
        if st.button("下一页", key=f"{widget_key}_next", icon=":material/chevron_right:", disabled=current >= total_pages, width="stretch"):
            st.session_state[page_state_key] = current + 1
            st.rerun()
    with jump_col:
        jump_input_col, jump_btn_col = st.columns([1.2, 1])
        with jump_input_col:
            jump = st.number_input(
                "跳转页",
                min_value=1,
                max_value=total_pages,
                value=current,
                key=f"{widget_key}_jump_value",
                label_visibility="collapsed",
            )
        with jump_btn_col:
            if st.button("跳转", key=f"{widget_key}_go", width="stretch"):
                st.session_state[page_state_key] = int(jump)
                st.rerun()

    shown_start = start + 1 if total else 0
    st.caption(f"显示 {shown_start}-{end}，共 {total} 条")
    return start, end


def _render_result_selector(results: list[dict], session_key: str = "selected_result_label", show_cards: bool = True) -> dict | None:
    """以可切换卡片展示当前扫描和历史扫描结果。"""
    if not results:
        return None

    if st.session_state.get(session_key) not in {item["label"] for item in results}:
        st.session_state[session_key] = results[0]["label"]

    tab_key = f"{session_key}_scan_tab"
    st.session_state.setdefault(tab_key, "当前扫描")

    if not show_cards:
        if st.session_state.get(session_key) not in {item["label"] for item in results}:
            st.session_state[session_key] = results[0]["label"]
        selected_label = st.session_state.get(session_key)
        return next((item for item in results if item["label"] == selected_label), None)

    st.markdown("#### 审计结果")

    current_tab, history_tab = st.columns([1.3, 1.3])
    with current_tab:
        if st.button(
            "当前扫描",
            key=f"{session_key}_tab_current",
            type="primary" if st.session_state[tab_key] == "当前扫描" else "secondary",
            icon=":material/radar:",
            width="stretch",
        ):
            st.session_state[tab_key] = "当前扫描"
            st.rerun()
    with history_tab:
        if st.button(
            "历史扫描",
            key=f"{session_key}_tab_history",
            type="primary" if st.session_state[tab_key] == "历史扫描" else "secondary",
            icon=":material/history:",
            width="stretch",
        ):
            st.session_state[tab_key] = "历史扫描"
            st.rerun()

    if st.session_state[tab_key] == "当前扫描":
        visible_results = results[:1]
        if show_cards:
            st.caption("当前展示最新一次扫描结果。")
    else:
        visible_results = results[1:] if len(results) > 1 else []
        if show_cards:
            st.caption("当前展示历史扫描结果。点击「查看」可切换到该次审计。")

    page_state_key = f"{session_key}_page"
    page_size = 10

    if not visible_results:
        st.info("还没有历史扫描结果。")
        selected_label = st.session_state.get(session_key)
        return next((item for item in results if item["label"] == selected_label), None)

    current_page = max(1, int(st.session_state.get(page_state_key, 1)))
    total_pages = max(1, (len(visible_results) + page_size - 1) // page_size)
    if current_page > total_pages:
        current_page = total_pages
        st.session_state[page_state_key] = current_page
    start = (current_page - 1) * page_size
    page_results = visible_results[start:start + page_size]
    pending = st.session_state.get("pending_delete_label")

    for item in page_results:
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
                if st.button("查看", key=f"view_{session_key}_{item['label']}", icon=":material/visibility:", width="stretch", disabled=is_selected):
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
                        icon=":material/download:",
                        width="stretch",
                    )
                else:
                    st.button("下载", key=f"download_disabled_{session_key}_{item['label']}", icon=":material/download:", width="stretch", disabled=True)
            with c4:
                if st.button("删除", key=f"del_{session_key}_{item['label']}", icon=":material/delete:", width="stretch", type="secondary"):
                    st.session_state.pending_delete_label = item["label"]
                    st.rerun()

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

    if len(visible_results) > page_size:
        _render_pager(len(visible_results), page_size, page_state_key, widget_suffix="_bottom")

    selected_label = st.session_state.get(session_key)
    return next((item for item in results if item["label"] == selected_label), None)


def _render_stat_cards(risk_rows: list[dict], subtitle: str):
    level_counts = {level: sum(1 for row in risk_rows if row["level"] == level) for level in ["高危", "中危", "低危", "信息"]}
    card_cols = st.columns(4)
    card_data = [
        ("漏洞 / 风险", str(len(risk_rows)), subtitle),
        ("高危", str(level_counts["高危"]), "需要优先处理"),
        ("中危 / 低危", f"{level_counts['中危']} / {level_counts['低危']}", "建议复核"),
        ("信息", str(level_counts["信息"]), "低优先级提示"),
    ]
    for column, (label, value, sub) in zip(card_cols, card_data):
        with column:
            st.markdown(
                f"""
                <div class="yakit-card">
                  <div class="label">{label}</div>
                  <div class="value">{value}</div>
                  <div class="sub">{sub}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def _load_result_rows(item: dict) -> list[dict]:
    report_path = item.get("report_path") or ""
    if not report_path or not os.path.exists(report_path):
        return []
    rows = []
    for section in parse_report(read_text_file(report_path)):
        for finding in section["findings"]:
            rows.append({
                "file": section["file_path"],
                "finding": finding,
                "raw": section.get("raw", ""),
                "level": get_finding_level_label(finding["type"]),
                "pass": is_pass_finding(finding),
                "source": item["label"],
            })
    return rows


def _render_filter_toolbar(prefix: str):
    st.markdown('<div class="filter-gap"></div>', unsafe_allow_html=True)
    tool_cols = st.columns([2.6, 1.8, 1.0])
    with tool_cols[0]:
        keyword = st.text_input(
            "搜索",
            placeholder="请输入关键词搜索",
            label_visibility="collapsed",
            key=f"{prefix}_keyword",
        )
    with tool_cols[1]:
        selected_levels = st.multiselect(
            "等级",
            ["高危", "中危", "低危", "信息"],
            default=["高危", "中危", "低危", "信息"],
            label_visibility="collapsed",
            key=f"{prefix}_levels",
        )
    with tool_cols[2]:
        show_passed = st.toggle("显示通过", value=False, key=f"{prefix}_show_passed")
    return keyword or "", selected_levels, show_passed


def _render_risk_table(all_rows: list[dict], selected: dict):
    finding_page_size = 10
    keyword, selected_levels, show_passed = _render_filter_toolbar("risk")

    visible_rows = []
    for row in all_rows:
        if row["pass"] and not show_passed:
            continue
        if not row["pass"] and row["level"] not in selected_levels:
            continue
        haystack = " ".join([
            row["file"],
            row["finding"].get("type", ""),
            row["finding"].get("feature", ""),
            row["finding"].get("vector", ""),
        ]).lower()
        if keyword and keyword.strip().lower() not in haystack:
            continue
        visible_rows.append(row)

    visible_rows.sort(key=lambda row: get_finding_priority(row["finding"]["type"]))
    if not visible_rows:
        st.info("当前筛选条件下没有可展示结果。")
        return

    filter_sig = f"{keyword}|{tuple(selected_levels)}|{show_passed}|{len(visible_rows)}"
    if st.session_state.get("finding_filter_sig") != filter_sig:
        st.session_state["finding_filter_sig"] = filter_sig
        st.session_state["finding_page"] = 1
    start = (max(1, int(st.session_state.get("finding_page", 1))) - 1) * finding_page_size
    page_rows = visible_rows[start:start + finding_page_size]

    table_rows = []
    for index, row in enumerate(page_rows, start=start + 1):
        finding = row["finding"]
        finding_key = f"{row['file']}|{finding['type']}|{finding.get('location')}"
        table_rows.append({
            "index": index,
            "name": Path(row["file"]).name,
            "type": finding["type"],
            "level": row["level"],
            "location": finding.get("location") or "-",
            "key": finding_key,
            "row": row,
        })

    display_rows = [{
        #"序号": item["index"],
        "扫描目标": item["name"],
        "漏洞类型": item["type"],
        "等级": item["level"],
        "位置": item["location"],
    } for item in table_rows]
    selection = st.dataframe(
        pd.DataFrame(display_rows),
        width="stretch",
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key="risk_table",
    )
    selected_rows = selection.selection.rows if selection and selection.selection else []
    if selected_rows:
        open_item = table_rows[selected_rows[0]]
        open_key = open_item["key"]
        if st.session_state.get("closed_finding_key") != open_key:
            finding = open_item["row"]["finding"]
            badge_class = get_finding_badge_class(finding["type"])
            with st.container(border=True):
                st.markdown('<div class="detail-anchor"></div>', unsafe_allow_html=True)
                title_col, close_col = st.columns([8, 0.7])
                with title_col:
                    st.markdown(
                        f"""
                        <div class="detail-head">
                          <div class="detail-title">{finding['type']}</div>
                          <span class="level-tag {badge_class}">{open_item['level']}</span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                with close_col:
                    if st.button("×", key="close_finding_detail", help="关闭", type="tertiary"):
                        st.session_state["closed_finding_key"] = open_key
                        st.rerun()
                st.markdown(f'<div class="detail-path">{open_item["row"]["file"]}</div>', unsafe_allow_html=True)
                if finding.get("feature"):
                    st.markdown('<div class="detail-label">代码特征</div>', unsafe_allow_html=True)
                    st.code(finding["feature"], language="text")
                for label, value in (
                    ("攻击向量", finding.get("vector")),
                    ("潜在影响", finding.get("impact")),
                    ("修复建议", finding.get("fix")),
                ):
                    if value:
                        st.markdown(
                            f'<div class="detail-label">{label}</div><div class="detail-text">{value}</div>',
                            unsafe_allow_html=True,
                        )
    if len(visible_rows) > finding_page_size:
        _render_pager(len(visible_rows), finding_page_size, "finding_page", widget_suffix="_bottom")


def _handle_history_action(session_key: str, action: str, tab_key: str = "result_active_tab", return_tab: str = "漏洞与风险"):
    click_key = f"history_{action}_click"
    click = st.session_state.get(click_key)
    items = st.session_state.get("_history_page_items") or []
    if not click or not items:
        return
    row = click["row"] if isinstance(click, dict) else click.row
    if row < 0 or row >= len(items):
        return
    item = items[row]
    if action == "view":
        st.session_state[session_key] = item["label"]
        st.session_state[tab_key] = return_tab
        st.rerun()
    elif action == "delete":
        output_dir = Path(item["output_dir"])
        try:
            if output_dir.exists():
                shutil.rmtree(output_dir, ignore_errors=True)
            latest = st.session_state.get("latest_result")
            if latest and latest.get("output_dir") == str(output_dir):
                st.session_state.latest_result = None
            if st.session_state.get(session_key) == item["label"]:
                st.session_state[session_key] = None
            st.rerun()
        except Exception as e:
            st.session_state["history_action_error"] = f"删除失败：{e}"
    elif action == "download":
        st.session_state["history_download_item"] = item


def _render_history_table(results: list[dict], session_key: str, tab_key: str = "result_active_tab", return_tab: str = "漏洞与风险"):
    page_size = 10
    page_key = "history_scan_page"
    st.markdown('<div class="filter-gap"></div>', unsafe_allow_html=True)
    tool_cols = st.columns([2.6, 1.8, 1.0])
    with tool_cols[0]:
        keyword = st.text_input("搜索", placeholder="请输入关键词搜索", label_visibility="collapsed", key="history_keyword")
    with tool_cols[1]:
        selected_levels = st.multiselect(
            "等级",
            ["高危", "中危", "低危", "信息"],
            default=["高危", "中危", "低危", "信息"],
            label_visibility="collapsed",
            key="history_levels",
        )
    with tool_cols[2]:
        show_passed = st.toggle("显示通过", value=False, key="history_show_passed")

    filtered = []
    needle = (keyword or "").strip().lower()
    for item in results:
        name = Path(item["output_dir"]).name
        time_text = item["label"].split("|")[-1].strip()
        hash_text = (item.get("project_hash") or "")[:12]
        if needle and needle not in f"{name} {time_text} {hash_text}".lower():
            continue
        if selected_levels != ["高危", "中危", "低危", "信息"] or show_passed:
            rows = _load_result_rows(item)
            levels = {row["level"] for row in rows if not row["pass"]}
            if selected_levels and not levels.intersection(selected_levels):
                continue
            if show_passed and not any(row["pass"] for row in rows):
                continue
        filtered.append(item)

    filter_sig = f"{needle}|{tuple(selected_levels)}|{show_passed}|{len(filtered)}"
    if st.session_state.get("history_filter_sig") != filter_sig:
        st.session_state["history_filter_sig"] = filter_sig
        st.session_state[page_key] = 1

    total = len(filtered)
    if total == 0:
        st.info("当前筛选条件下没有可展示结果。")
        return
    total_pages = max(1, (total + page_size - 1) // page_size)
    current = max(1, int(st.session_state.get(page_key, 1) or 1))
    if current > total_pages:
        current = total_pages
        st.session_state[page_key] = current
    start = (current - 1) * page_size
    page_results = filtered[start:start + page_size]
    st.session_state["_history_page_items"] = page_results

    rows = []
    for item in page_results:
        report_path = item.get("report_path") or ""
        rows.append({
            "扫描目标": Path(item["output_dir"]).name,
            "时间": item["label"].split("|")[-1].strip(),
            "哈希": (item.get("project_hash") or "")[:12],
            "查看": ":material/visibility:",
            "下载": ":material/download:" if report_path and os.path.exists(report_path) else "",
            "删除": ":material/delete:",
        })
    st.dataframe(
        pd.DataFrame(rows),
        width="stretch",
        hide_index=True,
        column_order=["扫描目标", "时间", "哈希", "查看", "下载", "删除"],
        column_config={
            "扫描目标": st.column_config.TextColumn("扫描目标", width=720),
            "时间": st.column_config.TextColumn("时间", width=220),
            "哈希": st.column_config.TextColumn("哈希", width=160),
            "查看": st.column_config.ButtonColumn(
                "查看",
                on_click=_handle_history_action,
                args=(session_key, "view", tab_key, return_tab),
                key="history_view_click",
                width=48,
                alignment="center",
            ),
            "下载": st.column_config.ButtonColumn(
                "下载",
                on_click=_handle_history_action,
                args=(session_key, "download", tab_key, return_tab),
                key="history_download_click",
                width=48,
                alignment="center",
            ),
            "删除": st.column_config.ButtonColumn(
                "删除",
                on_click=_handle_history_action,
                args=(session_key, "delete", tab_key, return_tab),
                key="history_delete_click",
                width=48,
                alignment="center",
            ),
        },
        key="history_table",
    )
    error = st.session_state.pop("history_action_error", None)
    if error:
        st.error(error)
    download_item = st.session_state.pop("history_download_item", None)
    if download_item:
        _trigger_file_download(download_item)
    _render_pager(total, page_size, page_key, widget_suffix="_history")


def render_result_list_page(workspace: Path):
    render_page_hero(
        "审计结果",
        "聚焦查看结构化风险项、攻击向量与修复建议。默认会隐藏纯“审计通过”块。",
        "Result Review",
    )
    results = get_selected_result(workspace)
    if not results:
        st.info("还没有可展示的结果，请先在“分析”页面执行一次审计。")
        return

    selected = _render_result_selector(results, session_key="selected_result_label", show_cards=False)
    if not selected:
        st.info("请选择一个分析结果。")
        return

    current_rows = _load_result_rows(selected)
    current_risks = [row for row in current_rows if not row["pass"]]
    history_rows = []
    for item in results:
        history_rows.extend(row for row in _load_result_rows(item) if not row["pass"])

    st.session_state.setdefault("result_active_tab", "漏洞与风险")
    tab_col, history_col = st.columns([1.6, 1.2])
    with tab_col:
        if st.button(
            f"漏洞与风险 ({len(current_risks)})",
            key="tab_risk",
            type="primary" if st.session_state["result_active_tab"] == "漏洞与风险" else "secondary",
            width="stretch",
        ):
            st.session_state["result_active_tab"] = "漏洞与风险"
            st.rerun()
    with history_col:
        if st.button(
            "历史扫描",
            key="tab_history",
            type="primary" if st.session_state["result_active_tab"] == "历史扫描" else "secondary",
            width="stretch",
        ):
            st.session_state["result_active_tab"] = "历史扫描"
            st.rerun()

    if st.session_state["result_active_tab"] == "历史扫描":
        _render_stat_cards(history_rows, "全部历史扫描风险总数")
        _render_history_table(results, session_key="selected_result_label")
    else:
        _render_stat_cards(current_risks, "当前结果风险总数")
        _render_risk_table(current_rows, selected)


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

    selected = _render_result_selector(results, session_key="selected_graph_label", show_cards=False)
    if not selected:
        st.info("请选择一个分析结果。")
        return

    st.session_state.setdefault("graph_active_tab", "当前图谱")
    current_col, history_col = st.columns([1.6, 1.2])
    with current_col:
        if st.button(
            "当前图谱",
            key="tab_graph_current",
            type="primary" if st.session_state["graph_active_tab"] == "当前图谱" else "secondary",
            width="stretch",
        ):
            st.session_state["graph_active_tab"] = "当前图谱"
            st.rerun()
    with history_col:
        if st.button(
            "历史扫描",
            key="tab_graph_history",
            type="primary" if st.session_state["graph_active_tab"] == "历史扫描" else "secondary",
            width="stretch",
        ):
            st.session_state["graph_active_tab"] = "历史扫描"
            st.rerun()

    if st.session_state["graph_active_tab"] == "历史扫描":
        st.caption("默认展示最新一次扫描。点击「查看」可切换到该次依赖图谱。")
        _render_history_table(
            results,
            session_key="selected_graph_label",
            tab_key="graph_active_tab",
            return_tab="当前图谱",
        )
        return

    if not os.path.exists(selected["graph_path"]):
        st.warning("当前结果没有可用的 graphml 文件。")
        return

    graph = nx.read_graphml(selected["graph_path"])
    render_stat_strip([
        ("节点数", str(graph.number_of_nodes())),
        ("边数", str(graph.number_of_edges())),
        ("结果目录", Path(selected["output_dir"]).name),
    ])
    view = st.radio(
        "图谱视图",
        ["交互图谱", "静态预览", "节点列表", "边列表"],
        horizontal=True,
        label_visibility="collapsed",
        key="graph_view",
    )
    if view == "交互图谱":
        st.caption("首次打开会计算一次力导向布局并缓存。点击节点可在当前窗口查看它的直接相连节点，可拖动，返回全局后恢复。")
        html_path = cached_graph_html(selected["graph_path"])
        st.iframe(html_path, height=820)
    elif view == "静态预览":
        st.caption("静态预览只显示前 120 个高优先级节点。可滚轮缩放，点击节点查看直接相连，返回全局后恢复。")
        html_path = cached_static_graph_html(selected["graph_path"])
        st.iframe(html_path, height=820)
    elif view == "节点列表":
        node_df = build_node_dataframe(graph)
        search_text = st.text_input("搜索节点 / 文件 / 路径", key="node_search").strip().lower()
        if search_text:
            node_df = node_df[
                node_df.astype(str).apply(lambda col: col.str.lower().str.contains(search_text, na=False))
                .any(axis=1)
            ]
        st.dataframe(node_df, width="stretch", height=520)
    else:
        st.dataframe(build_edge_dataframe(graph), width="stretch", height=520)


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
    st.session_state.setdefault("enable_thinking", False)
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


