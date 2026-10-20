import asyncio
import hashlib
import os
import re
from collections import deque
from typing import List

import networkx as nx
from loguru import logger
from tqdm import tqdm

from audit import get_all_source_files_bfs, print_source_dir, scan_project_struct
from audit.agent import agent_1, agent_2
from audit.tool import (
    build_dependency_tree,
    gen_text_from_dependency_tree,
    gen_text_from_local_subgraph,
    get_global_ranked_dependency_trees,
    get_local_security_summary,
    get_local_subgraph_nodes,
    get_security_hint_profile,
    security_hint_score,
    _format_node,
)
from config import C
from models import SourceFile
from prompt import build_agent_1_prompt, build_agent_2_prompt
from utils import (
    count_message_tokens,
    count_text_tokens,
    gen_graph_by_codeunits,
    get_available_text_token_budget,
    get_effective_max_input_tokens,
    write_file,
)


PASS_CONCLUSIONS = {"审计通过", "结构化审计通过结果", "审核通过"}


def _estimate_message_tokens(prompt: str, text: str) -> int:
    return count_message_tokens([
        {"role": "system", "content": prompt},
        {"role": "user", "content": text},
    ])


def _resolve_agent_1_chunk_token_size() -> int:
    effective_input_limit = get_effective_max_input_tokens()
    prompt_candidates = [build_agent_1_prompt(ext) for ext in C.project.source_file_ext] or [build_agent_1_prompt(".txt")]
    prompt_budget_candidates = [
        budget
        for budget in (get_available_text_token_budget(prompt) for prompt in prompt_candidates)
        if budget is not None
    ]
    if not prompt_budget_candidates:
        legacy_chunk_size = getattr(C.openai, "max_per_tokens", None)
        return legacy_chunk_size or 4096

    safe_chunk_size = min(prompt_budget_candidates)
    legacy_chunk_size = getattr(C.openai, "max_per_tokens", None)
    if legacy_chunk_size is not None:
        safe_chunk_size = min(safe_chunk_size, legacy_chunk_size)

    if effective_input_limit is not None:
        logger.warning(
            "模型 {} 的输入上限为 {} tokens，源码分片预算已自动计算为 {} tokens",
            C.openai.model,
            effective_input_limit,
            safe_chunk_size,
        )
    return safe_chunk_size


def _build_incomplete_audit_report(total_tasks: int, failed_tasks: int, threshold: float) -> str:
    failure_rate = (failed_tasks / total_tasks) if total_tasks else 0.0
    return (
        "<审计报告>\n"
        "<结论>审计不完整</结论>\n"
        "<统计>\n"
        f"总任务数: {total_tasks}\n"
        f"失败任务数: {failed_tasks}\n"
        f"失败率: {failure_rate:.2%}\n"
        f"阈值: {threshold:.2%}\n"
        "</统计>\n"
        "<说明>\n"
        "本次 Agent_2 审计阶段存在较高比例的大模型请求失败，当前结果不应视为“审计通过”。\n"
        "建议检查网络连通性、代理服务稳定性或降低并发后重新执行审计。\n"
        "</说明>\n"
        "</审计报告>"
    )


def _collect_payload_extensions(graph: nx.DiGraph, nodes: list[str]) -> list[str]:
    extensions = []
    for node in nodes:
        path = str(graph.nodes[node].get("path", "") or "")
        ext = os.path.splitext(path)[1].lower()
        if ext and ext not in extensions:
            extensions.append(ext)
    return sorted(extensions)


def _truncate_text(text: str, max_chars: int) -> str:
    if not text or len(text) <= max_chars:
        return text
    if max_chars < 200:
        return text[:max_chars]
    half = max_chars // 2
    return text[:half] + "\n\n...[源码过长，已截断中间部分]...\n\n" + text[-half:]


def _is_low_value_bundle_node(node: str, node_data: dict) -> bool:
    path = str(node_data.get("path") or node).replace("\\", "/").lower()
    name = str(node_data.get("source_name") or node.rsplit("|", 1)[-1])
    bundle_markers = (
        "/public/js/app.js",
        "/public/js/vendor",
        ".min.js",
        "/dist/",
        "/third-party/",
        "/node_modules/",
        "/bower_components/",
    )
    if any(marker in path for marker in bundle_markers):
        return True
    # 压缩后的短函数名，通常来自打包产物
    if path.endswith(".js") and len(name) <= 2 and name.isidentifier():
        return True
    return False


def _fit_agent_2_tree_payload(graph: nx.DiGraph, tree: dict):
    root = tree["root"]
    root_code = str(graph.nodes[root].get("source_code") or "")
    degree = graph.in_degree(root) + graph.out_degree(root)
    if len(root_code) > 20000 or degree > 80:
        logger.info("跳过超大或高连接依赖树适配: {}", root)
        return None, None

    payload = gen_text_from_dependency_tree(graph, tree)
    if len(payload) > 80000:
        payload = payload[:80000]
    extensions = _collect_payload_extensions(graph, tree["nodes"])
    prompt = build_agent_2_prompt(extensions)
    message_tokens = _estimate_message_tokens(prompt, payload)
    max_input_tokens = get_effective_max_input_tokens()
    if max_input_tokens is None or message_tokens <= max_input_tokens:
        return payload, message_tokens

    # 超限时直接截断一次，不再对大文本做多次 replace
    truncated_payload = payload[: max(4000, len(payload) // 3)]
    message_tokens = _estimate_message_tokens(prompt, truncated_payload)
    if max_input_tokens is None or message_tokens <= max_input_tokens:
        return truncated_payload, message_tokens
    return None, None


def _tree_candidate_score(graph: nx.DiGraph, tree: dict) -> int:
    score = 0
    branch_bonus = 0
    input_count = 0
    sink_count = 0
    validation_count = 0
    safety_count = 0
    for node in tree["nodes"]:
        node_data = graph.nodes[node]
        profile = get_security_hint_profile(node_data)
        input_count += profile["input_count"]
        sink_count += profile["sink_count"]
        validation_count += profile["validation_count"]
        safety_count += profile["safety_count"]
        score += security_hint_score(node_data) * 5
        score += graph.in_degree(node) + graph.out_degree(node)
        score += max(1, len(str(node_data.get("source_code", "")).splitlines()))

    for branch in tree["branches"]:
        branch_path = branch["path"]
        branch_bonus += min(120, len(branch_path) * 15)
        if branch["direction"] == "downstream":
            branch_bonus += 20

    score += branch_bonus
    score += input_count * 25 + sink_count * 35 + validation_count * 8 + safety_count * 5
    if input_count > 0 and sink_count > 0:
        score += 200
    if input_count > 0 and sink_count > 0 and validation_count == 0 and safety_count == 0:
        score += 150
    return score


def _candidate_precheck_score(graph: nx.DiGraph, node: str) -> tuple[int, dict]:
    # 预筛只看节点自身线索和度数，不做局部子图遍历。
    # 局部遍历在高连接第三方库节点上会极慢，不适合作为全图扫描。
    node_data = graph.nodes[node]
    profile = get_security_hint_profile(node_data)
    degree = graph.in_degree(node) + graph.out_degree(node)
    score = (
        profile["input_count"] * 8
        + profile["sink_count"] * 10
        + profile["validation_count"] * 3
        + profile["safety_count"] * 2
        + min(20, degree)
    )
    local_summary = {
        "input_nodes": int(profile["has_input"]),
        "sink_nodes": int(profile["has_sink"]),
        "validation_nodes": int(profile["has_validation"]),
        "safety_nodes": int(profile["has_safety"]),
        "combined_risk_nodes": int(profile["has_input"] and profile["has_sink"]),
        "local_nodes": [node],
    }
    return score, {"profile": profile, "local_summary": local_summary}


def _is_high_value_audit_candidate(graph: nx.DiGraph, node: str) -> tuple[bool, int]:
    score, context = _candidate_precheck_score(graph, node)
    profile = context["profile"]
    local_summary = context["local_summary"]
    raw_threshold = getattr(C.project, "agent2_candidate_score_threshold", 12)
    if raw_threshold is not None and raw_threshold < 0:
        return True, score
    threshold = max(1, raw_threshold)

    has_direct_signal = profile["has_input"] or profile["has_sink"] or profile["has_validation"] or profile["has_safety"]
    has_local_risk_chain = (
        local_summary["combined_risk_nodes"] > 0
        or (local_summary["input_nodes"] > 0 and local_summary["sink_nodes"] > 0)
    )
    return has_direct_signal or has_local_risk_chain or score >= threshold, score


def _fit_light_payload(graph: nx.DiGraph, center_node: str):
    node_data = dict(graph.nodes[center_node])
    original = str(node_data.get("source_code") or "")
    if len(original) > 8000:
        node_data["source_code"] = _truncate_text(original, 4000)
    payload = _format_node(0, node_data)
    extensions = _collect_payload_extensions(graph, [center_node])
    prompt = build_agent_2_prompt(extensions)
    message_tokens = _estimate_message_tokens(prompt, payload)
    max_input_tokens = get_effective_max_input_tokens()
    if max_input_tokens is None or message_tokens <= max_input_tokens:
        return payload, [center_node], message_tokens
    return _fit_truncated_only(graph, center_node, node_data, str(node_data.get("source_code") or ""))


def _append_node_payload(
    payload_candidates,
    payload_signature_counts,
    context_signature_counts,
    node_dedup_limit,
    graph,
    node,
    node_data,
    payload,
    local_nodes,
    message_tokens,
    prescreen_score,
):
    payload_signature = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    payload_kept_count = payload_signature_counts.get(payload_signature, 0)
    if node_dedup_limit >= 0 and payload_kept_count >= max(1, node_dedup_limit):
        return

    center_signature = hashlib.sha256(
        "||".join([
            node_data.get("path", ""),
            node_data.get("source_name", ""),
            node_data.get("target_name", ""),
            node_data.get("desc", ""),
            node_data.get("source_code", ""),
            ",".join(sorted(local_nodes)),
        ]).encode("utf-8")
    ).hexdigest()
    context_kept_count = context_signature_counts.get(center_signature, 0)
    if node_dedup_limit >= 0 and context_kept_count >= max(1, node_dedup_limit):
        return

    payload_signature_counts[payload_signature] = payload_kept_count + 1
    context_signature_counts[center_signature] = context_kept_count + 1
    payload_candidates.append({
        "payload": payload,
        "score": (
            security_hint_score(node_data) * 5
            + graph.in_degree(node)
            + graph.out_degree(node)
            + len(local_nodes) * 2
            + max(1, len(node_data.get("source_code", "").splitlines()))
            + prescreen_score
        ),
        "tokens": message_tokens if message_tokens is not None else count_text_tokens(payload),
    })


def _fit_agent_2_payload(graph: nx.DiGraph, center_node: str):
    max_depth = max(1, C.project.audit_context_depth)
    max_nodes = max(1, C.project.max_audit_nodes)
    node_data = dict(graph.nodes[center_node])
    original = str(node_data.get("source_code") or "")

    # 超大源码直接走截断路径，避免反复尝试耗时
    if len(original) > 15000:
        return _fit_truncated_only(graph, center_node, node_data, original)

    for depth in range(max_depth, 0, -1):
        for node_limit in range(max_nodes, 0, -1):
            ordered_nodes = get_local_subgraph_nodes(
                graph,
                center_node,
                max_depth=depth,
                max_nodes=node_limit,
            )
            payload = gen_text_from_local_subgraph(
                graph,
                center_node,
                max_depth=depth,
                max_nodes=node_limit,
            )
            extensions = _collect_payload_extensions(graph, ordered_nodes)
            prompt = build_agent_2_prompt(extensions)
            message_tokens = _estimate_message_tokens(prompt, payload)
            max_input_tokens = get_effective_max_input_tokens()
            if max_input_tokens is None or message_tokens <= max_input_tokens:
                return payload, ordered_nodes, message_tokens

    return _fit_truncated_only(graph, center_node, node_data, original)


def _fit_truncated_only(graph, center_node, node_data, original):
    extensions = _collect_payload_extensions(graph, [center_node])
    prompt = build_agent_2_prompt(extensions)
    max_input_tokens = get_effective_max_input_tokens()

    for ratio in (0.4, 0.2, 0.1, 0.05):
        truncated = _truncate_text(original, max(600, int(len(original) * ratio) or 600))
        node_data = dict(node_data)
        node_data["source_code"] = truncated
        payload = _format_node(0, node_data)
        message_tokens = _estimate_message_tokens(prompt, payload)
        if max_input_tokens is None or message_tokens <= max_input_tokens:
            logger.debug("节点源码已截断以适配模型限制: {}", center_node)
            return payload, [center_node], message_tokens
    return None, [], None


def calculate_project_hash(root_dir) -> str:
    hash_object = hashlib.sha256()
    queue = deque([root_dir])
    while queue:
        current = queue.popleft()
        for file in sorted(current.source_files, key=lambda item: item.path):
            hash_object.update(file.path.encode("utf-8"))
            hash_object.update(file.extension.encode("utf-8"))
            hash_object.update(file.source_code.encode("utf-8"))
        for sub_dir in sorted(current.source_dirs, key=lambda item: item.path):
            queue.append(sub_dir)
    return hash_object.hexdigest()


async def async_run_agent_1(source_file_list: List[SourceFile], out_file, batch_size=10):
    logger.info("Agent_1 开始执行，文件分片数: {}", len(source_file_list))
    batches = [source_file_list[i:i + batch_size] for i in range(0, len(source_file_list), batch_size)]
    res_list = []
    failed_count = 0
    for batch in tqdm(batches, total=len(batches), desc="Agent_1 执行中..."):
        tasks = [asyncio.create_task(agent_1(source_file)) for source_file in batch]
        result_list = await asyncio.gather(*tasks, return_exceptions=True)
        for result in result_list:
            if isinstance(result, Exception):
                failed_count += 1
                logger.warning("Agent_1 任务失败并已隔离: {}", result)
                continue
            if result is None:
                continue
            res_list.extend(result)

    graph = gen_graph_by_codeunits(res_list)
    nx.write_graphml(graph, out_file)
    logger.info("Agent_1 计算完毕，输出文件:{}，失败任务数:{}", out_file, failed_count)


def build_audit_payloads(graph: nx.DiGraph) -> List[str]:
    payload_candidates = []
    tree_payload_candidates = []
    prescreen_threshold = getattr(C.project, "agent2_candidate_score_threshold", 12)
    prescreen_disabled = prescreen_threshold is not None and prescreen_threshold < 0
    tree_dedup_limit = int(getattr(C.project, "agent2_tree_payload_dedup_limit", 1))
    node_dedup_limit = int(getattr(C.project, "agent2_node_payload_dedup_limit", 1))
    final_dedup_limit = int(getattr(C.project, "agent2_final_payload_dedup_limit", 1))
    tree_signature_counts = {}
    payload_signature_counts = {}
    context_signature_counts = {}
    merged_payload_counts = {}
    skipped_oversize_count = 0
    skipped_prescreen_count = 0
    prescreened_nodes = []

    total_nodes = graph.number_of_nodes()
    logger.info("Agent_2 开始构建审计任务，图节点数: {}", total_nodes)

    logger.info("正在计算全局依赖树...")
    configured_max_trees = int(getattr(C.project, "agent2_max_trees", 0))
    # 0 表示按规模自动放宽，不再写死 30
    auto_max_trees = max(80, min(total_nodes, 160))
    max_trees = configured_max_trees if configured_max_trees > 0 else auto_max_trees
    ranked_trees = get_global_ranked_dependency_trees(
        graph,
        max_depth=max(1, C.project.audit_context_depth),
        max_nodes=max(1, C.project.max_audit_nodes),
        max_trees=max_trees,
    )
    logger.info("依赖树计算完成，共 {} 棵，开始筛选与适配...", len(ranked_trees))
    skipped_bundle_count = 0

    for tree_idx, tree in enumerate(ranked_trees, 1):
        root_data = graph.nodes[tree["root"]]
        if _is_low_value_bundle_node(tree["root"], root_data):
            skipped_bundle_count += 1
            if skipped_bundle_count <= 5 or skipped_bundle_count % 20 == 0:
                logger.info("跳过打包/压缩产物依赖树: {}", tree["root"])
            continue
        logger.info("依赖树处理进度: {}/{}，根节点: {}", tree_idx, len(ranked_trees), tree["root"])
        is_candidate, prescreen_score = _is_high_value_audit_candidate(graph, tree["root"])
        if not prescreen_disabled and not is_candidate:
            continue
        payload, message_tokens = _fit_agent_2_tree_payload(graph, tree)
        if not payload:
            continue
        payload_signature = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        tree_kept_count = tree_signature_counts.get(payload_signature, 0)
        if tree_dedup_limit >= 0 and tree_kept_count >= max(1, tree_dedup_limit):
            continue
        tree_signature_counts[payload_signature] = tree_kept_count + 1
        tree_payload_candidates.append({
            "payload": payload,
            "score": _tree_candidate_score(graph, tree) + prescreen_score,
            "tokens": message_tokens if message_tokens is not None else count_text_tokens(payload),
            "root": root_data.get("source_name", tree["root"]),
        })
    logger.info("依赖树适配完成，跳过打包产物 {} 棵，保留 {} 棵", skipped_bundle_count, len(tree_payload_candidates))

    logger.info("开始逐节点快速预筛...")
    nodes_with_code = [n for n in graph.nodes if graph.nodes[n].get("source_code")]
    scored_nodes = []
    for node_idx, node in enumerate(nodes_with_code, 1):
        if node_idx % 200 == 0 or node_idx == len(nodes_with_code):
            logger.info("快速预筛进度: {}/{}，当前: {}", node_idx, len(nodes_with_code), node)
        is_candidate, prescreen_score = _is_high_value_audit_candidate(graph, node)
        scored_nodes.append((node, prescreen_score, is_candidate))
        if not prescreen_disabled and not is_candidate:
            skipped_prescreen_count += 1

    full_fit_limit = int(getattr(C.project, "agent2_full_fit_limit", 80))
    light_fit_limit = int(getattr(C.project, "agent2_light_fit_limit", 200))
    candidates_to_fit = [
        (node, score) for node, score, is_cand in scored_nodes
        if prescreen_disabled or is_cand
    ]
    candidates_to_fit.sort(key=lambda x: -x[1])
    full_fit = candidates_to_fit[:full_fit_limit] if full_fit_limit > 0 else candidates_to_fit
    remaining = candidates_to_fit[len(full_fit):]
    light_fit = remaining[:light_fit_limit] if light_fit_limit > 0 else remaining
    logger.info(
        "预筛完成，完整上下文 {} 个，轻量审计 {} 个（候选共 {}）",
        len(full_fit),
        len(light_fit),
        len(candidates_to_fit),
    )

    for fit_idx, (node, prescreen_score) in enumerate(full_fit, 1):
        if fit_idx % 5 == 0 or fit_idx == len(full_fit):
            logger.info("完整上下文适配进度: {}/{}", fit_idx, len(full_fit))
        node_data = graph.nodes[node]
        if _is_low_value_bundle_node(node, node_data):
            continue
        payload, local_nodes, message_tokens = _fit_agent_2_payload(graph, node)
        if not payload:
            skipped_oversize_count += 1
            logger.warning("Agent_2 上下文与截断回退均无法适配模型限制，已跳过节点: {}", node)
            continue
        _append_node_payload(
            payload_candidates,
            payload_signature_counts,
            context_signature_counts,
            node_dedup_limit,
            graph,
            node,
            node_data,
            payload,
            local_nodes,
            message_tokens,
            prescreen_score,
        )

    for fit_idx, (node, prescreen_score) in enumerate(light_fit, 1):
        if fit_idx % 20 == 0 or fit_idx == len(light_fit):
            logger.info("轻量审计进度: {}/{}", fit_idx, len(light_fit))
        node_data = graph.nodes[node]
        if _is_low_value_bundle_node(node, node_data):
            continue
        payload, local_nodes, message_tokens = _fit_light_payload(graph, node)
        if not payload:
            continue
        _append_node_payload(
            payload_candidates,
            payload_signature_counts,
            context_signature_counts,
            node_dedup_limit,
            graph,
            node,
            node_data,
            payload,
            local_nodes,
            message_tokens,
            prescreen_score,
        )

    # 兼容后续放宽逻辑使用的变量
    prescreened_nodes = scored_nodes

    source_nodes = [node for node in graph.nodes if graph.nodes[node].get("source_code")]
    # 大图时降低最低候选数，避免放宽阶段再次遍历过多节点
    minimum_candidate_count = min(
        80,
        len(source_nodes),
        max(10, max(1, len(source_nodes) // 10)),
    )

    if not prescreen_disabled and len(payload_candidates) < minimum_candidate_count:
        prescreened_nodes.sort(key=lambda item: (-item[1], str(item[0])))
        logger.warning(
            "Agent_2 预筛选结果较严格，已自动放宽候选保留数量: current={} minimum={}",
            len(payload_candidates),
            minimum_candidate_count,
        )
        for node, prescreen_score, already_selected in prescreened_nodes:
            if len(payload_candidates) >= minimum_candidate_count:
                break
            if already_selected:
                continue
            node_data = graph.nodes[node]
            payload, local_nodes, message_tokens = _fit_agent_2_payload(graph, node)
            if not payload:
                continue
            payload_signature = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            payload_kept_count = payload_signature_counts.get(payload_signature, 0)
            if node_dedup_limit >= 0 and payload_kept_count >= max(1, node_dedup_limit):
                continue
            center_signature = hashlib.sha256(
                "||".join([
                    node_data.get("path", ""),
                    node_data.get("source_name", ""),
                    node_data.get("target_name", ""),
                    node_data.get("desc", ""),
                    node_data.get("source_code", ""),
                    ",".join(sorted(local_nodes)),
                ]).encode("utf-8")
            ).hexdigest()
            context_kept_count = context_signature_counts.get(center_signature, 0)
            if node_dedup_limit >= 0 and context_kept_count >= max(1, node_dedup_limit):
                continue

            payload_signature_counts[payload_signature] = payload_kept_count + 1
            context_signature_counts[center_signature] = context_kept_count + 1
            payload_candidates.append({
                "payload": payload,
                "score": (
                    security_hint_score(node_data) * 5 +
                    graph.in_degree(node) +
                    graph.out_degree(node) +
                    len(local_nodes) * 2 +
                    max(1, len(node_data.get("source_code", "").splitlines())) +
                    prescreen_score
                ),
                "tokens": message_tokens if message_tokens is not None else count_text_tokens(payload),
            })

    tree_payload_candidates.sort(key=lambda item: (-item["score"], -item["tokens"]))
    payload_candidates.sort(key=lambda item: (-item["score"], -item["tokens"]))
    if not payload_candidates:
        logger.warning("Agent_2 预筛选后无候选节点，已回退为有限高分节点模式")
        fallback_nodes = [item[0] for item in sorted(scored_nodes, key=lambda x: -x[1])[:100]]
        for node in fallback_nodes:
            node_data = graph.nodes[node]
            payload, local_nodes, message_tokens = _fit_agent_2_payload(graph, node)
            if not payload:
                continue
            payload_candidates.append({
                "payload": payload,
                "score": (
                    security_hint_score(node_data) * 5
                    + graph.in_degree(node)
                    + graph.out_degree(node)
                    + len(local_nodes) * 2
                    + max(1, len(node_data.get("source_code", "").splitlines()))
                ),
                "tokens": message_tokens if message_tokens is not None else count_text_tokens(payload),
            })
        payload_candidates.sort(key=lambda item: (-item["score"], -item["tokens"]))

    merged_candidates = tree_payload_candidates + payload_candidates
    merged_candidates.sort(key=lambda item: (-item["score"], -item["tokens"]))

    payloads = []
    for item in merged_candidates:
        signature = hashlib.sha256(item["payload"].encode("utf-8")).hexdigest()
        merged_kept_count = merged_payload_counts.get(signature, 0)
        if final_dedup_limit >= 0 and merged_kept_count >= max(1, final_dedup_limit):
            continue
        merged_payload_counts[signature] = merged_kept_count + 1
        payloads.append(item)

    # 默认不截断。仅当用户显式设置正数上限时才限制，避免为速度丢失覆盖。
    max_payloads = int(getattr(C.project, "agent2_max_payloads", 0))
    max_per_file = int(getattr(C.project, "agent2_max_per_file", 0))
    if max_payloads > 0 and len(payloads) > max_payloads:
        payloads = _select_diverse_payloads(payloads, max_payloads, max_per_file)
        logger.warning(
            "Agent_2 任务数超过显式上限 {}，已保留 {} 个（单文件最多 {}；0 表示不限制单文件）",
            max_payloads,
            len(payloads),
            max_per_file,
        )
    else:
        logger.info("Agent_2 未启用任务数上限，全部 {} 个去重任务将送审", len(payloads))

    payload_texts = [item["payload"] for item in payloads]
    logger.info(
        "Agent_2 任务压缩完成，候选节点:{}，候选依赖树数:{}，预筛选跳过节点数:{}，去重后任务数:{}，超限跳过节点数:{}，预筛选关闭:{}，树去重上限:{}，节点去重上限:{}，最终去重上限:{}",
        graph.number_of_nodes(),
        len(tree_payload_candidates),
        skipped_prescreen_count,
        len(payload_texts),
        skipped_oversize_count,
        prescreen_disabled,
        tree_dedup_limit,
        node_dedup_limit,
        final_dedup_limit,
    )
    return payload_texts


def _extract_payload_file(payload: str) -> str:
    match = re.search(r"源码路径:([^\n]+)", payload)
    if match:
        return match.group(1).strip()
    return "unknown"


def _select_diverse_payloads(candidates: list[dict], max_payloads: int, max_per_file: int) -> list[dict]:
    selected = []
    file_counts = {}
    deferred = []
    for item in candidates:
        file_key = _extract_payload_file(item["payload"])
        count = file_counts.get(file_key, 0)
        if max_per_file > 0 and count >= max_per_file:
            deferred.append(item)
            continue
        selected.append(item)
        file_counts[file_key] = count + 1
        if max_payloads > 0 and len(selected) >= max_payloads:
            return selected
    if max_payloads <= 0:
        return selected + deferred
    for item in deferred:
        if len(selected) >= max_payloads:
            break
        selected.append(item)
    return selected


def normalize_report_text(report: str) -> str:
    if report is None:
        return ""
    normalized = report.strip()
    if normalized == "结构化审计通过结果":
        return "<审计报告>\n<结论>审计通过</结论>\n</审计报告>"
    return normalized


def is_pass_only_report(report: str) -> bool:
    normalized = normalize_report_text(report)
    if not normalized:
        return True
    if "<文件>" in normalized and "<漏洞>" in normalized:
        return False
    if normalized == "<审计通过>":
        return True

    conclusion_matches = re.findall(r"<结论>\s*(.*?)\s*</结论>", normalized, flags=re.DOTALL)
    if conclusion_matches and all(match.strip() in PASS_CONCLUSIONS for match in conclusion_matches):
        return True
    return normalized in PASS_CONCLUSIONS


async def async_run_agent_2(graph: nx.DiGraph, out_file, batch_size=10):
    payloads = build_audit_payloads(graph)
    logger.info("Agent_2 开始执行，局部上下文任务数: {}", len(payloads))
    if not payloads:
        empty_report = "<审计报告>\n<结论>审计通过</结论>\n</审计报告>"
        write_file(out_file, empty_report)
        logger.warning("Agent_2 未生成可审计任务，已输出占位报告: {}", out_file)
        return

    batches = [payloads[i:i + batch_size] for i in range(0, len(payloads), batch_size)]
    reports = []
    failed_count = 0
    filtered_pass_count = 0
    total_tasks = len(payloads)
    failure_rate_threshold = max(0.0, min(1.0, getattr(C.project, "agent2_failure_rate_threshold", 0.3)))

    for batch in tqdm(batches, total=len(batches), desc="Agent_2 执行中..."):
        tasks = [asyncio.create_task(agent_2(payload)) for payload in batch]
        result_list = await asyncio.gather(*tasks, return_exceptions=True)
        for result in result_list:
            if isinstance(result, Exception):
                failed_count += 1
                logger.warning("Agent_2 任务失败并已隔离: {}", result)
                continue
            if result is None:
                continue
            normalized = normalize_report_text(result)
            if is_pass_only_report(normalized):
                filtered_pass_count += 1
                continue
            reports.append(normalized)
        write_file(
            out_file,
            "\n--------------------------------\n".join(reports)
            if reports
            else "<审计报告>\n<结论>审计通过</结论>\n</审计报告>",
        )

    failure_rate = (failed_count / total_tasks) if total_tasks else 0.0
    is_incomplete = failed_count > 0 and failure_rate >= failure_rate_threshold

    if is_incomplete:
        incomplete_report = _build_incomplete_audit_report(total_tasks, failed_count, failure_rate_threshold)
        final_report = incomplete_report
        if reports:
            final_report += "\n--------------------------------\n" + "\n--------------------------------\n".join(reports)
        write_file(out_file, final_report)
        logger.warning(
            "Agent_2 失败率过高，结果已标记为审计不完整: total_tasks={} failed_tasks={} failure_rate={:.2%} threshold={:.2%}",
            total_tasks,
            failed_count,
            failure_rate,
            failure_rate_threshold,
        )
    elif not reports and not os.path.exists(out_file):
        write_file(out_file, "<审计报告>\n<结论>审计通过</结论>\n</审计报告>")

    logger.info(
        "Agent_2 计算完毕，输出文件:{}，失败任务数:{}，失败率:{:.2%}，过滤通过结果数:{}，保留风险结果数:{}",
        out_file,
        failed_count,
        failure_rate,
        filtered_pass_count,
        len(reports),
    )


def run_audit(project_dir: str, output_dir: str, batch_size: int = 10):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    root_dir = scan_project_struct(project_dir)
    project_hash = calculate_project_hash(root_dir)
    logger.info("扫描完成，项目内容哈希: {}", project_hash)
    logger.debug("解析目录结构如下\n{}", print_source_dir(root_dir))

    graph_path = os.path.join(output_dir, f"{project_hash}.graphml")
    report_path = os.path.join(output_dir, f"{project_hash}_审计结果.log")

    if not os.path.exists(graph_path):
        source_file_list = get_all_source_files_bfs(root_dir, chunk_token_size=_resolve_agent_1_chunk_token_size())
        logger.info("调用异步处理 Agent_1...")
        asyncio.run(async_run_agent_1(source_file_list, out_file=graph_path, batch_size=batch_size))
    else:
        logger.info("项目依赖解析文件存在，直接跳过")

    logger.info("调用异步处理 Agent_2...")
    graph = nx.read_graphml(graph_path)
    asyncio.run(async_run_agent_2(graph, out_file=report_path, batch_size=batch_size))
    logger.success("输出成功，请在目录:{}查看", output_dir)

    return {
        "project_hash": project_hash,
        "graph_path": graph_path,
        "report_path": report_path,
        "output_dir": output_dir,
    }
