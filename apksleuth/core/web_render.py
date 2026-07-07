from __future__ import annotations

import json
import time
from html import escape
from typing import Any

from apksleuth.core.web_jobs import active_jobs as _active_jobs
from apksleuth.core.web_jobs import job_payload as _job_payload
from apksleuth.core.web_models import WebConfig, WebJob


def _render_index(config: WebConfig) -> str:
    return _page(
        "ApkSleuth Web UI",
        f"""
        <section class="hero">
          <p class="eyebrow">Local-first APK analysis</p>
          <h1>ApkSleuth 本地分析台</h1>
          <p>上传 APK 或填写本机路径，分析会在本机完成，不会上传到云端。</p>
        </section>
        <section>
          <h2>开始分析</h2>
          <form action="/scan" method="post" enctype="multipart/form-data">
            <label>上传 APK（可多选）</label>
            <input type="file" name="apk" accept=".apk,application/vnd.android.package-archive" multiple>
            <label>或填写本机 APK 路径（每行一个）</label>
            <textarea name="apk_path" placeholder="C:\\path\\to\\app.apk"></textarea>
            <button type="submit">开始分析</button>
          </form>
        </section>
        {_render_active_jobs(config)}
        {_render_history_section(_recent_analyses(config))}
        """,
    )


def _render_active_jobs(config: WebConfig) -> str:
    jobs = _active_jobs(config)
    if not jobs:
        return ""
    rows = "".join(_active_job_row(job) for job in jobs)
    return f"""
        <section>
          <h2>当前任务</h2>
          <div class="table-wrap">
            <table>
              <thead><tr><th>APK</th><th>任务 ID</th><th>状态</th><th>当前步骤</th><th>结果</th></tr></thead>
              <tbody id="active-jobs-body">{rows}</tbody>
            </table>
          </div>
        </section>
        {_active_jobs_script()}
        """


def _active_job_row(job: WebJob) -> str:
    analysis_link = f'<a href="/analysis/{escape(job.job_id)}">查看</a>' if job.status == "done" else ""
    return (
        f'<tr data-active-job-row data-job-id="{escape(job.job_id, quote=True)}">'
        f"<td>{escape(job.apk_name)}</td>"
        f"<td><code>{escape(job.job_id)}</code></td>"
        f'<td data-job-status>{escape(job.status)}</td>'
        f'<td data-job-message>{escape(job.message)}</td>'
        f'<td data-job-result>{analysis_link}</td>'
        "</tr>"
    )


def _active_jobs_script() -> str:
    return """
        <script>
        (() => {
          const rows = Array.from(document.querySelectorAll('[data-active-job-row]'));
          if (!rows.length) return;
          async function poll(row) {
            const jobId = row.dataset.jobId;
            if (!jobId) return;
            try {
              const response = await fetch(`/api/jobs/${jobId}`, { cache: 'no-store' });
              const data = await response.json();
              const status = row.querySelector('[data-job-status]');
              const message = row.querySelector('[data-job-message]');
              const result = row.querySelector('[data-job-result]');
              if (status) status.textContent = data.status || 'unknown';
              if (message) message.textContent = data.message || '';
              if (result && data.status === 'done') result.innerHTML = `<a href="${data.analysis_url || `/analysis/${jobId}`}">查看</a>`;
              if (data.status !== 'done' && data.status !== 'error' && data.status !== 'missing') setTimeout(() => poll(row), 1200);
            } catch (error) {
              setTimeout(() => poll(row), 2000);
            }
          }
          rows.forEach((row) => poll(row));
        })();
        </script>
        """


def _render_history_section(analyses: list[dict[str, Any]]) -> str:
    rows = "".join(_history_row(item) for item in analyses)
    if not rows:
        return '<section><h2>报告历史</h2><p class="muted">暂无历史分析记录。</p></section>'
    return f"""
        <section class="history">
          <h2>报告历史</h2>
          <div class="history-toolbar">
            <label>搜索历史分析结果
              <input id="history-search" type="search" placeholder="应用名、包名、版本、SHA256、风险规则...">
            </label>
            <label>排序
              <select id="history-sort">
                <option value="newest">按时间最新</option>
                <option value="risk">按综合风险</option>
                <option value="high">按高危数量</option>
                <option value="medium">按中危数量</option>
                <option value="total">按风险总数</option>
                <option value="name">按应用名</option>
              </select>
            </label>
          </div>
          <p id="history-count" class="muted"></p>
          <div class="table-wrap">
            <table>
              <thead><tr><th>应用</th><th>包名</th><th>版本</th><th>高危</th><th>中危</th><th>低危</th><th>总数</th><th>时间</th><th>操作</th></tr></thead>
              <tbody id="history-body">
                {rows}
                <tr id="history-empty-row" class="empty-row" hidden><td colspan="9">没有匹配的历史分析结果。</td></tr>
              </tbody>
            </table>
          </div>
          <p class="muted">删除历史记录会移除本地生成的报告目录和上传副本，不会删除本机路径中的原始 APK。</p>
        </section>
        {_history_script()}
        """


def _history_script() -> str:
    return """
        <script>
        (() => {
          const input = document.getElementById('history-search');
          const sort = document.getElementById('history-sort');
          const tbody = document.getElementById('history-body');
          const count = document.getElementById('history-count');
          if (!tbody) return;
          const rows = Array.from(tbody.querySelectorAll('[data-history-row]'));
          const empty = document.getElementById('history-empty-row');
          const number = (row, key) => Number(row.dataset[key] || 0);

          function compareRows(a, b) {
            const mode = sort ? sort.value : 'newest';
            if (mode === 'risk') {
              return number(b, 'high') - number(a, 'high') || number(b, 'medium') - number(a, 'medium') || number(b, 'total') - number(a, 'total') || number(b, 'updated') - number(a, 'updated');
            }
            if (mode === 'high' || mode === 'medium' || mode === 'total') {
              return number(b, mode) - number(a, mode) || number(b, 'updated') - number(a, 'updated');
            }
            if (mode === 'name') {
              return (a.dataset.name || '').localeCompare(b.dataset.name || '', 'zh-Hans');
            }
            return number(b, 'updated') - number(a, 'updated');
          }

          function applyHistoryFilters() {
            const query = (input ? input.value : '').trim().toLowerCase();
            let visible = 0;
            rows.sort(compareRows).forEach((row) => {
              const matched = !query || (row.dataset.search || '').includes(query);
              row.hidden = !matched;
              if (matched) visible += 1;
              tbody.appendChild(row);
            });
            if (empty) empty.hidden = visible !== 0;
            if (count) count.textContent = `显示 ${visible} / ${rows.length} 条历史记录`;
          }

          if (input) input.addEventListener('input', applyHistoryFilters);
          if (sort) sort.addEventListener('change', applyHistoryFilters);
          applyHistoryFilters();
        })();
        </script>
        """


def _render_job(config: WebConfig, job_id: str) -> str:
    payload = _job_payload(config, job_id)
    if payload.get("status") == "missing":
        return _render_error("任务不存在", "Job was not found.")
    return _page(
        "ApkSleuth 分析任务",
        f"""
        <section class="hero">
          <p class="eyebrow">Analysis job</p>
          <h1>正在分析 APK</h1>
          <p>任务 ID：<code>{escape(job_id)}</code></p>
        </section>
        <section>
          <h2>任务状态</h2>
          <div class="status-box">
            <div><span>状态</span><strong id="job-status">{escape(str(payload.get('status') or 'pending'))}</strong></div>
            <div><span>当前步骤</span><strong id="job-message">{escape(str(payload.get('message') or '等待分析'))}</strong></div>
          </div>
          <progress id="job-progress" max="100"></progress>
          <p id="job-error" class="error" hidden></p>
          <p id="job-link" hidden><a class="button-link" href="/analysis/{escape(job_id)}">查看分析结果</a></p>
        </section>
        <p><a href="/">返回首页</a></p>
        <script>
        (() => {{
          const statusEl = document.getElementById('job-status');
          const messageEl = document.getElementById('job-message');
          const progressEl = document.getElementById('job-progress');
          const errorEl = document.getElementById('job-error');
          const linkEl = document.getElementById('job-link');
          let ticks = 0;
          async function poll() {{
            ticks += 1;
            try {{
              const response = await fetch('/api/jobs/{escape(job_id)}', {{ cache: 'no-store' }});
              const data = await response.json();
              statusEl.textContent = data.status || 'unknown';
              messageEl.textContent = data.message || '';
              if (progressEl && data.status !== 'done') progressEl.value = Math.min(95, 12 + ticks * 4);
              if (data.status === 'done') {{
                if (progressEl) progressEl.value = 100;
                if (linkEl) linkEl.hidden = false;
                window.location.href = data.analysis_url || '/analysis/{escape(job_id)}';
                return;
              }}
              if (data.status === 'error' || data.status === 'missing') {{
                if (errorEl) {{ errorEl.hidden = false; errorEl.textContent = data.error || data.message || '分析失败'; }}
                return;
              }}
              setTimeout(poll, 1000);
            }} catch (error) {{
              if (messageEl) messageEl.textContent = '等待服务响应...';
              setTimeout(poll, 1500);
            }}
          }}
          poll();
        }})();
        </script>
        """,
    )


def _render_analysis(config: WebConfig, job_id: str) -> str:
    report_dir = config.workdir / "reports" / job_id
    summary_path = report_dir / "report.summary.json"
    if not summary_path.exists():
        return _render_error("报告不存在", "Analysis report was not found.")
    data = json.loads(summary_path.read_text(encoding="utf-8"))
    apk = data.get("apk", {})
    risk = data.get("risk", {})
    confidence = data.get("confidence", {})
    signals = data.get("key_signals", {})
    links = "".join(
        f"<a class=\"button-link\" href=\"/files/{escape(job_id)}/{filename}\">{label}</a>"
        for label, filename in (
            ("HTML 报告", "report.html"),
            ("简报 Markdown", "report.summary.md"),
            ("结构化简报 JSON", "report.summary.json"),
            ("完整 JSON", "report.json"),
        )
    )
    return _page(
        f"{apk.get('app_name') or apk.get('file_name') or 'ApkSleuth'}",
        f"""
        <section class="hero">
          <p class="eyebrow">Analysis complete</p>
          <h1>{escape(apk.get('app_name') or apk.get('file_name') or 'APK')}</h1>
          <p><code>{escape(apk.get('package_name') or '')}</code> | {escape(apk.get('version_name') or '')} ({escape(apk.get('version_code') or '')})</p>
        </section>
        <section class="cards">
          <div><span>高危</span><strong>{risk.get('high', 0)}</strong></div>
          <div><span>中危</span><strong>{risk.get('medium', 0)}</strong></div>
          <div><span>低危</span><strong>{risk.get('low', 0)}</strong></div>
          <div><span>总风险项</span><strong>{risk.get('total', 0)}</strong></div>
          <div><span>高置信风险项</span><strong>{confidence.get('high', 0)}</strong></div>
          <div><span>需复核风险项</span><strong>{confidence.get('medium', 0)}</strong></div>
          <div><span>导出组件</span><strong>{signals.get('exported_components', 0)}</strong></div>
          <div><span>HTTP URL</span><strong>{signals.get('http_urls', 0)}</strong></div>
          <div><span>疑似密钥</span><strong>{signals.get('possible_secrets', 0)}</strong></div>
        </section>
        <section><h2>报告下载</h2><p class="links">{links}</p></section>
        {_render_analysis_findings(data.get('top_findings', []))}
        {_render_analysis_details(data)}
        <p><a href="/">返回首页</a></p>
        {_analysis_script()}
        """,
    )


def _render_analysis_findings(top_findings: object) -> str:
    rows = "".join(_analysis_finding_row(item) for item in _dict_items(top_findings))
    if not rows:
        rows = '<tr class="empty-row"><td colspan="8">没有风险项。</td></tr>'
    return f"""
        <section>
          <h2>主要风险项</h2>
          <div class="analysis-toolbar">
            <label>搜索风险项
              <input id="analysis-search" type="search" placeholder="规则、标题、证据、建议...">
            </label>
            <label>等级筛选
              <select id="analysis-severity">
                <option value="">全部</option>
                <option value="high">高危</option>
                <option value="medium">中危</option>
                <option value="low">低危</option>
                <option value="info">信息</option>
              </select>
            </label>
          </div>
          <p id="analysis-count" class="muted"></p>
          <div class="table-wrap">
            <table>
              <thead><tr><th>等级</th><th>可信度</th><th>规则</th><th>标题</th><th>数量</th><th>样例证据</th><th>建议</th><th>复核提示</th></tr></thead>
              <tbody id="analysis-findings-body">
                {rows}
                <tr id="analysis-empty-row" class="empty-row" hidden><td colspan="8">没有匹配的风险项。</td></tr>
              </tbody>
            </table>
          </div>
        </section>
        """


def _analysis_finding_row(item: dict[str, Any]) -> str:
    severity = _string(item.get("severity"))
    label = _string(item.get("severity_label") or severity)
    confidence = _string(item.get("confidence"))
    confidence_label = _string(item.get("confidence_label") or confidence)
    finding_id = _string(item.get("id"))
    title = _string(item.get("title"))
    evidence = _string(item.get("sample_evidence"))
    recommendation = _string(item.get("recommendation"))
    review_hint = _string(item.get("review_hint"))
    count = _string(item.get("count", 0))
    search_text = " ".join((severity, label, confidence, confidence_label, finding_id, title, evidence, recommendation, review_hint)).lower()
    return (
        f'<tr data-analysis-finding-row data-severity="{escape(severity, quote=True)}" data-search="{escape(search_text, quote=True)}">'
        f"<td><span class=\"badge {escape(severity, quote=True)}\">{escape(label)}</span></td>"
        f"<td>{escape(confidence_label)}</td>"
        f"<td><code>{escape(finding_id)}</code></td>"
        f"<td>{escape(title)}</td>"
        f"<td>{escape(count)}</td>"
        f"<td>{escape(evidence)}</td>"
        f"<td>{escape(recommendation)}</td>"
        f"<td>{escape(review_hint)}</td>"
        "</tr>"
    )


def _render_analysis_details(data: dict[str, Any]) -> str:
    return "".join(
        (
            _detail_section("高危权限", _simple_list(data.get("high_risk_permissions"), code=True), open_section=True),
            _detail_section("导出组件样例", _component_table(data.get("exported_component_samples")), open_section=True),
            _detail_section("HTTP URL 样例", _url_table(data.get("http_url_samples")), open_section=bool(data.get("http_url_samples"))),
            _detail_section("疑似密钥样例", _secret_table(data.get("possible_secret_samples"))),
            _detail_section("SDK 指纹", _fingerprint_table(data.get("sdks"), "type")),
            _detail_section("加固/混淆线索", _fingerprint_table(data.get("packers"), "confidence")),
            _detail_section("优先修复建议", _simple_list(data.get("recommendations")), open_section=True),
            _detail_section("分析说明", _simple_list(data.get("errors"))),
        )
    )


def _detail_section(title: str, body: str, open_section: bool = False) -> str:
    open_attr = " open" if open_section else ""
    return f'<details class="detail-section"{open_attr}><summary>{escape(title)}</summary><div class="detail-body">{body}</div></details>'


def _simple_list(items: object, code: bool = False) -> str:
    values = [_string(item) for item in items] if isinstance(items, list) else []
    values = [value for value in values if value]
    if not values:
        return '<p class="muted">无</p>'
    if code:
        return "<ul>" + "".join(f"<li><code>{escape(value)}</code></li>" for value in values) + "</ul>"
    return "<ul>" + "".join(f"<li>{escape(value)}</li>" for value in values) + "</ul>"


def _component_table(items: object) -> str:
    rows = []
    for item in _dict_items(items):
        rows.append(
            "<tr>"
            f"<td>{escape(_string(item.get('type')))}</td>"
            f"<td><code>{escape(_string(item.get('name')))}</code></td>"
            f"<td>{escape(_string(item.get('permission') or '无'))}</td>"
            f"<td>{escape(_string(item.get('exported')))}</td>"
            "</tr>"
        )
    return _table(("类型", "名称", "权限", "导出"), rows, "无导出组件样例。")


def _url_table(items: object) -> str:
    rows = []
    for item in _dict_items(items):
        rows.append(
            "<tr>"
            f"<td><code>{escape(_string(item.get('value')))}</code></td>"
            f"<td>{escape(_string(item.get('source')))}</td>"
            f"<td>{escape(_string(item.get('severity')))}</td>"
            "</tr>"
        )
    return _table(("URL", "来源", "等级"), rows, "未发现 HTTP URL 样例。")


def _secret_table(items: object) -> str:
    rows = []
    for item in _dict_items(items):
        rows.append(
            "<tr>"
            f"<td>{escape(_string(item.get('type')))}</td>"
            f"<td><code>{escape(_string(item.get('value')))}</code></td>"
            f"<td>{escape(_string(item.get('source')))}</td>"
            "</tr>"
        )
    return _table(("类型", "值", "来源"), rows, "未发现疑似密钥样例。")


def _fingerprint_table(items: object, extra_key: str) -> str:
    rows = []
    for item in _dict_items(items):
        patterns = ", ".join(_string(value) for value in item.get("matched_patterns", []) if value) if isinstance(item.get("matched_patterns"), list) else ""
        rows.append(
            "<tr>"
            f"<td>{escape(_string(item.get('name')))}</td>"
            f"<td>{escape(_string(item.get(extra_key)))}</td>"
            f"<td>{escape(patterns)}</td>"
            "</tr>"
        )
    return _table(("名称", "类型/可信度", "命中特征"), rows, "无。")


def _table(headers: tuple[str, ...], rows: list[str], empty_message: str) -> str:
    if not rows:
        return f'<p class="muted">{escape(empty_message)}</p>'
    header_html = "".join(f"<th>{escape(header)}</th>" for header in headers)
    return f'<div class="table-wrap"><table><thead><tr>{header_html}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>'


def _dict_items(value: object) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _string(value: object) -> str:
    return "" if value is None else str(value)


def _analysis_script() -> str:
    return """
        <script>
        (() => {
          const input = document.getElementById('analysis-search');
          const severity = document.getElementById('analysis-severity');
          const tbody = document.getElementById('analysis-findings-body');
          const count = document.getElementById('analysis-count');
          if (!tbody) return;
          const rows = Array.from(tbody.querySelectorAll('[data-analysis-finding-row]'));
          const empty = document.getElementById('analysis-empty-row');

          function applyAnalysisFilters() {
            const query = (input ? input.value : '').trim().toLowerCase();
            const level = severity ? severity.value : '';
            let visible = 0;
            rows.forEach((row) => {
              const matchedQuery = !query || (row.dataset.search || '').includes(query);
              const matchedLevel = !level || row.dataset.severity === level;
              const matched = matchedQuery && matchedLevel;
              row.hidden = !matched;
              if (matched) visible += 1;
            });
            if (empty) empty.hidden = visible !== 0;
            if (count) count.textContent = `显示 ${visible} / ${rows.length} 个风险项`;
          }

          if (input) input.addEventListener('input', applyAnalysisFilters);
          if (severity) severity.addEventListener('change', applyAnalysisFilters);
          applyAnalysisFilters();
        })();
        </script>
        """


def _render_error(title: str, message: str) -> str:
    return _page(title, f"<section class=\"hero\"><h1>{escape(title)}</h1><p>{escape(message)}</p><p><a href=\"/\">返回首页</a></p></section>")


def _page(title: str, body: str) -> str:
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)}</title>
  <style>
    :root {{ color-scheme: light dark; --bg:#0f172a; --panel:#111827; --line:#243244; --text:#e5e7eb; --muted:#94a3b8; --accent:#38bdf8; }}
    body {{ margin:0; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:linear-gradient(135deg,#0f172a,#111827 55%,#172554); color:var(--text); }}
    main {{ max-width: 1060px; margin: 0 auto; padding: 32px 18px 64px; }}
    section {{ background: rgba(15,23,42,.62); border:1px solid rgba(148,163,184,.18); border-radius:22px; padding:22px; margin:16px 0; }}
    .hero h1 {{ font-size: clamp(2rem, 5vw, 4rem); margin:.2rem 0; letter-spacing:-.05em; }}
    .eyebrow, p, .muted {{ color:var(--muted); }}
    form {{ display:grid; gap:12px; }}
    input, select, textarea {{ border:1px solid var(--line); border-radius:12px; background:rgba(15,23,42,.78); color:var(--text); padding:12px; }}
    textarea {{ min-height:82px; resize:vertical; }}
    button, .button-link {{ display:inline-block; border:0; border-radius:14px; background:var(--accent); color:#082f49; padding:11px 16px; font-weight:800; text-decoration:none; cursor:pointer; }}
    .danger-button {{ background:#fecaca; color:#7f1d1d; }}
    .links {{ display:flex; gap:10px; flex-wrap:wrap; }}
    .history-toolbar, .analysis-toolbar {{ display:grid; grid-template-columns: minmax(220px,1fr) minmax(180px,260px); gap:12px; align-items:end; }}
    .history-toolbar label, .analysis-toolbar label {{ display:grid; gap:8px; color:var(--muted); }}
    .table-wrap {{ overflow-x:auto; }}
    table {{ width:100%; border-collapse:collapse; background:rgba(17,24,39,.72); border-radius:14px; overflow:hidden; }}
    th,td {{ text-align:left; padding:10px 12px; border-bottom:1px solid var(--line); vertical-align:top; }}
    tr[hidden] {{ display:none; }}
    .empty-row td {{ color:var(--muted); text-align:center; }}
    .inline-form {{ display:inline; }}
    .history-actions {{ display:flex; gap:8px; flex-wrap:wrap; }}
    code {{ color:#bae6fd; word-break:break-all; }}
    details.detail-section {{ background: rgba(15,23,42,.62); border:1px solid rgba(148,163,184,.18); border-radius:22px; margin:16px 0; overflow:hidden; }}
    details.detail-section summary {{ cursor:pointer; padding:18px 22px; font-weight:800; }}
    .detail-body {{ padding:0 22px 22px; }}
    .badge {{ display:inline-block; border-radius:999px; padding:4px 9px; background:rgba(148,163,184,.18); font-weight:800; }}
    .badge.high {{ background:rgba(248,113,113,.2); color:#fecaca; }}
    .badge.medium {{ background:rgba(251,191,36,.18); color:#fde68a; }}
    .badge.low {{ background:rgba(56,189,248,.16); color:#bae6fd; }}
    .badge.info {{ background:rgba(148,163,184,.18); color:#cbd5e1; }}
    .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:12px; background:transparent; border:0; padding:0; }}
    .cards div {{ background:rgba(17,24,39,.82); border:1px solid var(--line); border-radius:18px; padding:16px; }}
    .cards strong {{ display:block; font-size:2rem; margin-top:5px; }}
    .status-box {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:12px; margin:12px 0; }}
    .status-box div {{ background:rgba(17,24,39,.82); border:1px solid var(--line); border-radius:18px; padding:16px; }}
    .status-box span {{ display:block; color:var(--muted); margin-bottom:6px; }}
    .status-box strong {{ font-size:1.2rem; }}
    progress {{ width:100%; height:18px; accent-color:var(--accent); }}
    .error {{ color:#fecaca; }}
    @media (max-width: 720px) {{ .history-toolbar, .analysis-toolbar {{ grid-template-columns:1fr; }} }}
  </style>
</head>
<body><main>{body}</main></body>
</html>"""


def _recent_analyses(config: WebConfig) -> list[dict[str, Any]]:
    reports_root = config.workdir / "reports"
    items: list[dict[str, Any]] = []
    if not reports_root.exists():
        return items
    for summary_path in sorted(reports_root.glob("*/report.summary.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            data = json.loads(summary_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        apk = data.get("apk", {})
        risk = data.get("risk", {})
        tool = data.get("tool", {}) if isinstance(data.get("tool"), dict) else {}
        top_findings = data.get("top_findings", [])
        findings_text = " ".join(
            str(value)
            for item in top_findings
            if isinstance(item, dict)
            for value in (item.get("id"), item.get("title"), item.get("severity"), item.get("severity_label"))
            if value
        )
        updated_at = summary_path.stat().st_mtime
        generated_at = str(tool.get("generated_at") or "")
        generated_display = generated_at[:19].replace("T", " ") if generated_at else time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(updated_at))
        search_text = " ".join(
            str(value)
            for value in (
                summary_path.parent.name,
                apk.get("file_name"),
                apk.get("app_name"),
                apk.get("package_name"),
                apk.get("version_name"),
                apk.get("version_code"),
                apk.get("sha256"),
                findings_text,
            )
            if value
        ).lower()
        items.append(
            {
                "job_id": summary_path.parent.name,
                "file_name": apk.get("file_name"),
                "app_name": apk.get("app_name"),
                "package_name": apk.get("package_name"),
                "version_name": apk.get("version_name"),
                "high": int(risk.get("high", 0) or 0),
                "medium": int(risk.get("medium", 0) or 0),
                "low": int(risk.get("low", 0) or 0),
                "total": int(risk.get("total", 0) or 0),
                "updated_at": updated_at,
                "generated_display": generated_display,
                "search_text": search_text,
            }
        )
    return items


def _history_row(item: dict[str, Any]) -> str:
    job_id = str(item.get("job_id") or "")
    app_name = str(item.get("app_name") or item.get("file_name") or "未知应用")
    package_name = str(item.get("package_name") or "")
    version_name = str(item.get("version_name") or "")
    search_text = str(item.get("search_text") or "")
    sort_name = app_name.lower()
    high = int(item.get("high", 0) or 0)
    medium = int(item.get("medium", 0) or 0)
    low = int(item.get("low", 0) or 0)
    total = int(item.get("total", 0) or 0)
    updated_at = float(item.get("updated_at", 0) or 0)
    generated_display = str(item.get("generated_display") or "")
    return (
        f'<tr data-history-row data-search="{escape(search_text)}" data-name="{escape(sort_name)}" '
        f'data-high="{high}" data-medium="{medium}" data-total="{total}" data-updated="{updated_at}">'
        f"<td>{escape(app_name)}</td>"
        f"<td><code>{escape(package_name)}</code></td>"
        f"<td>{escape(version_name)}</td>"
        f"<td>{high}</td><td>{medium}</td><td>{low}</td><td>{total}</td>"
        f"<td>{escape(generated_display)}</td>"
        f"<td><div class=\"history-actions\">"
        f"<a href=\"/analysis/{escape(job_id)}\">查看</a>"
        f"<form class=\"inline-form\" action=\"/delete/{escape(job_id)}\" method=\"post\" onsubmit=\"return confirm('删除这条历史记录？');\">"
        f"<button class=\"danger-button\" type=\"submit\">删除</button>"
        f"</form></div></td></tr>"
    )
