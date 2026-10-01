"""Embedded ops dashboard assets (vanilla HTML/JS, no external resources)."""

from __future__ import annotations

INDEX_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>审计馈送中继 · 运维台</title>
<style>
  :root { --bg:#0f1420; --panel:#171e2e; --line:#26304a; --fg:#e6ebf5;
          --mut:#8b97b3; --ok:#37d399; --warn:#f5b452; --bad:#f06464;
          --accent:#5b8cff; }
  * { box-sizing:border-box; }
  body { margin:0; font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,
         "PingFang SC","Microsoft YaHei",sans-serif; background:var(--bg);
         color:var(--fg); }
  header { padding:16px 22px; border-bottom:1px solid var(--line);
           display:flex; align-items:center; gap:16px; flex-wrap:wrap; }
  header h1 { font-size:17px; margin:0; font-weight:600; }
  header .sp { flex:1; }
  input,button,select { font:inherit; background:#0e1424; color:var(--fg);
         border:1px solid var(--line); border-radius:7px; padding:7px 10px; }
  button { cursor:pointer; }
  button:hover { border-color:var(--accent); }
  main { padding:20px 22px; display:grid; gap:18px; }
  .cards { display:grid; gap:14px; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); }
  .card { background:var(--panel); border:1px solid var(--line); border-radius:12px;
          padding:15px 16px; }
  .card .k { color:var(--mut); font-size:12px; letter-spacing:.04em;
             text-transform:uppercase; }
  .card .v { font-size:26px; font-weight:650; margin-top:5px; }
  .card .sub { color:var(--mut); font-size:12px; margin-top:4px; word-break:break-all; }
  .ok{color:var(--ok)} .warn{color:var(--warn)} .bad{color:var(--bad)}
  section { background:var(--panel); border:1px solid var(--line);
            border-radius:12px; overflow:hidden; }
  section h2 { margin:0; padding:13px 16px; font-size:14px; font-weight:600;
               border-bottom:1px solid var(--line); display:flex; gap:10px;
               align-items:center; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:9px 12px; border-bottom:1px solid var(--line);
          vertical-align:top; }
  th { color:var(--mut); font-weight:500; font-size:12px; }
  tr:last-child td { border-bottom:none; }
  .pill { display:inline-block; padding:1px 9px; border-radius:999px; font-size:12px;
          border:1px solid var(--line); }
  .pill.ok{ border-color:var(--ok); } .pill.off{ border-color:var(--bad); color:var(--bad); }
  .pill.warn{ border-color:var(--warn); color:var(--warn); }
  code { background:#0e1424; padding:1px 5px; border-radius:5px; font-size:12px; }
  .muted{ color:var(--mut); }
  .grid2{ display:grid; gap:18px; grid-template-columns:1fr 1fr; }
  @media (max-width:900px){ .grid2{ grid-template-columns:1fr; } }
  .row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
  .reason { color:var(--warn); }
  .hidden{ display:none; }
</style>
</head>
<body>
<header>
  <h1>审计馈送中继 · 运维台</h1>
  <span id="upPill" class="pill">…</span>
  <span class="sp"></span>
  <input id="adminToken" type="password" placeholder="admin token" size="22">
  <input id="baseUrl" type="text" placeholder="http://127.0.0.1:8090" size="24">
  <label class="muted"><input type="checkbox" id="auto" checked> 自动刷新</label>
  <button id="syncBtn">立即同步</button>
  <button id="saveBtn">保存</button>
</header>
<main>
  <div class="cards" id="cards"></div>
  <section>
    <h2>审计租户 · 隔离筛选与消费位点</h2>
    <div style="overflow:auto"><table>
      <thead><tr>
        <th>租户</th><th>状态</th><th>位点</th><th>镜像高度</th>
        <th>积压(总/匹配)</th><th>租约持有者</th><th>重试</th>
        <th>租约区间</th><th>筛选版本</th>
      </tr></thead>
      <tbody id="tenants"></tbody>
    </table></div>
  </section>
  <div class="grid2">
    <section>
      <h2>最近事件（同步 / 投递）</h2>
      <div style="max-height:340px; overflow:auto"><table>
        <thead><tr><th>时间</th><th>类别</th><th>事件</th><th>租户</th><th>详情</th></tr></thead>
        <tbody id="events"></tbody></table></div>
    </section>
    <section>
      <h2>拒绝原因</h2>
      <div style="max-height:340px; overflow:auto"><table>
        <thead><tr><th>时间</th><th>原因</th><th>租户</th><th>详情</th></tr></thead>
        <tbody id="rejects"></tbody></table></div>
    </section>
  </div>
</main>
<script src="/ops/app.js"></script>
</body>
</html>
"""

APP_JS = r"""
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s == null ? "" : s)
  .replace(/[&<>"]/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

function cfg() {
  return {
    token: localStorage.getItem("ar_token") || "",
    base: (localStorage.getItem("ar_base") || location.origin).replace(/\/$/, ""),
  };
}
$("saveBtn").onclick = () => {
  localStorage.setItem("ar_token", $("adminToken").value.trim());
  localStorage.setItem("ar_base", $("baseUrl").value.trim() || location.origin);
  load();
};
$("syncBtn").onclick = async () => {
  const c = cfg();
  await fetch(c.base + "/v1/admin/sync", { method: "POST",
    headers: { Authorization: "Bearer " + c.token }});
  load();
};

async function api(path, opts) {
  const c = cfg();
  const r = await fetch(c.base + path, Object.assign({
    headers: { Authorization: "Bearer " + c.token, "Content-Type": "application/json" },
  }, opts || {}));
  if (!r.ok) throw new Error((await r.json()).message || r.status);
  return r.json();
}

function pill(text, cls) { return `<span class="pill ${cls}">${esc(text)}</span>`; }

function card(k, v, sub, cls) {
  return `<div class="card"><div class="k">${esc(k)}</div>` +
    `<div class="v ${cls||""}">${esc(v)}</div>` +
    `<div class="sub">${sub==null?"":esc(sub)}</div></div>`;
}

function render(d) {
  const m = d.mirror, u = m.upstream || {};
  const upState = u.state || "unknown";
  const upCls = upState === "healthy" ? "ok" :
                upState === "frozen" ? "warn" : "bad";
  $("upPill").className = "pill " + upCls;
  $("upPill").textContent = "上游: " + upState +
    (u.halt_reason ? " (" + u.halt_reason + ")" : "");

  let cards = "";
  cards += card("镜像高度", m.mirror_height,
    "可信树头 " + (m.last_trusted_tree_size||0));
  cards += card("已存叶记录", m.stored_leaves,
    "最近可信时间 " + (m.last_trusted_at||"—"));
  cards += card("上游通告高度", u.advertised_height == null ? "—" : u.advertised_height,
    "可信位点 " + (u.trusted_height == null ? "—" : u.trusted_height), upCls);
  let totalBacklog = 0, totalRetry = 0, activeLeases = 0;
  d.tenants.forEach(t => { totalBacklog += (t.backlog_matching||0);
    if (t.open_lease) { totalRetry += (t.open_lease.attempt-1); activeLeases++; }});
  cards += card("匹配积压合计", totalBacklog, "所有租户待消费匹配记录");
  cards += card("活动租约", activeLeases, "短租约持有中的投递包");
  cards += card("重试合计", totalRetry,
    u.halt_reason ? ("暂停: " + u.halt_reason) : "超时/重投累计次数",
    u.halt_reason ? "warn" : "");
  $("cards").innerHTML = cards;

  $("tenants").innerHTML = d.tenants.map(t => {
    const L = t.open_lease;
    return `<tr>
      <td><b>${esc(t.tenant_id)}</b><br><span class="muted">${esc(t.name)}</span></td>
      <td>${t.active ? pill("启用","ok") : pill("已停用","off")}</td>
      <td><code>${esc(t.cursor)}</code></td>
      <td>${esc(t.mirror_height)}</td>
      <td>${esc(t.backlog)} / <b>${esc(t.backlog_matching)}</b></td>
      <td>${L ? esc(L.lease_holder||"—") +
            (L.expired ? pill("已超时","warn") : pill("持有中","ok"))
            : '<span class="muted">—</span>'}</td>
      <td>${L ? esc(L.attempt) : "0"}</td>
      <td>${L ? `<code>${esc(L.seq_start)}–${esc(L.seq_end)}</code>`
              : '<span class="muted">—</span>'}</td>
      <td>v${esc(t.filter_version)}</td>
    </tr>`;
  }).join("") || '<tr><td colspan="9" class="muted">暂无租户</td></tr>';

  const evRow = (e) => `<tr>
    <td class="muted">${esc((e.at||"").slice(11,19))}</td>
    <td>${esc(e.category)}</td><td>${esc(e.kind)}</td>
    <td>${esc(e.tenant_id||"—")}</td>
    <td class="muted">${esc(JSON.stringify(e.detail))}</td></tr>`;
  $("events").innerHTML = d.events.map(evRow).join("")
    || '<tr><td colspan="5" class="muted">无</td></tr>';
  $("rejects").innerHTML = d.rejections.map(evRow).join("")
    || '<tr><td colspan="4" class="muted">无拒绝</td></tr>';
}

async function load() {
  try {
    const d = await api("/v1/admin/status");
    render(d);
  } catch (e) {
    $("upPill").className = "pill bad";
    $("upPill").textContent = "无法加载: " + e.message;
  }
}

(function init(){
  const c = cfg();
  if (c.token) $("adminToken").value = c.token;
  $("baseUrl").value = c.base === location.origin ? "" : c.base;
  load();
  setInterval(() => { if ($("auto").checked) load(); }, 2000);
})();
"""

UI_ASSETS = {
    "index.html": INDEX_HTML,
    "app.js": APP_JS,
}
