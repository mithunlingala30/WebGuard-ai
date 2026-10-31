(function () {
  "use strict";
  const { esc, api, sevBadge, statusBadge } = WG;
  const $ = (id) => document.getElementById(id);
  const meta = $("scanMeta"), scanId = +meta.dataset.scanId;
  let all = [], timer = null, chart;
  Chart.defaults.color = "#5e6c84";

  document.querySelectorAll("[data-time]").forEach((el) => { if (el.dataset.time && el.dataset.time !== "None") el.textContent = WG.fmt(el.dataset.time); });

  function drawChart(sev) {
    const labels = ["Critical", "High", "Medium", "Low"], vals = labels.map((l) => sev[l] || 0), total = vals.reduce((a, b) => a + b, 0);
    const cfg = { type: "pie", data: { labels, datasets: [{ data: total ? vals : [1], backgroundColor: total ? labels.map((l) => WG.SEV_COLORS[l]) : ["#dce2ec"], borderColor: "#f0f3f8", borderWidth: 4, hoverOffset: 8 }] },
      options: { maintainAspectRatio: false, plugins: { legend: { display: false }, tooltip: { enabled: !!total } } } };
    if (chart) { chart.data = cfg.data; chart.update(); } else chart = new Chart($("sevChart"), cfg);
    $("sevLegend").innerHTML = total ? labels.map((l, i) => `<span><i style="background:${WG.SEV_COLORS[l]}"></i>${l} · ${vals[i]}</span>`).join("") : "<span>No findings</span>";
  }

  async function loadFindings() {
    const qs = new URLSearchParams({ q: $("q").value, severity: $("fSev").value, type: $("fType").value });
    try {
      const r = await api(`/api/scans/${scanId}/findings?` + qs);
      all = r.findings; drawChart(r.severity);
      const sel = $("fType"), cur = sel.value;
      if (sel.options.length - 1 !== r.types.length) sel.innerHTML = '<option value="">All categories</option>' + r.types.map((t) => `<option ${t === cur ? "selected" : ""}>${esc(t)}</option>`).join("");
      $("findCount").textContent = `${all.length} shown`;
      $("findBody").innerHTML = all.length ? all.map((f, i) => `
        <tr class="click" data-i="${i}"><td>${f.priority}</td><td><b>${esc(f.name)}</b>${f.status === "suspected" ? ' <span class="badge neutral">suspected</span>' : ""}</td>
        <td>${sevBadge(f.severity)}</td><td class="hide-sm">${esc(f.owasp)}</td><td class="url-cell mono">${esc(f.url)}</td><td>${esc(f.confidence)}</td></tr>`).join("")
        : `<tr><td colspan="6" class="empty">${meta.dataset.active === "true" ? "Findings will appear when the scan completes." : "No findings match. " + ($("q").value || $("fSev").value || $("fType").value ? "Try clearing the filters." : "Nothing was detected in this scan.")}</td></tr>`;
      $("findBody").querySelectorAll("tr.click").forEach((tr) => tr.addEventListener("click", () => showFinding(all[+tr.dataset.i])));
    } catch (e) { WG.toast(e.message, "error"); }
  }

  function showFinding(f) {
    WG.openModal(`
      <div class="modal-head"><div><h2 id="mTitle">${esc(f.name)}</h2>${sevBadge(f.severity)}
        <span class="badge neutral">${esc(f.status)}</span><span class="badge neutral">${esc(f.priority_label)}</span></div>
        <button class="btn btn-icon btn-sm" data-close aria-label="Close">✕</button></div>
      <dl class="kv"><dt>OWASP category</dt><dd>${esc(f.owasp)}</dd><dt>Affected URL</dt><dd class="mono">${esc(f.url)}</dd>
        ${f.param ? `<dt>Parameter</dt><dd class="mono">${esc(f.param)}</dd>` : ""}
        <dt>Confidence</dt><dd>${esc(f.confidence)} (${Math.round(f.confidence_score * 100)}%)</dd></dl>
      <h4>Description</h4><p>${esc(f.description)}</p>
      <h4>Detection evidence</h4><pre class="evidence">${esc(f.evidence)}</pre>
      <h4>Potential impact</h4><p>${esc(f.impact)}</p>
      <h4>Remediation recommendation</h4><p>${esc(f.recommendation)}</p>
      <h4>Why the AI engine classified it this way</h4><ul class="muted" style="padding-left:1.1rem;margin:0">${f.rationale.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>
      <div style="margin-top:1.5rem;text-align:right"><button class="btn" data-close>Close</button></div>`);
  }

  async function loadCompare() {
    try {
      const r = await api(`/api/scans/${scanId}/compare`), box = $("compare");
      if (!r.available) { box.textContent = r.message; return; }
      const list = (items, cls) => items.length ? items.map((i) => `<div class="list-item">${sevBadge(i.severity)}<div class="grow"><b>${esc(i.name)}</b><small>${esc(i.url)}</small></div></div>`).join("") : '<div class="faint" style="font-size:.84rem">None</div>';
      const d = r.risk_delta;
      box.innerHTML = `<p style="margin-bottom:1rem">Versus scan <a href="/scan/${r.old.id}">#${r.old.id}</a>: risk <b style="color:${d > 0 ? "var(--crit)" : d < 0 ? "var(--ok)" : "var(--muted)"}">${d > 0 ? "+" : ""}${d}</b>
        · <b>${r.new_findings.length}</b> new · <b>${r.resolved.length}</b> resolved · <b>${r.persistent.length}</b> unchanged</p>
        <h4 style="font-size:.72rem;letter-spacing:.1em;text-transform:uppercase;color:var(--faint)">New</h4><div class="list">${list(r.new_findings.slice(0, 5))}</div>
        <h4 style="font-size:.72rem;letter-spacing:.1em;text-transform:uppercase;color:var(--faint);margin-top:1rem">Resolved</h4><div class="list">${list(r.resolved.slice(0, 5))}</div>`;
    } catch (e) { $("compare").textContent = "Comparison unavailable."; }
  }

  function logLine(m) {
    const d = document.createElement("div"); d.className = m.status || "info";
    d.innerHTML = `<span class="t">${esc(WG.timeOnly(m.timestamp))}</span>${esc(m.message)}`;
    $("console").appendChild(d); $("console").scrollTop = $("console").scrollHeight;
  }

  function live(p) {
    $("livePct").textContent = p.progress + "%"; $("liveBar").firstElementChild.style.width = p.progress + "%";
    $("liveStatus").innerHTML = statusBadge(p.status); $("liveActivity").textContent = p.activity || "";
    $("sPages").textContent = p.pages; $("sTests").textContent = p.tests;
    if (["Completed", "Failed", "Cancelled"].includes(p.status)) { clearInterval(timer); setTimeout(() => location.reload(), 900); }
  }

  api(`/api/scans/${scanId}/logs`).then((r) => r.logs.forEach(logLine)).catch(() => {});
  loadFindings(); loadCompare();
  let t; ["q", "fSev", "fType"].forEach((id) => $(id).addEventListener(id === "q" ? "input" : "change", () => { clearTimeout(t); t = setTimeout(loadFindings, 220); }));

  if (meta.dataset.active === "true") {
    if (WG.socket) {
      WG.socket.emit("subscribe_scan", { scan_id: scanId });
      WG.socket.on("scan_progress", (p) => p.scan_id === scanId && live(p));
      WG.socket.on("scan_log", (m) => m.scan_id === scanId && logLine(m));
    }
    timer = setInterval(async () => { try { live(await api("/api/scans/" + scanId)); } catch (e) { /* retry */ } }, 2500);
    $("cancelBtn").addEventListener("click", async () => {
      $("cancelBtn").disabled = true;
      try { await api(`/api/scans/${scanId}/cancel`, { method: "POST" }); WG.toast("Cancelling scan…", "warning"); } catch (e) { WG.toast(e.message, "error"); }
    });
  }
})();
