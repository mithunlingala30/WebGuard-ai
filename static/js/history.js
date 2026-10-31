(function () {
  "use strict";
  const { esc, api, sevBadge, statusBadge, fmt } = WG;
  const $ = (id) => document.getElementById(id);
  let selected = new Set();

  function updateSel() {
    $("selCount").textContent = selected.size;
    $("compareBtn").disabled = selected.size !== 2;
    document.querySelectorAll(".sel").forEach((c) => { c.disabled = selected.size >= 2 && !c.checked; });
  }

  async function load() {
    const qs = new URLSearchParams({ q: $("q").value, status: $("fStatus").value === "Running" ? "" : $("fStatus").value });
    try {
      const r = await api("/api/history?" + qs);
      let scans = r.scans;
      if ($("fStatus").value === "Running") scans = scans.filter((s) => !["Completed", "Failed", "Cancelled"].includes(s.status));
      $("histBody").innerHTML = scans.length ? scans.map((s) => {
        const done = s.status === "Completed", act = !["Completed", "Failed", "Cancelled"].includes(s.status);
        return `<tr><td>${done ? `<label class="check" style="gap:0"><input class="sel" type="checkbox" value="${s.scan_id}" ${selected.has(s.scan_id) ? "checked" : ""} aria-label="Select scan ${s.scan_id}"><span class="box"><svg viewBox="0 0 24 24"><polyline points="20 6 9 17 4 12"/></svg></span></label>` : ""}</td>
          <td>#${s.scan_id}</td><td class="url-cell"><a href="/scan/${s.scan_id}">${esc(s.target_url)}</a></td><td>${statusBadge(s.status)}${act ? ` <span class="faint">${s.progress}%</span>` : ""}</td>
          <td>${s.findings}</td><td>${done ? Math.round(s.risk_score) : "—"}</td><td>${fmt(s.start_time || s.created_at)}</td>
          <td style="white-space:nowrap"><a class="btn btn-sm" href="/scan/${s.scan_id}">Open</a> ${act ? "" : `<button class="btn btn-sm btn-danger" data-del="${s.scan_id}" aria-label="Delete scan ${s.scan_id}">Delete</button>`}</td></tr>`;
      }).join("") : '<tr><td colspan="8" class="empty">No scans found.</td></tr>';
      document.querySelectorAll(".sel").forEach((c) => c.addEventListener("change", () => { c.checked ? selected.add(+c.value) : selected.delete(+c.value); updateSel(); }));
      document.querySelectorAll("[data-del]").forEach((b) => b.addEventListener("click", () => del(+b.dataset.del)));
      updateSel();
    } catch (e) { WG.toast(e.message, "error"); }
  }

  async function del(id) {
    if (!confirm(`Delete scan #${id} and its findings and reports? This cannot be undone.`)) return;
    try { await api(`/api/scans/${id}/delete`, { method: "POST" }); selected.delete(id); WG.toast("Scan deleted.", "success"); load(); }
    catch (e) { WG.toast(e.message, "error"); }
  }

  $("compareBtn").addEventListener("click", async () => {
    const [a, b] = [...selected];
    try {
      const r = await api(`/api/compare?a=${a}&b=${b}`);
      const list = (items) => items.length ? items.map((i) => `<div class="list-item">${sevBadge(i.severity)}<div class="grow"><b>${esc(i.name)}</b><small>${esc(i.url)}</small></div></div>`).join("") : '<div class="faint" style="font-size:.85rem">None</div>';
      WG.openModal(`<div class="modal-head"><div><h2 id="mTitle">Scan #${r.old.id} → #${r.new.id}</h2>
        <span class="muted">Risk ${r.old.risk} → ${r.new.risk} (<b style="color:${r.risk_delta > 0 ? "var(--crit)" : r.risk_delta < 0 ? "var(--ok)" : "var(--muted)"}">${r.risk_delta > 0 ? "+" : ""}${r.risk_delta}</b>)</span></div>
        <button class="btn btn-icon btn-sm" data-close aria-label="Close">✕</button></div>
        ${r.old.target !== r.new.target ? '<div class="notice" style="margin-bottom:1rem">These scans have different targets.</div>' : ""}
        <h4>New findings (${r.new_findings.length})</h4><div class="list">${list(r.new_findings)}</div>
        <h4>Resolved (${r.resolved.length})</h4><div class="list">${list(r.resolved)}</div>
        <h4>Still present (${r.persistent.length})</h4><div class="list">${list(r.persistent)}</div>
        <div style="margin-top:1.5rem;text-align:right"><button class="btn" data-close>Close</button></div>`);
    } catch (e) { WG.toast(e.message, "error"); }
  });

  let t; $("q").addEventListener("input", () => { clearTimeout(t); t = setTimeout(load, 250); });
  $("fStatus").addEventListener("change", load);
  document.addEventListener("wg:scan_finished", load);
  load();
})();
