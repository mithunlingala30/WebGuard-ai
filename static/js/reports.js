(function () {
  "use strict";
  const { esc, api, fmt } = WG;
  api("/api/reports").then((r) => {
    const body = document.getElementById("repBody");
    body.innerHTML = r.scans.length ? r.scans.map((s) => `
      <tr><td>#${s.scan_id}</td><td class="url-cell"><a href="/scan/${s.scan_id}">${esc(s.target_url)}</a></td><td>${s.findings}</td><td>${Math.round(s.risk_score)}</td>
      <td>${fmt(s.end_time)}</td><td style="white-space:nowrap"><a class="btn btn-sm btn-primary no-dot" href="/reports/${s.scan_id}/pdf">PDF</a>
      <a class="btn btn-sm" href="/reports/${s.scan_id}/html">HTML</a></td></tr>`).join("")
      : '<tr><td colspan="6" class="empty">No completed scans yet. <a href="/scan/new">Run a scan</a> to generate a report.</td></tr>';
  }).catch((e) => WG.toast(e.message, "error"));
})();
