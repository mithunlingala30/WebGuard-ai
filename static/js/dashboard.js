(function () {
  "use strict";
  const { esc, api, sevBadge, statusBadge, fmt } = WG;
  const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  let sevChart, actChart;

  Chart.defaults.color = "#5e6c84";
  Chart.defaults.font.family = css("--font") || "Inter, sans-serif";

  function riskColor(level) {
    return { None: css("--ok"), Minimal: css("--ok"), Low: css("--low"), Moderate: css("--med"), High: css("--high"), Critical: css("--crit") }[level] || css("--primary");
  }

  function render(d) {
    document.querySelectorAll("[data-stat]").forEach((el) => WG.countUp(el, d.totals[el.dataset.stat] || 0));

    // risk gauge
    const arc = document.getElementById("gaugeArc"), c = riskColor(d.risk.level);
    arc.style.stroke = c;
    arc.style.strokeDashoffset = 515 - (515 * d.risk.score) / 100;
    document.getElementById("riskScore").textContent = Math.round(d.risk.score);
    const lv = document.getElementById("riskLevel"); lv.textContent = d.risk.level === "None" ? "No data" : d.risk.level; lv.style.color = c;
    document.getElementById("riskNote").textContent = d.risk.targets
      ? `Average of the latest score for ${d.risk.targets} scanned target${d.risk.targets > 1 ? "s" : ""}.`
      : "Run a scan to calculate your risk score.";

    // severity pie
    const labels = ["Critical", "High", "Medium", "Low"], vals = labels.map((l) => d.severity[l]);
    const total = vals.reduce((a, b) => a + b, 0);
    const sevCfg = {
      type: "doughnut",
      data: { labels, datasets: [{ data: total ? vals : [1], backgroundColor: total ? labels.map((l) => WG.SEV_COLORS[l]) : ["#dce2ec"], borderColor: "#f0f3f8", borderWidth: 4, hoverOffset: 8 }] },
      options: { maintainAspectRatio: false, cutout: "62%", plugins: { legend: { display: false }, tooltip: { enabled: !!total } } },
    };
    if (sevChart) { sevChart.data = sevCfg.data; sevChart.options = sevCfg.options; sevChart.update(); } else sevChart = new Chart(document.getElementById("sevChart"), sevCfg);
    document.getElementById("sevLegend").innerHTML = total
      ? labels.map((l, i) => `<span><i style="background:${WG.SEV_COLORS[l]}"></i>${l} · ${vals[i]}</span>`).join("")
      : "<span>No vulnerabilities recorded yet</span>";

    // activity bar
    const barData = { labels: d.activity.map((a) => a.date), datasets: [{ label: "Scans", data: d.activity.map((a) => a.count), borderRadius: 6, backgroundColor: "#dc2626", hoverBackgroundColor: "#b91c1c", maxBarThickness: 26 }] };
    const barOpts = { maintainAspectRatio: false, plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, ticks: { precision: 0, color: "#5e6c84" }, grid: { color: "rgba(210,217,230,0.6)" }, border: { display: false } }, x: { grid: { display: false }, ticks: { color: "#5e6c84", maxRotation: 0, autoSkip: true, maxTicksLimit: 7 } } } };
    if (actChart) { actChart.data = barData; actChart.update(); } else actChart = new Chart(document.getElementById("activityChart"), { type: "bar", data: barData, options: barOpts });

    // recent findings
    const rf = document.getElementById("recentFindings");
    rf.innerHTML = d.recent_findings.length ? d.recent_findings.map((f) => `
      <a class="list-item" href="/scan/${f.scan_id}" style="text-decoration:none;color:inherit">
        ${sevBadge(f.severity)}<div class="grow"><b>${esc(f.name)}</b><small>${esc(f.url)}</small></div></a>`).join("")
      : '<div class="empty">No findings yet. Start a scan to see results here.</div>';

    // recent scans
    const rs = document.getElementById("recentScans");
    rs.innerHTML = d.recent_scans.length ? d.recent_scans.map((s) => `
      <tr class="click" data-href="/scan/${s.scan_id}"><td class="url-cell">${esc(s.target_url)}</td><td>${statusBadge(s.status)}</td>
      <td>${s.findings}</td><td>${s.status === "Completed" ? Math.round(s.risk_score) : "—"}</td><td>${fmt(s.start_time || s.created_at)}</td></tr>`).join("")
      : '<tr><td colspan="5" class="empty">No scans yet. <a href="/scan/new">Start your first scan</a>.</td></tr>';
    rs.querySelectorAll("tr.click").forEach((tr) => tr.addEventListener("click", () => (location.href = tr.dataset.href)));
  }

  async function load() {
    try { render(await api("/api/dashboard/stats")); }
    catch (e) { WG.toast(e.message, "error"); }
  }
  load();
  document.addEventListener("wg:scan_finished", load);
  setInterval(() => { if (document.visibilityState === "visible") load(); }, 15000);
})();
