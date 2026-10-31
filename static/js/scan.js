(function () {
  "use strict";
  const { esc, api, statusBadge } = WG;
  const $ = (id) => document.getElementById(id);
  const STEPS = ["Waiting", "Initializing", "Crawling", "Testing", "AI Analysis", "Completed"];
  let scanId = null, poll = null, joined = false;

  document.querySelectorAll("[data-fill]").forEach((b) => b.addEventListener("click", () => { $("url").value = b.dataset.fill; $("url").focus(); }));

  function renderSteps(status) {
    const idx = STEPS.indexOf(status);
    $("steps").innerHTML = STEPS.map((s, i) => {
      let c = "step";
      if (status === "Completed" || (idx > i)) c += " done"; else if (idx === i) c += " active";
      return `<div class="${c}"><i></i>${esc(s)}</div>`;
    }).join("");
  }

  function logLine(m) {
    const c = $("console");
    const d = document.createElement("div");
    d.className = m.status || "info";
    d.innerHTML = `<span class="t">${esc(WG.timeOnly(m.timestamp))}</span>${esc(m.message)}`;
    c.appendChild(d); c.scrollTop = c.scrollHeight;
  }

  function update(p) {
    $("livePct").textContent = p.progress + "%";
    const bar = $("liveBar"); bar.firstElementChild.style.width = p.progress + "%";
    bar.className = "progress" + (p.status === "Completed" ? " done" : p.status === "Failed" ? " fail" : "");
    $("liveStatus").innerHTML = statusBadge(p.status);
    $("liveActivity").textContent = p.activity || "";
    $("livePages").textContent = p.pages; $("liveTests").textContent = p.tests;
    $("liveFind").textContent = p.status === "Completed" ? p.findings : "–";
    renderSteps(p.status);
    const finished = ["Completed", "Failed", "Cancelled"].includes(p.status);
    $("cancelBtn").disabled = finished;
    if (finished) {
      clearInterval(poll); $("startBtn").disabled = false;
      $("doneActions").style.display = "block"; $("resultsLink").href = "/scan/" + p.scan_id;
      $("resultsLink").textContent = p.status === "Completed" ? "View results" : "View scan details";
      if (p.status === "Failed") $("liveActivity").textContent = p.error || "The scan failed.";
    }
  }

  function track(id, target) {
    scanId = id; joined = false;
    $("liveCard").style.display = "block"; $("liveTarget").textContent = target; $("console").innerHTML = "";
    $("doneActions").style.display = "none"; $("cancelBtn").disabled = false; $("startBtn").disabled = true;
    renderSteps("Waiting");
    $("liveCard").scrollIntoView({ behavior: "smooth", block: "start" });
    if (WG.socket) {
      WG.socket.emit("subscribe_scan", { scan_id: id });
      WG.socket.off("scan_progress").on("scan_progress", (p) => { if (p.scan_id === scanId) { joined = true; update(p); } });
      WG.socket.off("scan_log").on("scan_log", (m) => { if (m.scan_id === scanId) logLine(m); });
    }
    // polling fallback keeps the UI correct even if WebSockets are blocked
    clearInterval(poll);
    poll = setInterval(async () => {
      try { const s = await api("/api/scans/" + id); update(s); } catch (e) { /* transient */ }
    }, 2500);
    api("/api/scans/" + id + "/logs").then((r) => { $("console").innerHTML = ""; r.logs.forEach(logLine); }).catch(() => {});
  }

  $("scanForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    $("urlErr").textContent = ""; $("authErr").textContent = "";
    const url = $("url").value.trim();
    let bad = false;
    try { const u = new URL(/^[a-z]+:\/\//i.test(url) ? url : "https://" + url); if (!["http:", "https:"].includes(u.protocol)) throw 0; }
    catch (x) { $("urlErr").textContent = url ? "Enter a valid http(s) URL." : "Please enter a website URL."; bad = true; }
    if (!$("auth").checked) { $("authErr").textContent = "You must confirm that you are authorized to test this website."; bad = true; }
    if (bad) return;
    $("startBtn").disabled = true;
    try {
      const r = await api("/api/scans", { method: "POST", body: { url, scan_type: $("scanType").value, authorized: true, extra_paths: $("extra").value } });
      WG.toast("Scan #" + r.scan_id + " queued.", "success");
      track(r.scan_id, r.scan.target_url);
    } catch (err) {
      $("urlErr").textContent = err.message; $("startBtn").disabled = false;
    }
  });

  $("cancelBtn").addEventListener("click", async () => {
    if (!scanId) return;
    $("cancelBtn").disabled = true;
    try { await api("/api/scans/" + scanId + "/cancel", { method: "POST" }); WG.toast("Cancelling scan…", "warning"); }
    catch (e) { WG.toast(e.message, "error"); }
  });
})();
