/* WebGuard AI - shared client utilities (no inline scripts: CSP friendly) */
(function () {
  "use strict";
  const WG = (window.WG = {});
  const csrf = () => (document.querySelector('meta[name="csrf-token"]') || {}).content || "";

  // Escape ALL untrusted text (scan evidence comes from third-party sites) before using innerHTML.
  WG.esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  WG.sevBadge = (s) => `<span class="badge sev-${WG.esc(s)}">${WG.esc(s)}</span>`;
  WG.statusBadge = (s) => `<span class="badge st-${WG.esc(String(s).replace(/ /g, ""))}">${WG.esc(s)}</span>`;
  WG.fmt = (iso) => (iso ? new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "—");
  WG.timeOnly = (iso) => (iso ? new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "");
  WG.SEV_COLORS = { Critical: "#dc2626", High: "#ea580c", Medium: "#d97706", Low: "#0284c7" };

  WG.api = async function (url, opts = {}) {
    const o = Object.assign({ method: "GET", headers: {} }, opts);
    o.headers = Object.assign({ "X-CSRF-Token": csrf(), Accept: "application/json" }, o.headers);
    if (o.body && typeof o.body !== "string") { o.body = JSON.stringify(o.body); o.headers["Content-Type"] = "application/json"; }
    let res;
    try { res = await fetch(url, o); } catch (e) { throw new Error("Network error. Check your connection and try again."); }
    let data = {};
    try { data = await res.json(); } catch (e) { /* non-JSON */ }
    if (res.status === 401) { window.location.href = "/login"; throw new Error("Session expired."); }
    if (!res.ok) throw new Error(data.error || "Request failed (" + res.status + ").");
    return data;
  };

  WG.toast = function (msg, type = "info", link) {
    const box = document.getElementById("toasts");
    if (!box) return;
    const t = document.createElement("div");
    t.className = "toast " + type;
    t.innerHTML = `<div>${WG.esc(msg)}${link ? ` <a href="${WG.esc(link.href)}">${WG.esc(link.text)}</a>` : ""}</div>`;
    box.appendChild(t);
    setTimeout(() => { t.style.opacity = "0"; t.style.transition = "opacity .4s"; setTimeout(() => t.remove(), 450); }, 7000);
  };

  WG.countUp = function (el, to) {
    const from = parseInt(el.textContent, 10) || 0, start = performance.now(), dur = 700;
    if (from === to) { el.textContent = to; return; }
    (function step(now) {
      const p = Math.min(1, (now - start) / dur);
      el.textContent = Math.round(from + (to - from) * (1 - Math.pow(1 - p, 3)));
      if (p < 1) requestAnimationFrame(step);
    })(start);
  };

  WG.openModal = function (html) {
    const m = document.getElementById("modal");
    document.getElementById("modalBody").innerHTML = html;
    m.classList.add("open");
    const close = m.querySelector("[data-close]");
    if (close) close.focus();
    m.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", WG.closeModal));
  };
  WG.closeModal = () => { const m = document.getElementById("modal"); if (m) m.classList.remove("open"); };
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") WG.closeModal(); });
  document.addEventListener("click", (e) => { if (e.target.id === "modal") WG.closeModal(); });

  // ---- sidebar (mobile) ----
  const sb = document.getElementById("sidebar"), scrim = document.getElementById("scrim"), mb = document.getElementById("menuBtn");
  if (sb && mb) {
    const toggle = (open) => { sb.classList.toggle("open", open); scrim.classList.toggle("open", open); };
    mb.addEventListener("click", () => toggle(!sb.classList.contains("open")));
    scrim.addEventListener("click", () => toggle(false));
  }

  // ---- notifications ----
  const nBtn = document.getElementById("notifBtn"), nPanel = document.getElementById("notifPanel");
  const nList = document.getElementById("notifList"), nCount = document.getElementById("notifCount");
  let notes = [];
  try { notes = JSON.parse(sessionStorage.getItem("wg_notes") || "[]"); } catch (e) { notes = []; }
  function renderNotes() {
    if (!nList) return;
    const unread = notes.filter((n) => !n.read).length;
    nCount.textContent = unread; nCount.style.display = unread ? "grid" : "none";
    nList.innerHTML = notes.length
      ? notes.slice().reverse().map((n) => `<div class="notif-item"><a href="${WG.esc(n.href)}">${WG.esc(n.text)}</a><small>${WG.esc(n.time)}</small></div>`).join("")
      : '<div class="muted" style="font-size:.84rem;margin-top:.6rem">No new notifications.</div>';
  }
  function saveNotes() { try { sessionStorage.setItem("wg_notes", JSON.stringify(notes.slice(-20))); } catch (e) { /* storage unavailable */ } }
  if (nBtn) {
    nBtn.addEventListener("click", (e) => {
      e.stopPropagation(); nPanel.classList.toggle("open");
      if (nPanel.classList.contains("open")) { notes.forEach((n) => (n.read = true)); saveNotes(); setTimeout(renderNotes, 600); }
    });
    document.addEventListener("click", (e) => { if (!nPanel.contains(e.target)) nPanel.classList.remove("open"); });
    renderNotes();
  }

  // ---- socket (live updates; every page that has a sidebar) ----
  WG.socket = null;
  if (window.io && sb) {
    WG.socket = window.io({ reconnectionDelay: 1000 });
    WG.socket.on("scan_finished", (d) => {
      const ok = d.status === "Completed";
      const text = ok ? `Scan #${d.scan_id} completed: ${d.findings} finding(s).` : `Scan #${d.scan_id} ${d.status.toLowerCase()}.`;
      const href = "/scan/" + d.scan_id;
      WG.toast(text, ok ? "success" : d.status === "Cancelled" ? "warning" : "error", { href, text: "View" });
      notes.push({ text, href, time: new Date().toLocaleTimeString(), read: false }); saveNotes(); renderNotes();
      document.dispatchEvent(new CustomEvent("wg:scan_finished", { detail: d }));
    });
  }
})();
