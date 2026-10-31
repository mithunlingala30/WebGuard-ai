/* Client-side helpers for public pages (the server always re-validates). */
(function () {
  "use strict";
  const pw = document.getElementById("password");
  const rules = document.getElementById("pwRules");
  const confirm = document.getElementById("confirm_password");
  if (pw && rules) {
    const tests = { len: (v) => v.length >= 8, low: (v) => /[a-z]/.test(v), up: (v) => /[A-Z]/.test(v), num: (v) => /\d/.test(v) };
    pw.addEventListener("input", () => rules.querySelectorAll("span").forEach((s) => s.classList.toggle("ok", tests[s.dataset.r](pw.value))));
  }
  const form = document.getElementById("registerForm");
  if (form) {
    form.addEventListener("submit", (e) => {
      const err = document.getElementById("matchErr");
      if (confirm.value !== pw.value) { e.preventDefault(); err.textContent = "Passwords do not match."; confirm.focus(); } else { err.textContent = ""; }
    });
  }
})();
