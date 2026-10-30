/* ============================================================
   Login page script.
   This file only collects the form and talks to your server.
   EVERY real check happens on the server: password check, lockout,
   rate limiting, one-time code and role. Hiding or checking things
   here is for convenience only; it is never the security.

   Server contract (JSON over HTTPS, cookies set by the server):
   GET  /api/auth/csrf        -> { token }
   POST /api/auth/login       { identifier, password, remember }
        -> { ok:true, needsOtp:true }            when a code is required (admins)
        -> { ok:true, role:"admin|attachee|intern" }  when signed in
        -> { ok:false }  (401) wrong details, same reply for every cause
        -> 429 { retryAfter:seconds }  too many attempts
   POST /api/auth/verify-otp  { code }  -> { ok:true, role } or { ok:false }
   POST /api/auth/resend-otp  {}        -> { ok:true }
   The session cookie must be HttpOnly, Secure and SameSite=Strict.
   ============================================================ */
"use strict";

const API = { csrf:"/api/auth/csrf", login:"/api/auth/login", verifyOtp:"/api/auth/verify-otp", resendOtp:"/api/auth/resend-otp" };
/* Pages we are willing to send people to. The server only supplies a role; it never supplies a URL. */
const DEST = { admin:"admin.html", attachee:"registration-form.html", intern:"registration-form.html" };
const DEFAULT_DEST = "registration-form.html";
/* Set to true to move on automatically after sign-in instead of showing the Continue button */
const AUTO_REDIRECT = false;

const $ = id => document.getElementById(id);
const views = { login:$("v-login"), otp:$("v-otp"), ok:$("v-ok") };
const state = { role:"", fails:0, lockedUntil:0, timer:null };

function show(name){
  Object.values(views).forEach(v => v.classList.remove("show"));
  views[name].classList.add("show");
}
function busy(btn, on, label){ btn.disabled = on; btn.textContent = label; }

/* ---------- Talking to the server ---------- */
let csrfToken = "";
async function getCsrf(force){
  if (csrfToken && !force) return csrfToken;
  const r = await fetch(API.csrf, { credentials:"same-origin", cache:"no-store", headers:{ Accept:"application/json" } });
  if (!r.ok) throw new Error("csrf");
  const d = await r.json();
  csrfToken = String(d.token || "");
  if (!csrfToken) throw new Error("csrf");
  return csrfToken;
}
async function post(url, body, retried){
  const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), 15000);
  try{
    const res = await fetch(url, {
      method:"POST", credentials:"same-origin", cache:"no-store", redirect:"error", signal:ctl.signal,
      headers:{ "Content-Type":"application/json", Accept:"application/json", "X-CSRF-Token":await getCsrf(!!retried) },
      body:JSON.stringify(body || {})
    });
    if (res.status === 403 && !retried){ csrfToken = ""; return post(url, body, true); }   // token expired: fetch a fresh one once
    let data = {}; try{ data = await res.json(); }catch(e){}
    return { status:res.status, ok:res.ok && data.ok !== false, data };
  }catch(e){
    return { status:0, ok:false, data:{}, network:true };
  }finally{
    clearTimeout(t);
  }
}

/* ---------- Page setup ---------- */
const pic = document.querySelector(".visual img");
if (pic){ pic.addEventListener("error", () => pic.remove()); if (pic.complete && pic.naturalWidth === 0) pic.remove(); }
$("identifier").focus();
addEventListener("pageshow", e => { if (e.persisted){ $("password").value = ""; } });   // never show an old password after the Back button

/* ---------- Show / hide password and Caps Lock warning ---------- */
function hidePassword(){ $("password").type = "password"; $("tg").textContent = "Show"; $("tg").setAttribute("aria-pressed", "false"); }
$("tg").addEventListener("click", () => {
  const reveal = $("password").type === "password";
  $("password").type = reveal ? "text" : "password";
  $("tg").textContent = reveal ? "Hide" : "Show";
  $("tg").setAttribute("aria-pressed", String(reveal));
});
["keyup","keydown"].forEach(ev => $("password").addEventListener(ev, e => {
  $("caps").style.display = e.getModifierState && e.getModifierState("CapsLock") ? "flex" : "none";
}));

/* ---------- Waiting period after too many attempts (the server enforces the real limit) ---------- */
function lock(seconds){
  state.lockedUntil = Date.now() + seconds * 1000; state.fails = 0;
  $("b1").disabled = true;
  clearInterval(state.timer);
  const tick = () => {
    const left = Math.ceil((state.lockedUntil - Date.now()) / 1000);
    if (left <= 0){ clearInterval(state.timer); $("b1").disabled = false; $("m1").textContent = ""; return; }
    $("m1").textContent = "Too many attempts. Try again in " + left + " seconds.";
  };
  tick(); state.timer = setInterval(tick, 500);
}

/* ---------- Login ---------- */
$("v-login").addEventListener("submit", async e => {
  e.preventDefault();
  if (Date.now() < state.lockedUntil || $("b1").disabled) return;
  const id = $("identifier").value.trim();
  const pw = $("password").value;
  const idOk = id.length <= 254 && (/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(id) || /^\d{7,10}$/.test(id));

  $("f-id").classList.toggle("bad", !idOk);
  $("f-pw").classList.toggle("bad", !pw);
  if (!idOk){ $("m1").textContent = "Enter a valid email address or ID number."; $("identifier").focus(); return; }
  if (!pw){ $("m1").textContent = "Enter your password."; $("password").focus(); return; }
  $("m1").textContent = "";

  busy($("b1"), true, "Logging in…");
  let r;
  try{ r = await post(API.login, { identifier:id, password:pw, remember:$("remember").checked }); }
  finally{ busy($("b1"), false, "Login"); }
  $("password").value = ""; hidePassword();

  if (r.network){ $("m1").textContent = "Can't reach the server. Check your connection and try again."; $("password").focus(); return; }
  if (r.status === 429){ lock(Math.max(5, Math.min(900, +r.data.retryAfter || 30))); return; }
  if (!r.ok){
    state.fails++;
    $("f-id").classList.add("bad"); $("f-pw").classList.add("bad");
    if (state.fails >= 5) lock(30);
    // Generic message: never reveal whether the ID or the password was wrong
    else $("m1").textContent = "Incorrect login details. Check them and try again.";
    $("password").focus();
    return;
  }
  $("f-id").classList.remove("bad"); $("f-pw").classList.remove("bad");
  state.fails = 0;
  if (r.data.needsOtp){ show("otp"); otpBoxes[0].focus(); startResendWait(); }
  else finish(r.data.role);
});

/* ---------- Code view (only when the server asks for it) ---------- */
const otpBoxes = [];
for (let i = 0; i < 6; i++){
  const b = document.createElement("input");
  b.type = "text"; b.inputMode = "numeric"; b.maxLength = 1;
  b.autocomplete = i === 0 ? "one-time-code" : "off";
  b.setAttribute("aria-label", "Digit " + (i+1));
  b.addEventListener("input", () => {
    b.value = b.value.replace(/\D/g, "");
    if (b.value && otpBoxes[i+1]) otpBoxes[i+1].focus();
  });
  b.addEventListener("keydown", e => {
    if (e.key === "Backspace" && !b.value && otpBoxes[i-1]) otpBoxes[i-1].focus();
  });
  b.addEventListener("paste", e => {
    const t = (e.clipboardData.getData("text") || "").replace(/\D/g, "").slice(0, 6);
    if (!t) return;
    e.preventDefault();
    t.split("").forEach((c, k) => otpBoxes[k].value = c);
    otpBoxes[Math.min(t.length, 5)].focus();
  });
  otpBoxes.push(b); $("otp").appendChild(b);
}
const clearOtp = () => otpBoxes.forEach(b => b.value = "");
$("v-otp").addEventListener("submit", async e => {
  e.preventDefault();
  if ($("b2").disabled) return;
  const code = otpBoxes.map(b => b.value).join("");
  if (!/^\d{6}$/.test(code)){ $("m2").textContent = "Enter all 6 digits."; return; }
  $("m2").textContent = "";
  busy($("b2"), true, "Verifying…");
  let r;
  try{ r = await post(API.verifyOtp, { code }); }
  finally{ busy($("b2"), false, "Verify and login"); }
  if (r.network){ $("m2").textContent = "Can't reach the server. Check your connection and try again."; return; }
  if (r.status === 429){ $("m2").textContent = "Too many attempts. Please log in again later."; clearOtp(); return; }
  if (!r.ok){ $("m2").textContent = "That code is incorrect or has expired."; clearOtp(); otpBoxes[0].focus(); return; }
  finish(r.data.role);
});

/* Resend is limited to once every 30 seconds here; the server limits it too */
let resendT;
function startResendWait(){
  clearInterval(resendT); let s = 30; $("resend").disabled = true;
  const upd = () => { $("resend").textContent = s > 0 ? "Send a new code (" + s + "s)" : "Send a new code"; if (s-- <= 0){ clearInterval(resendT); $("resend").disabled = false; } };
  upd(); resendT = setInterval(upd, 1000);
}
$("resend").addEventListener("click", async () => {
  if ($("resend").disabled) return;
  startResendWait();
  const r = await post(API.resendOtp, {});
  $("m2").style.color = r.ok ? "var(--accent)" : "";
  $("m2").textContent = r.ok ? "A new code has been sent." : "Could not send a new code. Try again shortly.";
  setTimeout(() => { $("m2").style.color = ""; $("m2").textContent = ""; }, 3500);
});
$("back").addEventListener("click", () => { clearOtp(); $("m2").textContent = ""; show("login"); $("identifier").focus(); });

/* ---------- Success and redirect (the SERVER decides the role; the page list is fixed above) ---------- */
function finish(role){
  state.role = role;
  const admin = role === "admin";
  const target = DEST[role] || DEFAULT_DEST;
  $("dest").textContent = admin
    ? "Welcome back. You're signed in. Continue to the admin console."
    : "Welcome back. You're signed in. Continue to your registration form.";
  $("go").href = target;
  show("ok");
  $("go").focus();
  if (AUTO_REDIRECT) setTimeout(() => { location.assign(target); }, 2000);
}
