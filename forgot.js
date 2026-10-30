/* ============================================================
   DEMO BACKEND — replace each function with a real fetch() call
   to your server (HTTPS, POST, credentials:"include", CSRF token
   in a header). The SERVER must do the real security work:
     - Always answer requestCode() the same way and in the same
       time, whether or not the account exists.
     - Store only a HASH of the code; single use; expire in 10 min;
       allow 5 attempts; rate-limit per account and per IP.
     - verifyCode() returns a random, single-use reset token that
       expires in 10 minutes.
     - resetPassword() hashes with Argon2/bcrypt, checks the policy
       and breached-password list again, invalidates the token and
       ALL sessions, and emails the owner that the password changed.
   Demo: any valid email/ID works. The code is 123456.
   ============================================================ */
const csrf = document.querySelector('meta[name="csrf-token"]').content;
const wait = ms => new Promise(r => setTimeout(r, ms));
const api = {
  async requestCode(id){                 // POST /api/auth/forgot        { id }
    await wait(800);
    return { ok:true };                  // identical answer for every input
  },
  async verifyCode(code){                // POST /api/auth/forgot/verify { id, code }
    await wait(600);
    return code === "123456" ? { ok:true, token:"demo-single-use-token" } : { ok:false };
  },
  async resetPassword(token, pw){        // POST /api/auth/forgot/reset  { token, password }
    await wait(800);
    return { ok: !!token };
  }
};

const $ = id => document.getElementById(id);
const views = { req:$("v-req"), code:$("v-code"), pw:$("v-pw"), done:$("v-done") };

/* Logo: shows images/logo.png, or the shield if that file is missing */
(function(){
  const img = document.querySelector(".logo-tile img"), fb = document.querySelector(".logo-fallback");
  if (!img || !fb) return;
  const miss = () => { img.hidden = true; fb.hidden = false; };
  img.addEventListener("error", miss);
  if (img.complete && img.naturalWidth === 0) miss();
})();

const CODE_LIFE = 10 * 60 * 1000;   // code valid for 10 minutes
const SESSION_LIFE = 10 * 60 * 1000; // time allowed to set the new password
const RESEND_WAIT = 60 * 1000;      // 60 seconds between sends
const MAX_SENDS = 3;                // per hour
const MAX_TRIES = 5;                // wrong codes before starting over
const state = { id:"", token:null, sends:[], tries:0, expiresAt:0, resendAt:0, ticker:null, sessionTimer:null };

function show(name){
  Object.values(views).forEach(v => v.classList.remove("show"));
  views[name].classList.add("show");
  document.querySelector(".panel").dataset.view = name;
}
function busy(btn, on, label){ btn.disabled = on; btn.textContent = label; }
function mask(v){
  if (v.includes("@")){ const [l, d] = v.split("@"); return l[0] + "•••@" + d; }
  return "•".repeat(Math.max(v.length - 3, 3)) + v.slice(-3);
}
const fmt = ms => { const s = Math.max(0, Math.ceil(ms/1000)); return String(Math.floor(s/60)).padStart(2,"0") + ":" + String(s%60).padStart(2,"0"); };

/* ---------- Start over, wiping everything sensitive from memory and the page ---------- */
function resetFlow(message){
  clearInterval(state.ticker); clearTimeout(state.sessionTimer);
  state.token = null; state.tries = 0;
  otpBoxes.forEach(b => b.value = "");
  ["np","cp"].forEach(id => { $(id).value = ""; $(id).type = "password"; });
  document.querySelectorAll(".toggle").forEach(t => { t.textContent = "Show"; t.setAttribute("aria-pressed","false"); });
  updatePassword();
  $("m2").textContent = ""; $("m3").textContent = "";
  $("m1").textContent = message || "";
  show("req"); $("identifier").focus();
}
window.addEventListener("pagehide", () => { ["np","cp"].forEach(id => $(id).value = ""); state.token = null; });

/* ---------- Step 1: request a code ---------- */
$("v-req").addEventListener("submit", async e => {
  e.preventDefault();
  const id = $("identifier").value.trim();
  const ok = /^\S+@\S+\.\S+$/.test(id) || /^\d{7,10}$/.test(id);
  $("f-id").classList.toggle("bad", !ok);
  if (!ok){ $("m1").textContent = "Enter a valid email address or ID number."; $("identifier").focus(); return; }

  const now = Date.now();
  state.sends = state.sends.filter(t => now - t < 3600000);
  if (state.sends.length >= MAX_SENDS){ $("m1").textContent = "Too many requests. Please try again later."; return; }

  $("m1").textContent = "";
  busy($("b1"), true, "Sending…");
  try{
    if ($("website").value) await wait(800);       // bot trap filled: pretend, send nothing
    else await api.requestCode(id);
  }catch(err){
    busy($("b1"), false, "Send code");
    $("m1").textContent = "Something went wrong. Please try again."; return;
  }
  busy($("b1"), false, "Send code");

  // Same screen every time, so nobody can tell whether the account exists
  state.sends.push(Date.now());
  state.id = id; state.tries = 0;
  state.expiresAt = Date.now() + CODE_LIFE;
  state.resendAt = Date.now() + RESEND_WAIT;
  $("sentTo").textContent = mask(id);
  $("m2").textContent = "";
  show("code"); startTicker(); otpBoxes[0].focus();
});

/* ---------- Step 2: enter the code ---------- */
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

function startTicker(){
  clearInterval(state.ticker);
  const tick = () => {
    const now = Date.now(), left = state.expiresAt - now, wl = state.resendAt - now;
    if (left <= 0){ resetFlow("Your code has expired. Request a new one."); return; }
    $("expires").textContent = fmt(left);
    $("resend").disabled = wl > 0;
    $("resend").textContent = wl > 0 ? "Resend code in " + Math.ceil(wl/1000) + "s" : "Resend code";
  };
  tick(); state.ticker = setInterval(tick, 500);
}

$("resend").addEventListener("click", async () => {
  const now = Date.now();
  state.sends = state.sends.filter(t => now - t < 3600000);
  if (state.sends.length >= MAX_SENDS){ $("m2").textContent = "Too many requests. Please try again later."; return; }
  try{ await api.requestCode(state.id); }catch(err){ $("m2").textContent = "Something went wrong. Please try again."; return; }
  state.sends.push(Date.now()); state.tries = 0;
  state.expiresAt = Date.now() + CODE_LIFE; state.resendAt = Date.now() + RESEND_WAIT;
  otpBoxes.forEach(b => b.value = ""); otpBoxes[0].focus();
  $("m2").style.color = "var(--accent)"; $("m2").textContent = "A new code has been sent.";
  setTimeout(() => { $("m2").style.color = ""; $("m2").textContent = ""; }, 3000);
});
$("other").addEventListener("click", () => resetFlow(""));

$("v-code").addEventListener("submit", async e => {
  e.preventDefault();
  const code = otpBoxes.map(b => b.value).join("");
  if (code.length < 6){ $("m2").textContent = "Enter all 6 digits."; return; }
  busy($("b2"), true, "Verifying…");
  let r;
  try{ r = await api.verifyCode(code); }catch(err){ r = { ok:false }; }
  busy($("b2"), false, "Verify code");

  if (!r.ok){
    state.tries++;
    otpBoxes.forEach(b => b.value = "");
    if (state.tries >= MAX_TRIES){ resetFlow("Too many incorrect codes. Request a new code to continue."); return; }
    $("m2").textContent = "That code is incorrect or has expired."; otpBoxes[0].focus(); return;
  }
  // The token lives only in memory: never in the URL, localStorage or a cookie JavaScript can read
  state.token = r.token;
  clearInterval(state.ticker);
  clearTimeout(state.sessionTimer);
  state.sessionTimer = setTimeout(() => resetFlow("Your reset session timed out. Please start again."), SESSION_LIFE);
  otpBoxes.forEach(b => b.value = "");
  show("pw"); $("np").focus();
});

/* ---------- Step 3: new password ---------- */
function check(pw){
  return {
    len:   pw.length >= 12,
    upper: /[A-Z]/.test(pw),
    lower: /[a-z]/.test(pw),
    num:   /\d/.test(pw),
    sym:   /[^A-Za-z0-9]/.test(pw)
  };
}
function updatePassword(){
  const pw = $("np").value, cf = $("cp").value, r = check(pw);
  document.querySelectorAll("#rules li").forEach(li => li.classList.toggle("met", r[li.dataset.r]));

  const n = Object.values(r).filter(Boolean).length;
  let level = 0;
  if (pw){ level = n <= 2 ? 1 : n === 3 ? 2 : n === 4 ? 3 : (pw.length >= 16 ? 4 : 3); }
  $("meter").dataset.l = level;
  $("meterLabel").textContent = ["Password strength","Weak","Fair","Good","Strong"][level];

  const match = cf.length > 0 && pw === cf;
  $("m3").textContent = cf && !match ? "Passwords don't match." : "";
  $("b3").disabled = !(Object.values(r).every(Boolean) && match);
}
["np","cp"].forEach(id => {
  $(id).addEventListener("input", updatePassword);
  ["keyup","keydown"].forEach(ev => $(id).addEventListener(ev, e => {
    $("caps").style.display = e.getModifierState && e.getModifierState("CapsLock") ? "flex" : "none";
  }));
});
document.querySelectorAll(".toggle").forEach(t => t.addEventListener("click", () => {
  const f = $(t.dataset.for), reveal = f.type === "password";
  f.type = reveal ? "text" : "password";
  t.textContent = reveal ? "Hide" : "Show";
  t.setAttribute("aria-pressed", reveal);
}));

$("v-pw").addEventListener("submit", async e => {
  e.preventDefault();
  const pw = $("np").value;
  if ($("b3").disabled) return;
  busy($("b3"), true, "Resetting…");
  let r;
  try{ r = await api.resetPassword(state.token, pw); }catch(err){ r = { ok:false }; }
  busy($("b3"), false, "Reset password");

  if (!r.ok){ resetFlow("Your reset session has ended. Request a new code."); return; }
  clearTimeout(state.sessionTimer);
  state.token = null;
  ["np","cp"].forEach(id => $(id).value = "");
  updatePassword();
  show("done");
});
