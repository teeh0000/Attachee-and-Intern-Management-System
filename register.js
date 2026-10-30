/* ============================================================
   DEMO BACKEND — replace each function with a real fetch() call
   to your server (HTTPS, POST, credentials:"include", CSRF token
   in a header). The SERVER must do the real security work:
     - Re-validate EVERY field. Never trust this page.
     - Accept only "attachee" or "intern" as the account type.
       Admin accounts are NEVER created here.
     - If the email or ID already exists, answer exactly as for a
       new account (same screen, same timing) and email the owner
       "you already have an account" instead. No account leaks.
     - Hash the password with Argon2/bcrypt; check the breached-
       password list; encrypt the ID number in the database.
     - The account stays INACTIVE until the email code is verified.
       Store only a hash of the code; single use; 10-minute expiry;
       5 attempts; rate-limit per email and per IP; add CAPTCHA after
       repeated sign-ups from one IP.
   Demo: any valid details work. The code is 123456.
   ============================================================ */
const csrf = document.querySelector('meta[name="csrf-token"]').content;
const wait = ms => new Promise(r => setTimeout(r, ms));
const api = {
  async register(data){                 // POST /api/auth/register  { fullName, email, idNumber, phone, university, type, password, consent }
    await wait(900);
    return { ok:true };                 // identical answer for every input
  },
  async verifyEmail(email, code){       // POST /api/auth/verify-email { email, code }
    await wait(600);
    return { ok: code === "123456" };
  },
  async resendCode(email){              // POST /api/auth/resend-code { email }
    await wait(500);
    return { ok:true };
  }
};

const $ = id => document.getElementById(id);

/* Logo: shows images/logo.png, or the shield if that file is missing */
(function(){
  const img = document.querySelector(".logo-tile img"), fb = document.querySelector(".logo-fallback");
  if (!img || !fb) return;
  const miss = () => { img.hidden = true; fb.hidden = false; };
  img.addEventListener("error", miss);
  if (img.complete && img.naturalWidth === 0) miss();
})();
const views = { s1:$("v-s1"), s2:$("v-s2"), s3:$("v-s3"), verify:$("v-verify"), done:$("v-done") };
const STEP = { s1:1, s2:2, s3:3, verify:4, done:5 };

const CODE_LIFE = 10 * 60 * 1000, RESEND_WAIT = 60 * 1000, MAX_SENDS = 3, MAX_TRIES = 5;
const state = { email:"", sends:[], tries:0, expiresAt:0, resendAt:0, ticker:null };

/* Kenyan universities for the step 2 dropdown (users can also type their own) */
const UNIVERSITIES = [
  "University of Nairobi","Kenyatta University","Moi University","Egerton University",
  "Jomo Kenyatta University of Agriculture and Technology (JKUAT)","Maseno University",
  "Masinde Muliro University of Science and Technology","Dedan Kimathi University of Technology",
  "Technical University of Kenya","Technical University of Mombasa","Multimedia University of Kenya",
  "Chuka University","Embu University","Kisii University","Laikipia University","Maasai Mara University",
  "Meru University of Science and Technology","South Eastern Kenya University","Pwani University",
  "Taita Taveta University","Jaramogi Oginga Odinga University of Science and Technology",
  "Kibabii University","Karatina University","Machakos University","Rongo University",
  "University of Eldoret","Murang’a University of Technology","Kirinyaga University",
  "The Cooperative University of Kenya","Tom Mboya University","Tharaka University","Garissa University",
  "Alupe University","Bomet University","Koitaleel Samoei University","Open University of Kenya",
  "Strathmore University","United States International University – Africa (USIU-A)","Daystar University",
  "Catholic University of Eastern Africa","KCA University","Mount Kenya University",
  "Kenya Methodist University","Africa Nazarene University","Pan Africa Christian University",
  "Scott Christian University","St. Paul’s University","Adventist University of Africa",
  "Great Lakes University of Kisumu","GRETSA University","Kabarak University","KAG East University",
  "Riara University","Zetech University","Lukenya University","Presbyterian University of East Africa",
  "UMMA University","Management University of Africa","Aga Khan University","Africa International University",
  "Inoorero University","Hekima University College","Tangaza University","Uzima University",
  "Kenya Highlands Evangelical University","Mama Ngina University"
].sort();

function show(name){
  Object.values(views).forEach(v => v.classList.remove("show"));
  views[name].classList.add("show");
  document.querySelectorAll("#steps li").forEach((li, i) => {
    li.classList.toggle("done", i + 1 < STEP[name]);
    li.classList.toggle("on", i + 1 === STEP[name]);
  });
}
function busy(btn, on, label){ btn.disabled = on; btn.textContent = label; }
const mask = v => { const [l, d] = v.split("@"); return l[0] + "•••@" + d; };
const fmt = ms => { const s = Math.max(0, Math.ceil(ms/1000)); return String(Math.floor(s/60)).padStart(2,"0") + ":" + String(s%60).padStart(2,"0"); };

/* ---------- Field validation ---------- */
const DAY = 864e5, MAX_MONTHS = 12, BACKDATE_DAYS = 30;
const iso = d => d.toISOString().slice(0, 10);
function maxEnd(s){ const d = new Date(s); d.setUTCMonth(d.getUTCMonth() + MAX_MONTHS); return iso(d); }
const rulesFor = {
  fullname:   { test: v => /^\p{L}[\p{L}.'’ -]*\s+\p{L}[\p{L}.'’ -]*$/u.test(v.trim()), msg: "Enter your full name (first and last name)." },
  email:      { test: v => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v.trim()),             msg: "Enter a valid email address." },
  idno:       { test: v => /^\d{7,10}$/.test(v.trim()),                                  msg: "Enter a valid ID number (7 to 10 digits)." },
  phone:      { test: v => /^(\+?254|0)[71]\d{8}$/.test(v.replace(/[\s-]/g, "")),       msg: "Enter a valid Kenyan phone number, like 0712 345 678." },
  university: { test: v => /^[\p{L}0-9&.,'’()\/– -]{3,100}$/u.test(v.trim()),           msg: "Select your university from the list, or type its name." },
  department: { test: v => v !== "",                                                      msg: "Select your department." },
  study:      { test: v => /^[\p{L}0-9&,.()'’\/ -]{2,80}$/u.test(v.trim()),              msg: "Enter your area of study, like Computer Science." },
  startDate:  { test: v => v !== "" && v >= iso(new Date(Date.now() - BACKDATE_DAYS * DAY)), msg: "Choose a valid start date (not more than 30 days ago)." },
  endDate:    { test: v => { const s = $("startDate").value; return v !== "" && s !== "" && v > s && v <= maxEnd(s); }, msg: "Choose an end date after the start date, up to 12 months." }
};
function setError(key, msg){
  $("f-" + key).classList.toggle("bad", !!msg);
  $("e-" + key).textContent = msg || "";
  // Tell assistive technology which field is invalid
  const target = $("f-" + key).querySelector('[role="radiogroup"], input');
  if (target) target.setAttribute("aria-invalid", msg ? "true" : "false");
}
function checkField(key){
  const ok = rulesFor[key].test($(key).value);
  setError(key, ok ? "" : rulesFor[key].msg);
  return ok;
}
Object.keys(rulesFor).forEach(k => {
  $(k).addEventListener("blur", () => { if ($(k).value) checkField(k); });
  $(k).addEventListener("input", () => { if ($("f-" + k).classList.contains("bad")) checkField(k); });
});
$("idno").addEventListener("input", () => { $("idno").value = $("idno").value.replace(/\D/g, ""); });
document.querySelectorAll('input[name="type"],input[name="gender"]').forEach(r => r.addEventListener("change", () => setError(r.name, "")));

/* ---------- University combobox: pick from the list or type your own ---------- */
(function(){
  const box = $("combo"), input = $("university"), list = $("uniList"), btn = $("uniBtn");
  let active = -1;
  const esc = s => s.replace(/[&<>"]/g, c => ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;" }[c]));
  const options = () => Array.from(list.querySelectorAll("li[data-v]"));
  function open(){ list.hidden = false; box.classList.add("open"); input.setAttribute("aria-expanded", "true"); }
  function close(){ list.hidden = true; box.classList.remove("open"); input.setAttribute("aria-expanded", "false"); input.removeAttribute("aria-activedescendant"); active = -1; }
  function render(){
    const typed = input.value.trim(), q = typed.toLowerCase();
    let html = UNIVERSITIES.filter(u => u.toLowerCase().includes(q))
      .map((u, i) => '<li role="option" id="uni-' + i + '" data-v="' + esc(u) + '">' + esc(u) + "</li>").join("");
    if (typed && !UNIVERSITIES.some(u => u.toLowerCase() === q))
      html += '<li role="option" id="uni-own" class="own" data-v="' + esc(typed) + '">Use “' + esc(typed) + "”</li>";
    list.innerHTML = html || '<li class="empty" aria-disabled="true">Start typing your university</li>';
    active = -1; open();
  }
  function setActive(i){
    const o = options(); if (!o.length) return;
    active = (i + o.length) % o.length;
    o.forEach((li, k) => li.classList.toggle("act", k === active));
    input.setAttribute("aria-activedescendant", o[active].id);
    o[active].scrollIntoView({ block:"nearest" });
  }
  function pick(v){ input.value = v; close(); checkField("university"); }
  input.addEventListener("focus", render);
  input.addEventListener("input", render);
  btn.addEventListener("mousedown", e => { e.preventDefault(); if (list.hidden){ input.focus(); render(); } else close(); });
  list.addEventListener("mousedown", e => { e.preventDefault(); const li = e.target.closest("li[data-v]"); if (li) pick(li.dataset.v); });
  input.addEventListener("keydown", e => {
    if (e.key === "ArrowDown"){ e.preventDefault(); if (list.hidden) render(); setActive(active + 1); }
    else if (e.key === "ArrowUp"){ e.preventDefault(); if (list.hidden) render(); setActive(active - 1); }
    else if (e.key === "Enter" && !list.hidden && active > -1){ e.preventDefault(); pick(options()[active].dataset.v); }
    else if (e.key === "Escape") close();
  });
  box.addEventListener("focusout", () => setTimeout(() => { if (!box.contains(document.activeElement)) close(); }, 0));
})();

/* Period: live duration, and keep the end date within range of the start date */
function syncDates(){
  const s = $("startDate").value, e = $("endDate").value;
  $("endDate").min = s || ""; $("endDate").max = s ? maxEnd(s) : "";
  if (s && e && e > s){
    const days = Math.round((new Date(e) - new Date(s)) / DAY);
    $("duration").textContent = "Duration: " + (days < 60 ? days + " days" : (Math.round(days / 30.44 * 10) / 10) + " months");
  } else $("duration").textContent = "";
  if (e) checkField("endDate");
}
$("startDate").min = iso(new Date(Date.now() - BACKDATE_DAYS * DAY));
["startDate","endDate"].forEach(id => $(id).addEventListener("input", syncDates));
$("consent").addEventListener("change", () => setError("consent", ""));

const normalisePhone = v => {
  const d = v.replace(/[\s-]/g, "");
  return d.startsWith("+254") ? d : d.startsWith("254") ? "+" + d : "+254" + d.slice(1);
};

/* ---------- Password: rules, strength meter, confirmation ---------- */
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
  const n = ["len","upper","lower","num","sym"].filter(k => r[k]).length;
  let level = 0;
  if (pw){ level = n <= 2 ? 1 : n === 3 ? 2 : n === 4 ? 3 : (pw.length >= 16 ? 4 : 3); }
  $("meter").dataset.l = level;
  $("meterLabel").textContent = ["Password strength","Weak","Fair","Good","Strong"][level];
  if (Object.values(r).every(Boolean)){ $("e-np").classList.remove("on"); $("np").setAttribute("aria-invalid", "false"); }
  setError("cp", cf && pw !== cf ? "Passwords don't match." : "");
  return r;
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

/* ---------- Submit the form ---------- */
function validateStep1(){
  let first = null;
  const flag = el => { if (!first) first = el; };
  ["fullname","idno","phone"].forEach(k => { if (!checkField(k)) flag($(k)); });
  if (!document.querySelector('input[name="gender"]:checked')){
    setError("gender", "Select your gender.");
    flag(document.querySelector('input[name="gender"]'));
  }
  return first;
}
function validateStep2(){
  let first = null;
  const flag = el => { if (!first) first = el; };
  ["university","department","study"].forEach(k => { if (!checkField(k)) flag($(k)); });
  if (!document.querySelector('input[name="type"]:checked')){
    setError("type", "Choose whether you are an attachee or an intern.");
    flag(document.querySelector('input[name="type"]'));
  }
  ["startDate","endDate"].forEach(k => { if (!checkField(k)) flag($(k)); });
  return first;
}
function validateStep3(){
  let first = null;
  const flag = el => { if (!first) first = el; };
  if (!checkField("email")) flag($("email"));

  const r = updatePassword();
  if (!Object.values(r).every(Boolean)){
    $("e-np").textContent = "Choose a password that meets all the requirements above.";
    $("e-np").classList.add("on"); $("np").setAttribute("aria-invalid", "true"); flag($("np"));
  }
  if (!$("cp").value || $("cp").value !== $("np").value){
    setError("cp", $("cp").value ? "Passwords don't match." : "Confirm your password."); flag($("cp"));
  }
  if (!$("consent").checked){ setError("consent", "You need to agree before creating an account."); flag($("consent")); }
  return first;
}


/* Steps 1 and 2 validate, then move on */
function next(formId, validator, msgId, to, focusId){
  $(formId).addEventListener("submit", e => {
    e.preventDefault();
    $(msgId).textContent = "";
    const bad = validator();
    if (bad){ $(msgId).textContent = "Please complete all required fields correctly."; bad.focus(); return; }
    show(to); $(focusId).focus();
  });
}
next("v-s1", validateStep1, "m0", "s2", "university");
next("v-s2", validateStep2, "m0b", "s3", "email");
$("back2").addEventListener("click", () => { show("s1"); $("fullname").focus(); });
$("back").addEventListener("click", () => { show("s2"); $("department").focus(); });

/* Step 3 -> create the account */
$("v-s3").addEventListener("submit", async e => {
  e.preventDefault();
  $("m1").textContent = "";
  const bad = validateStep3();
  if (bad){ $("m1").textContent = "Please complete all required fields correctly."; bad.focus(); return; }

  const now = Date.now();
  state.sends = state.sends.filter(t => now - t < 3600000);
  if (state.sends.length >= MAX_SENDS){ $("m1").textContent = "Too many attempts. Please try again later."; return; }

  busy($("b1"), true, "Creating account…");
  try{
    if ($("website").value) await wait(900);          // bot trap filled: pretend, create nothing
    else await api.register({
      fullName: $("fullname").value.trim(),
      email: $("email").value.trim().toLowerCase(),
      idNumber: $("idno").value.trim(),
      phone: normalisePhone($("phone").value),
      gender: document.querySelector('input[name="gender"]:checked').value,
      university: $("university").value.trim(),
      department: $("department").value,
      areaOfStudy: $("study").value.trim(),
      startDate: $("startDate").value,
      endDate: $("endDate").value,
      type: document.querySelector('input[name="type"]:checked').value,
      password: $("np").value,
      consent: true
    });
  }catch(err){
    busy($("b1"), false, "Create account");
    $("m1").textContent = "Something went wrong. Please try again."; return;
  }
  busy($("b1"), false, "Create account");

  state.sends.push(Date.now());
  state.email = $("email").value.trim().toLowerCase(); state.tries = 0;
  state.expiresAt = Date.now() + CODE_LIFE; state.resendAt = Date.now() + RESEND_WAIT;
  $("sentTo").textContent = mask(state.email);
  $("m2").textContent = "";
  show("verify"); startTicker(); otpBoxes[0].focus();
});

/* ---------- Verify the email code ---------- */
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
    if (left <= 0){ backToForm("Your code has expired. Submit the form again to get a new one."); return; }
    $("expires").textContent = fmt(left);
    $("resend").disabled = wl > 0;
    $("resend").textContent = wl > 0 ? "Resend code in " + Math.ceil(wl/1000) + "s" : "Resend code";
  };
  tick(); state.ticker = setInterval(tick, 500);
}
function backToForm(message){
  clearInterval(state.ticker);
  otpBoxes.forEach(b => b.value = "");
  $("m1").textContent = message || "";
  show("s3");
}

$("resend").addEventListener("click", async () => {
  const now = Date.now();
  state.sends = state.sends.filter(t => now - t < 3600000);
  if (state.sends.length >= MAX_SENDS){ $("m2").textContent = "Too many requests. Please try again later."; return; }
  try{ await api.resendCode(state.email); }catch(err){ $("m2").textContent = "Something went wrong. Please try again."; return; }
  state.sends.push(Date.now()); state.tries = 0;
  state.expiresAt = Date.now() + CODE_LIFE; state.resendAt = Date.now() + RESEND_WAIT;
  otpBoxes.forEach(b => b.value = ""); otpBoxes[0].focus();
  $("m2").style.color = "var(--accent)"; $("m2").textContent = "A new code has been sent.";
  setTimeout(() => { $("m2").style.color = ""; $("m2").textContent = ""; }, 3000);
});
$("change").addEventListener("click", () => { backToForm(""); $("email").focus(); });

$("v-verify").addEventListener("submit", async e => {
  e.preventDefault();
  const code = otpBoxes.map(b => b.value).join("");
  if (code.length < 6){ $("m2").textContent = "Enter all 6 digits."; return; }
  busy($("b2"), true, "Verifying…");
  let r;
  try{ r = await api.verifyEmail(state.email, code); }catch(err){ r = { ok:false }; }
  busy($("b2"), false, "Verify and finish");

  if (!r.ok){
    state.tries++;
    otpBoxes.forEach(b => b.value = "");
    if (state.tries >= MAX_TRIES){ backToForm("Too many incorrect codes. Submit the form again to get a new code."); return; }
    $("m2").textContent = "That code is incorrect or has expired."; otpBoxes[0].focus(); return;
  }
  clearInterval(state.ticker);
  ["np","cp"].forEach(id => $(id).value = "");
  const fmtDate = v => new Date(v).toLocaleDateString("en-KE", { day:"numeric", month:"short", year:"numeric", timeZone:"UTC" });
  $("rName").textContent = $("fullname").value.trim();
  $("rUni").textContent = $("university").value.trim();
  $("rType").textContent = document.querySelector('input[name="type"]:checked').value === "intern" ? "Intern" : "Attachee";
  $("rDept").textContent = $("department").value;
  $("rPeriod").textContent = fmtDate($("startDate").value) + " to " + fmtDate($("endDate").value);
  show("done");
});

/* Never leave passwords sitting in the page when the user navigates away */
window.addEventListener("pagehide", () => { ["np","cp"].forEach(id => $(id).value = ""); });
