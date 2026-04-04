/* ─── State ─────────────────────────────────────────────────────────── */
let replacementMap = new Map();    // original → token
let reverseMap     = new Map();    // token → original
let mappings       = [];
let counters       = {};
let originalInput  = '';
let sanitizedOutput = '';

/* ─── Active Rules (toggle-able) ────────────────────────────────────── */
const activeRules = {
  ip:    true,
  email: true,
  host:  true,
  user:  true,
  sid:   true,
  token: true,
  path:  true,
  uuid:  true,
  mac:   true,
  phone: true,
  key:   true,
  json:  true,
};

/* ─── Sanitize Patterns ─────────────────────────────────────────────── */
const PATTERNS = {
  // IPv4 and IPv6
  ip:    /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}/g,
  // Email
  email: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
  // Windows SIDs
  sid:   /S-1-[0-9]+-(?:[0-9]+-)*[0-9]+/g,
  // UUIDs / GUIDs
  uuid:  /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
  // MAC addresses
  mac:   /\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b/g,
  // Phone numbers (international + common formats)
  phone: /(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b/g,
  // Secrets/API keys/tokens (long hex or base64-ish strings)
  token: /\b(?:eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*|[A-Za-z0-9]{32,}(?:[_\-][A-Za-z0-9]{4,})*)\b/g,
  // Windows file paths
  path:  /(?:[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*|\/(?:home|usr|etc|var|opt|tmp|root|proc|sys|run)\/[^\s"']+)/g,
  // Hostnames (e.g. DESKTOP-ABC123, WIN-XYZ, server-01.internal)
  host:  /\b(?:DESKTOP|LAPTOP|WIN|PC|SERVER|HOST|NODE|WS)-[A-Z0-9]{3,}\b|\b[a-zA-Z0-9\-]+\.(?:local|internal|corp|lan|intranet)\b/gi,
  // User/account names in KV context (handled specially in JSON pass)
  user:  null, // handled via JSON/KV pass
  // API keys / passwords in KV
  key:   null, // handled via JSON/KV pass
  // JSON fields – handled in json pass
  json:  null,
};

/* ─── JSON/KV Field Patterns ──────────────────────────────────────────  */
const USER_KEYS = ['user','username','account','acct','uid','loginuser','logonuser','samaccountname','targetusername','subjectusername','sender','recipient','from','to','name','cn','displayname','principal','upn','email','mail'];
const HOST_KEYS = ['host','hostname','computer','computername','device','endpoint','machine','workstation','server','domain','fqdn','targetservername','subjectdomainname','workstationname'];
const SECRET_KEYS = ['password','passwd','pwd','pass','secret','apikey','api_key','token','authtoken','auth_token','credential','credentials','key','privatekey','private_key','accesskey','access_key','clientsecret','client_secret'];
const IP_KEYS    = ['ip','ipaddress','ip_address','sourceaddress','src_ip','dst_ip','remoteaddress','clientip','client_ip','serverip','server_ip','ipv4','ipv6','xforwardedfor'];

/* ─── Helpers ────────────────────────────────────────────────────────── */
function resetState() {
  replacementMap.clear();
  reverseMap.clear();
  mappings = [];
  counters = { IP:1, EMAIL:1, USER:1, HOST:1, SID:1, TOKEN:1, PATH:1, UUID:1, MAC:1, PHONE:1, KEY:1, DATA:1 };
}

function getToken(val, type) {
  if (replacementMap.has(val)) return replacementMap.get(val);
  const tok = `[${type}_${counters[type] || 1}]`;
  counters[type] = (counters[type] || 1) + 1;
  replacementMap.set(val, tok);
  reverseMap.set(tok, val);
  mappings.push({ type, original: val, token: tok });
  return tok;
}

/* ─── JSON / KV pass ─────────────────────────────────────────────────── */
function sanitizeJsonKv(text) {
  // Matches: "key": "value"  OR  "key":"value"  OR  key=value  OR  key: value
  // Also handles arrays: "key": ["v1","v2"]

  // JSON string values
  text = text.replace(/"([^"]+)"\s*:\s*"([^"]+)"/g, (match, k, v) => {
    const lk = k.toLowerCase().replace(/[_\s]/g,'');
    if (IP_KEYS.some(x => lk.includes(x)) && activeRules.ip)       return `"${k}": "${getToken(v,'IP')}"`;
    if (HOST_KEYS.some(x => lk.includes(x)) && activeRules.host)   return `"${k}": "${getToken(v,'HOST')}"`;
    if (USER_KEYS.some(x => lk.includes(x)) && activeRules.user)   return `"${k}": "${getToken(v,'USER')}"`;
    if (SECRET_KEYS.some(x => lk.includes(x)) && activeRules.key)  return `"${k}": "${getToken(v,'KEY')}"`;
    return match;
  });

  // JSON array values  "key": ["v1","v2"]
  text = text.replace(/"([^"]+)"\s*:\s*(\[[\s\S]*?\])/g, (match, k, arr) => {
    const lk = k.toLowerCase().replace(/[_\s]/g,'');
    let typeHint = null;
    if (IP_KEYS.some(x => lk.includes(x)) && activeRules.ip)     typeHint = 'IP';
    if (HOST_KEYS.some(x => lk.includes(x)) && activeRules.host) typeHint = 'HOST';
    if (USER_KEYS.some(x => lk.includes(x)) && activeRules.user) typeHint = 'USER';
    if (SECRET_KEYS.some(x => lk.includes(x)) && activeRules.key) typeHint = 'KEY';
    if (!typeHint) return match;
    const cleanArr = arr.replace(/"([^"]+)"/g, (m, v) => `"${getToken(v, typeHint)}"`);
    return `"${k}": ${cleanArr}`;
  });

  // key=value  (ini / syslog style)
  text = text.replace(/\b([A-Za-z_][A-Za-z0-9_]*)=([^\s,;|&\n"]+)/g, (match, k, v) => {
    const lk = k.toLowerCase();
    if (IP_KEYS.some(x => lk.includes(x)) && activeRules.ip)       return `${k}=${getToken(v,'IP')}`;
    if (HOST_KEYS.some(x => lk.includes(x)) && activeRules.host)   return `${k}=${getToken(v,'HOST')}`;
    if (USER_KEYS.some(x => lk.includes(x)) && activeRules.user)   return `${k}=${getToken(v,'USER')}`;
    if (SECRET_KEYS.some(x => lk.includes(x)) && activeRules.key)  return `${k}=${getToken(v,'KEY')}`;
    return match;
  });

  // XML/CEF style  Key="Value"
  text = text.replace(/\b([A-Za-z_][A-Za-z0-9_]*)="([^"]+)"/g, (match, k, v) => {
    const lk = k.toLowerCase();
    if (IP_KEYS.some(x => lk.includes(x)) && activeRules.ip)       return `${k}="${getToken(v,'IP')}"`;
    if (HOST_KEYS.some(x => lk.includes(x)) && activeRules.host)   return `${k}="${getToken(v,'HOST')}"`;
    if (USER_KEYS.some(x => lk.includes(x)) && activeRules.user)   return `${k}="${getToken(v,'USER')}"`;
    if (SECRET_KEYS.some(x => lk.includes(x)) && activeRules.key)  return `${k}="${getToken(v,'KEY')}"`;
    return match;
  });

  return text;
}

/* ─── Main Sanitize ──────────────────────────────────────────────────── */
function sanitizeLog() {
  const input = document.getElementById('rawInput').value.trim();
  if (!input) { showToast('Paste some logs first!', 'warn'); return; }

  resetState();
  originalInput = input;
  let text = input;

  // 1. JSON/KV pass (most precise)
  if (activeRules.json || activeRules.user || activeRules.host || activeRules.key) {
    text = sanitizeJsonKv(text);
  }

  // 2. Global pattern passes (order matters — more specific first)
  const order = ['sid','uuid','mac','email','ip','phone','path','host','token'];
  for (const rule of order) {
    if (!activeRules[rule] || !PATTERNS[rule]) continue;
    PATTERNS[rule].lastIndex = 0;
    const type = rule.toUpperCase();
    text = text.replace(PATTERNS[rule], (m) => {
      // Don't re-tokenize already-tokenized values
      if (m.startsWith('[') && m.endsWith(']')) return m;
      return getToken(m, type);
    });
  }

  sanitizedOutput = text;
  document.getElementById('safeOutput').value = text;

  updateStats();
  renderFindings();
  renderMappingTable();
  renderDiff();

  document.getElementById('results').classList.remove('hidden');
  document.getElementById('results').scrollIntoView({ behavior:'smooth', block:'start' });
}

/* ─── Stats ──────────────────────────────────────────────────────────── */
function updateStats() {
  const counts = {};
  for (const m of mappings) {
    counts[m.type] = (counts[m.type] || 0) + 1;
  }
  const total = mappings.length;
  const unique = new Set(mappings.map(m=>m.original)).size;

  document.getElementById('s-total').textContent = total;
  document.getElementById('s-unique').textContent = unique;
  document.getElementById('s-ips').textContent    = counts['IP'] || 0;
  document.getElementById('s-emails').textContent = counts['EMAIL'] || 0;
  document.getElementById('s-users').textContent  = counts['USER'] || 0;
  document.getElementById('s-keys').textContent   = (counts['KEY'] || 0) + (counts['TOKEN'] || 0);

  document.getElementById('tab-badge-mappings').textContent = total;
  document.getElementById('tab-badge-findings').textContent = total > 0 ? buildFindings().length : 0;
}

/* ─── Findings ────────────────────────────────────────────────────────  */
function buildFindings() {
  const findings = [];
  const counts = {};
  for (const m of mappings) counts[m.type] = (counts[m.type]||0)+1;

  if (mappings.length === 0) {
    findings.push({ type:'green', icon:'✓', title:'No sensitive data detected', desc:'The log appears clean — no PII, credentials, or network identifiers were found.' });
    return findings;
  }

  if (counts['KEY'] || counts['TOKEN']) {
    findings.push({ type:'red', icon:'🔑', title:`${(counts['KEY']||0)+(counts['TOKEN']||0)} credential/secret value(s) detected`, desc:'API keys, passwords, tokens, or secrets found. These must be redacted before sharing.' });
  }
  if (counts['SID']) {
    findings.push({ type:'red', icon:'🪪', title:`${counts['SID']} Windows SID(s) found`, desc:'Security Identifiers (SIDs) can be used to enumerate Active Directory accounts.' });
  }
  if (counts['EMAIL']) {
    findings.push({ type:'amber', icon:'✉️', title:`${counts['EMAIL']} email address(es) found`, desc:'Email addresses are PII under GDPR/CCPA. Redact before sharing externally.' });
  }
  if (counts['IP']) {
    findings.push({ type:'amber', icon:'🌐', title:`${counts['IP']} IP address(es) found`, desc:'Network identifiers may reveal internal infrastructure topology.' });
  }
  if (counts['USER']) {
    findings.push({ type:'amber', icon:'👤', title:`${counts['USER']} username/account field(s) found`, desc:'Usernames can be used for enumeration and social engineering attacks.' });
  }
  if (counts['HOST']) {
    findings.push({ type:'blue', icon:'🖥️', title:`${counts['HOST']} hostname(s) detected`, desc:'Hostnames may reveal internal naming conventions or machine roles.' });
  }
  if (counts['UUID']) {
    findings.push({ type:'blue', icon:'🔷', title:`${counts['UUID']} UUID/GUID(s) found`, desc:'Session, object, or device identifiers that could aid correlation attacks.' });
  }
  if (counts['PATH']) {
    findings.push({ type:'blue', icon:'📁', title:`${counts['PATH']} file path(s) found`, desc:'File system paths may reveal directory structure or software installed.' });
  }
  if (counts['MAC']) {
    findings.push({ type:'blue', icon:'🔌', title:`${counts['MAC']} MAC address(es) found`, desc:'Hardware identifiers that can be used for device fingerprinting.' });
  }
  if (counts['PHONE']) {
    findings.push({ type:'amber', icon:'📞', title:`${counts['PHONE']} phone number(s) found`, desc:'Phone numbers are PII. Redact before sharing with external parties.' });
  }
  findings.push({ type:'green', icon:'✓', title:`${mappings.length} items sanitized — safe to share`, desc:'All detected sensitive values have been replaced with reversible tokens. Use the Mapping tab to restore original values.' });
  return findings;
}

function renderFindings() {
  const list = document.getElementById('findings-list');
  const findings = buildFindings();
  document.getElementById('tab-badge-findings').textContent = findings.filter(f=>f.type!=='green').length || '';
  list.innerHTML = findings.map(f => `
    <div class="finding finding-${f.type}">
      <div class="finding-icon">${f.icon}</div>
      <div class="finding-body">
        <div class="finding-title">${f.title}</div>
        <div class="finding-desc">${f.desc}</div>
      </div>
    </div>`).join('');
}

/* ─── Mapping Table ──────────────────────────────────────────────────── */
function renderMappingTable(filter = 'ALL') {
  const tbody = document.getElementById('mapping-tbody');
  const filtered = filter === 'ALL' ? mappings : mappings.filter(m => m.type === filter);

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4"><div class="empty-state"><svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2"><circle cx="12" cy="12" r="10"/><path d="M8 12h8M12 8v8"/></svg>No entries found</div></td></tr>`;
    return;
  }

  tbody.innerHTML = filtered.map((item, i) => `
    <tr>
      <td class="td-type"><span class="type-pill type-${item.type.toLowerCase()}">${item.type}</span></td>
      <td class="td-original">${escHtml(item.original)}</td>
      <td class="td-token">${escHtml(item.token)}</td>
      <td><button class="btn-restore-row" onclick="restoreSingle('${escAttr(item.token)}')">Restore</button></td>
    </tr>`).join('');
}

function buildTypeFilter() {
  const types = [...new Set(mappings.map(m=>m.type))];
  const bar = document.getElementById('type-filter-bar');
  if (!bar) return;
  bar.innerHTML = ['ALL',...types].map(t =>
    `<button class="rule-chip ${t==='ALL'?'active-ip':'active-'+t.toLowerCase()}" onclick="filterMapping('${t}',this)">${t}</button>`
  ).join('');
}

function filterMapping(type, el) {
  document.querySelectorAll('#type-filter-bar .rule-chip').forEach(b => b.classList.add('inactive'));
  document.querySelectorAll('#type-filter-bar .rule-chip').forEach(b => b.classList.remove('active-ip','active-email','active-host','active-user','active-sid','active-token','active-path','active-uuid','active-mac','active-phone','active-key'));
  el.classList.remove('inactive');
  renderMappingTable(type);
}

/* ─── Diff View ──────────────────────────────────────────────────────── */
function renderDiff() {
  const container = document.getElementById('diff-view');
  if (!sanitizedOutput) { container.textContent = ''; return; }

  // Highlight tokens in the sanitized output
  let html = escHtml(sanitizedOutput).replace(/\[([A-Z]+)_(\d+)\]/g, (m) =>
    `<span class="diff-token">${m}</span>`
  );
  container.innerHTML = html;
}

/* ─── Restore ─────────────────────────────────────────────────────────── */
function restoreSingle(token) {
  const original = reverseMap.get(token);
  if (!original) return;
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const newVal = document.getElementById('safeOutput').value.replace(new RegExp(escaped,'g'), original);
  document.getElementById('safeOutput').value = newVal;
  sanitizedOutput = newVal;

  // Remove from mappings
  const idx = mappings.findIndex(m=>m.token===token);
  if (idx > -1) mappings.splice(idx, 1);
  reverseMap.delete(token);
  replacementMap.delete(original);

  renderDiff();
  renderMappingTable();
  renderFindings();
  updateStats();
}

function restoreAll() {
  document.getElementById('safeOutput').value = originalInput;
  sanitizedOutput = originalInput;
  resetState();
  renderDiff();
  renderMappingTable();
  renderFindings();
  updateStats();
}

/* ─── File Upload ─────────────────────────────────────────────────────── */
function handleFileUpload(e) {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (ev) => {
    document.getElementById('rawInput').value = ev.target.result;
    document.getElementById('file-badge').textContent = file.name;
    document.getElementById('file-badge').classList.remove('hidden');
  };
  reader.readAsText(file);
}

/* ─── Drop Zone ──────────────────────────────────────────────────────── */
function initDropZone() {
  const dz = document.getElementById('dropZone');
  const ta = document.getElementById('rawInput');
  dz.addEventListener('click', () => document.getElementById('logFileInput').click());
  dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('drag-over'); });
  dz.addEventListener('dragleave', () => dz.classList.remove('drag-over'));
  dz.addEventListener('drop', e => {
    e.preventDefault(); dz.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => { ta.value = ev.target.result; };
    reader.readAsText(file);
  });
}

/* ─── Rule Toggles ────────────────────────────────────────────────────── */
function toggleRule(rule, el) {
  activeRules[rule] = !activeRules[rule];
  if (activeRules[rule]) {
    el.classList.remove('inactive');
  } else {
    el.classList.add('inactive');
  }
}

/* ─── Tab Switching ──────────────────────────────────────────────────── */
function switchTab(el, tab) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.add('hidden'));
  el.classList.add('active');
  document.getElementById('tab-' + tab).classList.remove('hidden');
  if (tab === 'mappings') { buildTypeFilter(); renderMappingTable(); }
}

/* ─── Clear / Copy ────────────────────────────────────────────────────── */
function clearAll() {
  document.getElementById('rawInput').value = '';
  document.getElementById('safeOutput').value = '';
  document.getElementById('file-badge').classList.add('hidden');
  document.getElementById('results').classList.add('hidden');
  resetState();
  sanitizedOutput = '';
  originalInput = '';
}

function copyOutput() {
  const val = document.getElementById('safeOutput').value;
  if (!val) { showToast('Nothing to copy yet', 'warn'); return; }
  navigator.clipboard.writeText(val).then(() => showToast('Copied to clipboard!', 'ok'));
}

function downloadOutput() {
  const val = document.getElementById('safeOutput').value;
  if (!val) return;
  const blob = new Blob([val], {type:'text/plain'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'sanitized-log.txt';
  a.click();
}

/* ─── Export Mapping CSV ─────────────────────────────────────────────── */
function exportMappingCSV() {
  if (!mappings.length) return;
  const rows = [['Type','Original','Token'],...mappings.map(m=>[m.type,m.original,m.token])];
  const csv = rows.map(r=>r.map(c=>`"${c.replace(/"/g,'""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], {type:'text/csv'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'sanitizer-mapping.csv';
  a.click();
}

/* ─── Toast ──────────────────────────────────────────────────────────── */
function showToast(msg, type='ok') {
  const t = document.createElement('div');
  t.style.cssText = `position:fixed;bottom:24px;right:24px;z-index:9999;background:var(--surface);border:1px solid var(--border2);padding:10px 18px;border-radius:8px;font-family:var(--font-mono);font-size:12px;color:${type==='ok'?'var(--accent)':'var(--amber)'};box-shadow:0 8px 32px rgba(0,0,0,0.4);animation:fadeIn 0.3s ease;`;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 2500);
}

/* ─── Utils ──────────────────────────────────────────────────────────── */
function escHtml(s) { return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function escAttr(s) { return s.replace(/'/g,"\\'"); }

/* ─── Init ───────────────────────────────────────────────────────────── */
window.addEventListener('DOMContentLoaded', initDropZone);
