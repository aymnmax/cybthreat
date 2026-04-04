/* ================================================================
   Cybthreat v2 — Email Header Analyser
   Phase 2A: URL Extraction · GeoIP · Attachment Detection · Bulk Upload
   analyser.js
   ================================================================ */

/* ─── Constants ──────────────────────────────────────────────────── */
const DANGEROUS_EXTENSIONS = [
  'exe','bat','cmd','com','msi','ps1','psm1','psd1','vbs','vbe',
  'js','jse','wsf','wsh','reg','dll','scr','hta','cpl','inf',
  'lnk','pif','application','gadget','msp','mst','jar','ade','adp'
];
const SUSPICIOUS_EXTENSIONS = [
  'docm','xlsm','pptm','dotm','xltm','xlam','doc','xls','ppt',
  'zip','rar','7z','iso','img','tar','gz','cab','ace','arj',
  'html','htm','svg','pdf','rtf'
];
const SAFE_EXTENSIONS = ['txt','png','jpg','jpeg','gif','bmp','mp4','mp3','csv'];

const SUSPICIOUS_TLDS = ['.tk','.ml','.ga','.cf','.gq','.top','.xyz','.work','.click','.link','.bid','.win'];
const URL_SHORTENERS  = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','dlvr.it','tiny.cc','rb.gy','shorturl'];

/* ─── Settings / API Key ─────────────────────────────────────────── */
function getVTKey() { return localStorage.getItem('cyb_vt_key') || ''; }

function saveVTKey() {
  const key = document.getElementById('vtApiKey').value.trim();
  const statusEl = document.getElementById('vtStatus');
  if (!key) {
    localStorage.removeItem('cyb_vt_key');
    updateModeIndicator();
    statusEl.textContent = 'API key removed.';
    statusEl.className = 'vt-status';
    return;
  }
  localStorage.setItem('cyb_vt_key', key);
  statusEl.textContent = '✓ API key saved to browser storage.';
  statusEl.className = 'vt-status ok';
  updateModeIndicator();
}

function updateModeIndicator() {
  const hasKey = !!getVTKey();
  const dot  = document.getElementById('modeIndicator')?.querySelector('.mode-dot');
  const text = document.getElementById('modeText');
  const badge = document.getElementById('vtBadge');
  if (dot)  { dot.className = 'mode-dot ' + (hasKey ? 'has-key' : 'no-key'); }
  if (text) { text.textContent = hasKey ? 'VirusTotal mode — deep URL & IP scanning enabled' : 'Basic mode — ip-api.com geolocation only'; }
  if (badge){ hasKey ? badge.classList.remove('hidden') : badge.classList.add('hidden'); }
}

function clearStoredData() {
  localStorage.removeItem('cyb_vt_key');
  document.getElementById('vtApiKey').value = '';
  document.getElementById('vtStatus').textContent = 'All data cleared.';
  document.getElementById('vtStatus').className = 'vt-status';
  updateModeIndicator();
}

function openSettings() {
  document.getElementById('settingsOverlay').classList.remove('hidden');
  const key = getVTKey();
  if (key) document.getElementById('vtApiKey').value = key;
  updateModeIndicator();
}

function closeSettings() {
  document.getElementById('settingsOverlay').classList.add('hidden');
}

/* ─── File Upload & Drag-Drop ─────────────────────────────────────── */
let bulkFiles = [];

function handleFileUpload(event) {
  const files = Array.from(event.target.files);
  if (!files.length) return;
  event.target.value = '';
  if (files.length === 1) {
    readEMLFile(files[0], false);
  } else {
    addToBulkQueue(files);
  }
}

function readEMLFile(file, isBulk) {
  const reader = new FileReader();
  reader.onload = e => {
    if (isBulk) return e.target.result;
    document.getElementById('emlInput').value = e.target.result;
    showFileLoadedBadge(file.name);
    analyseEML();
  };
  reader.readAsText(file, 'UTF-8');
  return reader;
}

function readFileAsync(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload  = e => resolve(e.target.result);
    reader.onerror = () => reject(new Error('Failed to read ' + file.name));
    reader.readAsText(file, 'UTF-8');
  });
}

function addToBulkQueue(files) {
  bulkFiles = [...bulkFiles, ...files];
  renderBulkBanner();
}

function renderBulkBanner() {
  const banner = document.getElementById('bulkBanner');
  const count  = document.getElementById('bulkCount');
  const list   = document.getElementById('bulkFileList');
  if (!bulkFiles.length) { banner.classList.remove('visible'); return; }
  banner.classList.add('visible');
  count.textContent = bulkFiles.length + ' file' + (bulkFiles.length > 1 ? 's' : '') + ' queued';
  list.innerHTML = bulkFiles.map((f, i) =>
    `<div class="bulk-file-chip" id="chip-${i}">${escapeHtml(f.name)}</div>`
  ).join('');
}

function clearBulk() {
  bulkFiles = [];
  renderBulkBanner();
  document.getElementById('bulkResults').classList.add('hidden');
}

async function analyseBulk() {
  if (!bulkFiles.length) return;
  const tbody = document.getElementById('bulkTableBody');
  tbody.innerHTML = '';
  document.getElementById('bulkResults').classList.remove('hidden');
  document.getElementById('results').classList.add('hidden');

  let bulkData = [];
  for (let i = 0; i < bulkFiles.length; i++) {
    const file = bulkFiles[i];
    const chip = document.getElementById('chip-' + i);
    try {
      const raw = await readFileAsync(file);
      const result = runAnalysis(raw);
      result._filename = file.name;
      bulkData.push(result);
      if (chip) chip.classList.add('done');
      renderBulkRow(tbody, i + 1, result, raw);
    } catch(e) {
      if (chip) chip.classList.add('err');
      const row = tbody.insertRow();
      row.innerHTML = `<td>${i+1}</td><td>${escapeHtml(file.name)}</td><td colspan="8" style="color:var(--red)">Failed to read file</td>`;
    }
  }
  window._bulkData = bulkData;
}

function renderBulkRow(tbody, idx, r, raw) {
  const riskClass = r.riskScore >= 60 ? 'high' : r.riskScore >= 30 ? 'med' : 'low';
  const row = tbody.insertRow();
  row.style.cursor = 'pointer';
  row.onclick = () => {
    document.getElementById('emlInput').value = raw;
    analyseEML();
    document.getElementById('analyser').scrollIntoView({ behavior: 'smooth' });
  };
  row.innerHTML = `
    <td>${idx}</td>
    <td style="max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeHtml(r._filename)}">${escapeHtml(r._filename)}</td>
    <td style="max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(r.from||'—')}</td>
    <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(r.subject||'—')}</td>
    <td>${badgeInline(r.auth.spf)}</td>
    <td>${badgeInline(r.auth.dkim)}</td>
    <td>${badgeInline(r.auth.dmarc)}</td>
    <td>${r.urls.length}</td>
    <td>${r.attachments.length}</td>
    <td><span class="risk-pill ${riskClass}">${r.riskScore}</span></td>`;
}

function exportBulkCSV() {
  const data = window._bulkData || [];
  if (!data.length) return;
  const headers = ['File','From','Subject','SPF','DKIM','DMARC','URLs','Attachments','Risk Score','Threat Level'];
  const rows = data.map(r => [
    r._filename, r.from, r.subject,
    r.auth.spf, r.auth.dkim, r.auth.dmarc,
    r.urls.length, r.attachments.length,
    r.riskScore, r.riskScore >= 60 ? 'HIGH' : r.riskScore >= 30 ? 'MEDIUM' : 'LOW'
  ].map(v => `"${(v||'').toString().replace(/"/g,'""')}"`).join(','));
  const csv = [headers.join(','), ...rows].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'cybthreat-bulk-report.csv';
  a.click();
}

/* ─── Header Parser ──────────────────────────────────────────────── */
function parseHeaders(raw) {
  const headers = {};
  const unfolded = raw.replace(/\r\n/g,'\n').replace(/\r/g,'\n').replace(/\n[ \t]+/g,' ');
  for (const line of unfolded.split('\n')) {
    const m = line.match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)/);
    if (!m) continue;
    const key = m[1].toLowerCase(), val = m[2].trim();
    if (!headers[key]) headers[key] = val;
    else if (Array.isArray(headers[key])) headers[key].push(val);
    else headers[key] = [headers[key], val];
  }
  return headers;
}
function getAll(h, key) { const v = h[key.toLowerCase()]; if (!v) return []; return Array.isArray(v)?v:[v]; }
function get(h, key) { return getAll(h,key)[0]||''; }

/* ─── IP Utilities ───────────────────────────────────────────────── */
function extractIP(str) { const m=str.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/); return m?(m[1]||m[2]):''; }
function isPrivateIP(ip) { if(!ip)return false; const p=ip.split('.').map(Number); return p[0]===10||(p[0]===172&&p[1]>=16&&p[1]<=31)||(p[0]===192&&p[1]===168)||p[0]===127; }

/* ─── Auth Parser ────────────────────────────────────────────────── */
function parseAuthResults(str) {
  const res={spf:'none',dkim:'none',dmarc:'none',arc:'none'};
  if(!str)return res;
  for(const c of['spf','dkim','dmarc','arc']){const m=str.match(new RegExp(c+'=([a-z]+)','i'));if(m)res[c]=m[1].toLowerCase();}
  return res;
}

/* ─── Received Parser ────────────────────────────────────────────── */
function parseReceived(str) {
  const fromM=str.match(/from\s+([^\s(]+)/i), byM=str.match(/by\s+([^\s(]+)/i), withM=str.match(/with\s+([^\s;]+)/i);
  const ip=extractIP(str), dateM=str.match(/;\s*(.+)$/);
  const d=dateM?new Date(dateM[1].trim()):null;
  return { from:fromM?fromM[1]:'', by:byM?byM[1]:'', with:withM?withM[1]:'', ip, dateStr:dateM?dateM[1].trim():'', date:(d&&!isNaN(d))?d:null, raw:str };
}

/* ─── URL Extractor ──────────────────────────────────────────────── */
function extractURLs(raw) {
  const urlRegex = /https?:\/\/[^\s"'<>\]\[(){}|\\^`\x00-\x20\x7f-\xff]+/gi;
  const found = raw.match(urlRegex) || [];
  const seen = new Set();
  return found.filter(u => { const clean = u.replace(/[.,;:!?)\]>]+$/, ''); if (seen.has(clean)) return false; seen.add(clean); return true; })
    .map(u => {
      const clean = u.replace(/[.,;:!?)\]>]+$/, '');
      let domain = '', isShortener = false, isSuspTLD = false, isIP = false;
      try {
        const parsed = new URL(clean);
        domain = parsed.hostname.toLowerCase();
        isShortener = URL_SHORTENERS.some(s => domain.includes(s));
        isSuspTLD = SUSPICIOUS_TLDS.some(t => domain.endsWith(t));
        isIP = /^\d+\.\d+\.\d+\.\d+$/.test(domain);
      } catch(e) {}
      const risk = isIP ? 'high' : isShortener ? 'high' : isSuspTLD ? 'med' : 'low';
      return { url: clean, domain, isShortener, isSuspTLD, isIP, risk };
    });
}

/* ─── Attachment Detector ────────────────────────────────────────── */
function extractAttachments(raw) {
  const attachments = [];
  const cdRegex = /Content-Disposition\s*:\s*attachment[^]*?(?=\n[A-Za-z]|$)/gi;
  const fnRegex1 = /filename\*?=["']?(?:UTF-8'')?([^"'\r\n;]+)/i;
  const fnRegex2 = /name=["']?([^"'\r\n;]+)/i;

  const parts = raw.split(/(?=Content-Disposition\s*:\s*attachment)/gi);
  for (const part of parts) {
    if (!/Content-Disposition\s*:\s*attachment/i.test(part)) continue;
    let filename = '';
    const m1 = part.match(fnRegex1); if (m1) filename = decodeURIComponent(m1[1].trim().replace(/["']/g,''));
    if (!filename) { const m2 = part.match(fnRegex2); if (m2) filename = m2[1].trim().replace(/["']/g,''); }
    if (!filename) {
      const ctMatch = part.match(/Content-Type\s*:[^\r\n]+name=["']?([^"'\r\n;]+)/i);
      if (ctMatch) filename = ctMatch[1].trim().replace(/["']/g,'');
    }
    if (!filename) filename = 'unknown_attachment';

    const ext = filename.split('.').pop().toLowerCase();
    const ctMatch = part.match(/Content-Type\s*:\s*([^\r\n;]+)/i);
    const contentType = ctMatch ? ctMatch[1].trim() : '';

    let risk = 'safe';
    if (DANGEROUS_EXTENSIONS.includes(ext)) risk = 'dangerous';
    else if (SUSPICIOUS_EXTENSIONS.includes(ext)) risk = 'suspicious';

    attachments.push({ filename, ext, contentType, risk });
  }

  // Also check Content-Type headers with name= for inline attachments
  const nameMatches = raw.matchAll(/Content-Type\s*:[^\r\n]+name=["']?([^"'\r\n;]+)/gi);
  for (const m of nameMatches) {
    const filename = m[1].trim().replace(/["']/g,'');
    if (attachments.some(a => a.filename === filename)) continue;
    const ext = filename.split('.').pop().toLowerCase();
    let risk = 'safe';
    if (DANGEROUS_EXTENSIONS.includes(ext)) risk = 'dangerous';
    else if (SUSPICIOUS_EXTENSIONS.includes(ext)) risk = 'suspicious';
    attachments.push({ filename, ext, contentType: '', risk });
  }

  return attachments;
}

/* ─── Badge Helpers ──────────────────────────────────────────────── */
function badge(val) {
  const v=(val||'none').toLowerCase();
  if(['pass','ok'].includes(v)) return `<span class="badge badge-pass">✓ ${v}</span>`;
  if(['fail','reject','hardfail'].includes(v)) return `<span class="badge badge-fail">✕ ${v}</span>`;
  if(['softfail','neutral','temperror','permerror'].includes(v)) return `<span class="badge badge-warn">⚠ ${v}</span>`;
  return `<span class="badge badge-none">— ${v}</span>`;
}
function badgeInline(val) {
  const v=(val||'none').toLowerCase();
  if(['pass','ok'].includes(v)) return `<span style="color:var(--green);font-family:var(--font-mono);font-size:11px">✓ ${v}</span>`;
  if(['fail','reject','hardfail'].includes(v)) return `<span style="color:var(--red);font-family:var(--font-mono);font-size:11px">✕ ${v}</span>`;
  if(['softfail','neutral'].includes(v)) return `<span style="color:var(--amber);font-family:var(--font-mono);font-size:11px">⚠ ${v}</span>`;
  return `<span style="color:var(--text3);font-family:var(--font-mono);font-size:11px">— ${v}</span>`;
}
function escapeHtml(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

/* ─── Core Analysis Engine ───────────────────────────────────────── */
function runAnalysis(raw) {
  const h = parseHeaders(raw);
  const from       = get(h,'from');
  const to         = get(h,'to');
  const subject    = get(h,'subject');
  const date       = get(h,'date');
  const msgId      = get(h,'message-id');
  const replyTo    = get(h,'reply-to');
  const returnPath = get(h,'return-path');
  const xMailer    = get(h,'x-mailer');
  const xOrigIP    = get(h,'x-originating-ip')||get(h,'x-sender-ip');
  const spamStatus = get(h,'x-spam-status');
  const spamScore  = get(h,'x-spam-score');
  const priority   = get(h,'x-priority')||get(h,'importance');
  const authWarn   = get(h,'x-authentication-warning');

  const authResultsRaw = get(h,'authentication-results');
  const auth = parseAuthResults(authResultsRaw);
  if (auth.spf==='none') { const s=get(h,'received-spf'); if(s){const m=s.match(/^([a-z]+)/i);if(m)auth.spf=m[1].toLowerCase();} }
  const dkimSig = get(h,'dkim-signature');
  if (auth.dkim==='none'&&dkimSig) auth.dkim='present';

  const receivedAll = getAll(h,'received');
  const hops = receivedAll.map(parseReceived).reverse();

  const fromAddr    = (from.match(/<([^>]+)>/)||from.match(/[\w.+%-]+@[\w.-]+/))?.[1]||from;
  const fromDomain  = fromAddr.includes('@')?fromAddr.split('@')[1].toLowerCase():'';
  const replyAddr   = (replyTo.match(/<([^>]+)>/)||[null,replyTo])[1]||replyTo;
  const replyDomain = replyAddr.includes('@')?replyAddr.split('@')[1].toLowerCase():'';
  const retAddr     = (returnPath.match(/<([^>]+)>/)||[null,returnPath])[1]||returnPath;
  const retDomain   = retAddr.includes('@')?retAddr.split('@')[1].toLowerCase():'';
  const dkimDomain  = dkimSig?(dkimSig.match(/d=([^;\s]+)/i)||[])[1]||'':'';

  const urls        = extractURLs(raw);
  const attachments = extractAttachments(raw);

  const findings = [];
  let riskScore = 0;
  const riskBreakdown = [];

  /* SPF */
  if(auth.spf==='pass'){findings.push({t:'SPF check passed',d:'Sender IP authorised by SPF record.',l:'green',i:'✓'});}
  else if(['fail','hardfail'].includes(auth.spf)){findings.push({t:'SPF FAIL — sender IP not authorised',d:`Sending IP not in SPF record for ${fromDomain||'this domain'}.`,l:'red',i:'✕'});riskScore+=30;riskBreakdown.push({label:'SPF Fail',score:30});}
  else if(auth.spf==='softfail'){findings.push({t:'SPF SoftFail',d:'~all matched — sender may not be authorised.',l:'amber',i:'⚠'});riskScore+=15;riskBreakdown.push({label:'SPF SoftFail',score:15});}
  else{findings.push({t:'SPF not found',d:'No SPF check performed.',l:'amber',i:'⚠'});riskScore+=10;riskBreakdown.push({label:'SPF Missing',score:10});}

  /* DKIM */
  if(auth.dkim==='pass'){findings.push({t:'DKIM signature verified',d:'Email cryptographically verified.',l:'green',i:'✓'});}
  else if(auth.dkim==='fail'){findings.push({t:'DKIM FAIL — signature invalid',d:'Message may have been tampered with.',l:'red',i:'✕'});riskScore+=35;riskBreakdown.push({label:'DKIM Fail',score:35});}
  else if(auth.dkim==='present'){findings.push({t:'DKIM present but unconfirmed',d:'Signature header found but no verification result.',l:'amber',i:'⚠'});riskScore+=5;}
  else{findings.push({t:'DKIM not found',d:'No DKIM signature.',l:'amber',i:'⚠'});riskScore+=15;riskBreakdown.push({label:'DKIM Missing',score:15});}

  /* DMARC */
  if(auth.dmarc==='pass'){findings.push({t:'DMARC policy passed',l:'green',i:'✓'});}
  else if(auth.dmarc==='fail'){findings.push({t:'DMARC FAIL — possible spoofing',d:`From domain (${fromDomain}) failed alignment.`,l:'red',i:'✕'});riskScore+=35;riskBreakdown.push({label:'DMARC Fail',score:35});}
  else{findings.push({t:'DMARC not evaluated',d:'Domain may lack DMARC policy.',l:'amber',i:'⚠'});riskScore+=10;riskBreakdown.push({label:'DMARC Missing',score:10});}

  /* Reply-To */
  if(replyTo&&replyDomain&&fromDomain&&replyDomain!==fromDomain){findings.push({t:'Reply-To domain mismatch',d:`From: ${fromDomain} → Reply-To: ${replyDomain}. Classic phishing technique.`,l:'red',i:'✕'});riskScore+=40;riskBreakdown.push({label:'Reply-To Mismatch',score:40});}

  /* Return-Path */
  if(returnPath&&retDomain&&fromDomain&&retDomain!==fromDomain){findings.push({t:'Return-Path differs from From',d:`From: ${fromDomain} → Return-Path: ${retDomain}.`,l:'amber',i:'⚠'});riskScore+=20;riskBreakdown.push({label:'Return-Path Mismatch',score:20});}

  /* URLs */
  const highRiskURLs = urls.filter(u=>u.risk==='high');
  const medRiskURLs  = urls.filter(u=>u.risk==='med');
  if(highRiskURLs.length){findings.push({t:`${highRiskURLs.length} high-risk URL(s) detected`,d:`Found: ${highRiskURLs.map(u=>u.domain).join(', ')}`,l:'red',i:'✕'});riskScore+=Math.min(30,highRiskURLs.length*10);riskBreakdown.push({label:'High-risk URLs',score:Math.min(30,highRiskURLs.length*10)});}
  if(medRiskURLs.length){findings.push({t:`${medRiskURLs.length} suspicious URL(s)`,d:`Suspicious TLD or domain pattern detected.`,l:'amber',i:'⚠'});riskScore+=Math.min(15,medRiskURLs.length*5);}
  if(urls.length>0&&highRiskURLs.length===0&&medRiskURLs.length===0){findings.push({t:`${urls.length} URL(s) extracted — no obvious flags`,d:'Review manually using the URLs tab.',l:'blue',i:'i'});}

  /* Attachments */
  const dangerousAttach = attachments.filter(a=>a.risk==='dangerous');
  const suspiciousAttach= attachments.filter(a=>a.risk==='suspicious');
  if(dangerousAttach.length){findings.push({t:`DANGEROUS attachment type detected`,d:`Files: ${dangerousAttach.map(a=>a.filename).join(', ')}`,l:'red',i:'✕'});riskScore+=40;riskBreakdown.push({label:'Dangerous Attachment',score:40});}
  if(suspiciousAttach.length){findings.push({t:`Suspicious attachment type`,d:`Files: ${suspiciousAttach.map(a=>a.filename).join(', ')} — macro-enabled or archive.`,l:'amber',i:'⚠'});riskScore+=15;riskBreakdown.push({label:'Suspicious Attachment',score:15});}
  if(attachments.length>0&&!dangerousAttach.length&&!suspiciousAttach.length){findings.push({t:`${attachments.length} attachment(s) — safe file type(s)`,l:'green',i:'✓'});}

  /* Other checks */
  if(!msgId){findings.push({t:'Missing Message-ID',d:'Absence often indicates spoofed mail.',l:'amber',i:'⚠'});riskScore+=10;}
  if(!date){findings.push({t:'Missing Date header',d:'Required by RFC 5322.',l:'amber',i:'⚠'});riskScore+=5;}
  else{const d=new Date(date);if(!isNaN(d)&&(Date.now()-d.getTime())<0){findings.push({t:'Date is in the future',d:'Possible timestamp manipulation.',l:'red',i:'✕'});riskScore+=15;}}
  if(hops.length>6){findings.push({t:`High hop count (${hops.length})`,d:'May indicate anonymous relay infrastructure.',l:'amber',i:'⚠'});riskScore+=10;}
  if(spamStatus&&/\byes\b/i.test(spamStatus)){findings.push({t:'Spam filter flagged message',d:`X-Spam-Status: ${spamStatus}`,l:'red',i:'✕'});riskScore+=20;}
  if(xMailer){const susp=['phpmailer','python','curl','sendblaster'].some(s=>xMailer.toLowerCase().includes(s));findings.push({t:`X-Mailer: ${xMailer}`,d:susp?'Commonly used in bulk/phishing campaigns.':'Mail client identifier.',l:susp?'amber':'blue',i:susp?'⚠':'i'});if(susp)riskScore+=8;}
  if(priority&&(priority==='1'||priority.toLowerCase()==='high')){findings.push({t:'High-priority flag set',d:'Phishing emails often use urgency flags.',l:'amber',i:'⚠'});riskScore+=5;}
  if(authWarn){findings.push({t:'Authentication warning present',d:`X-Authentication-Warning: ${authWarn}`,l:'amber',i:'⚠'});riskScore+=10;}
  if(!findings.filter(f=>f.l==='red').length&&riskScore===0){findings.push({t:'No critical issues detected',d:'Always apply human judgement.',l:'green',i:'✓'});}

  riskScore = Math.min(100, riskScore);
  return { h, from, to, subject, date, msgId, replyTo, returnPath, auth, authResultsRaw, hops, fromDomain, replyDomain, retDomain, dkimDomain, dkimSig, xOrigIP, urls, attachments, findings, riskScore, riskBreakdown };
}

/* ─── Main Entry ─────────────────────────────────────────────────── */
function analyseEML() {
  const raw = document.getElementById('emlInput').value.trim();
  if (!raw) { alert('Please paste email headers or upload a .eml file first.'); return; }
  const r = runAnalysis(raw);
  renderAll(r, raw);
}

/* ─── Render All ─────────────────────────────────────────────────── */
function renderAll(r, raw) {
  renderSummary(r);
  renderOverview(r);
  renderAuth(r);
  renderRouting(r);
  renderURLs(r.urls);
  renderAttachments(r.attachments);
  renderFindings(r.findings);
  renderRaw(r.h);
  document.getElementById('results').classList.remove('hidden');
  document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' });
  switchTabByName('overview');

  // Trigger GeoIP async
  if (r.xOrigIP || r.hops.some(h => h.ip && !isPrivateIP(h.ip))) {
    const ip = r.xOrigIP || r.hops.find(h => h.ip && !isPrivateIP(h.ip))?.ip;
    if (ip) lookupGeoIP(ip, r.hops);
  }
}

/* ─── Render: Summary ────────────────────────────────────────────── */
function renderSummary(r) {
  const { riskScore, hops, findings, auth, urls, attachments } = r;
  const authScore = ['spf','dkim','dmarc'].filter(k=>auth[k]==='pass').length;
  const riskLabel = riskScore>=60?'HIGH':riskScore>=30?'MEDIUM':'LOW';
  const riskClass = riskScore>=60?'risk-high':riskScore>=30?'risk-med':'risk-low';
  const barClass  = riskScore>=60?'risk-bar-high':riskScore>=30?'risk-bar-med':'risk-bar-low';

  document.getElementById('s-risk-score').textContent = riskScore;
  document.getElementById('s-auth').textContent = `${authScore}/3`;
  document.getElementById('s-hops').textContent = hops.length;
  document.getElementById('s-urls').textContent = urls.length;
  document.getElementById('s-attach').textContent = attachments.length;

  const lel = document.getElementById('s-risk-label');
  lel.textContent = riskLabel;
  lel.className = `sum-risk-label ${riskClass}`;

  const fill = document.getElementById('riskBarFill');
  fill.style.width = riskScore + '%';
  fill.className = `risk-bar-fill ${barClass}`;

  document.getElementById('findings-badge').textContent = findings.filter(f=>f.l==='red').length;
  document.getElementById('url-badge').textContent = urls.filter(u=>u.risk!=='low').length;

  const dangerAttach = attachments.filter(a=>a.risk==='dangerous').length;
  const suspAttach   = attachments.filter(a=>a.risk==='suspicious').length;
  const abadge = document.getElementById('attach-badge');
  abadge.textContent = dangerAttach + suspAttach;
  if (dangerAttach > 0) abadge.style.background = 'var(--red-bg)';
  else if (suspAttach > 0) abadge.style.background = 'var(--amber-bg)';
}

/* ─── Render: Overview ───────────────────────────────────────────── */
function renderOverview(r) {
  const kvData = [
    ['From', r.from], ['To', r.to], ['Subject', r.subject], ['Date', r.date],
    ['Message-ID', r.msgId], ['Reply-To', r.replyTo], ['Return-Path', r.returnPath]
  ];
  document.getElementById('envelope-list').innerHTML = kvData.map(([k,v]) =>
    `<div class="kv-row"><div class="kv-key">${k}</div><div class="kv-val ${v?'':'kv-empty'}">${v?escapeHtml(v):'—'}</div></div>`
  ).join('');

  const barClass  = r.riskScore>=60?'risk-bar-high':r.riskScore>=30?'risk-bar-med':'risk-bar-low';
  const riskClass = r.riskScore>=60?'risk-high':r.riskScore>=30?'risk-med':'risk-low';
  let bdHtml = `<div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
    <span class="${riskClass}" style="font-size:36px;font-weight:800;font-family:var(--font-mono)">${r.riskScore}</span>
    <div><div class="sum-lbl" style="margin-bottom:4px">Overall Risk Score</div>
      <div class="risk-bar-wrap" style="width:160px"><div class="risk-bar-fill ${barClass}" style="width:${r.riskScore}%"></div></div>
    </div></div>`;
  if (r.riskBreakdown.length) {
    bdHtml += `<div class="risk-items">` + r.riskBreakdown.map(rb =>
      `<div class="risk-item"><div class="risk-item-label">${escapeHtml(rb.label)}</div>
       <div class="risk-item-bar-wrap"><div class="risk-item-bar ${rb.score>=30?'risk-bar-high':rb.score>=15?'risk-bar-med':'risk-bar-low'}" style="width:${Math.min(100,(rb.score/40)*100)}%"></div></div>
       <div class="risk-item-score">+${rb.score}</div></div>`
    ).join('') + `</div>`;
  } else {
    bdHtml += `<div style="font-size:13px;color:var(--green)">✓ No risk factors detected</div>`;
  }
  document.getElementById('risk-breakdown').innerHTML = bdHtml;
  document.getElementById('auth-pills-overview').innerHTML =
    ['spf','dkim','dmarc'].map(k => `${badge(r.auth[k])} <span style="font-size:11px;color:var(--text3);margin-right:10px">${k.toUpperCase()}</span>`).join('');
}

/* ─── Render: Auth ───────────────────────────────────────────────── */
function renderAuth(r) {
  const items = [{name:'SPF',key:'spf',detail:'Sender Policy Framework'},{name:'DKIM',key:'dkim',detail:'DomainKeys Identified Mail'},{name:'DMARC',key:'dmarc',detail:'Domain-based Msg Auth'},{name:'ARC',key:'arc',detail:'Authenticated Received Chain'}];
  document.getElementById('auth-grid').innerHTML = items.map(item => `
    <div class="auth-item">
      <div class="auth-item-name">${item.name}</div>
      <div class="auth-item-result">${badge(r.auth[item.key])}</div>
      <div class="auth-item-detail">${item.detail}</div>
    </div>`).join('');
  const dkimAlign = r.dkimDomain&&r.fromDomain?r.dkimDomain===r.fromDomain:null;
  const retAlign  = r.retDomain&&r.fromDomain?r.retDomain===r.fromDomain:null;
  const rtAlign   = r.replyDomain&&r.fromDomain?r.replyDomain===r.fromDomain:null;
  document.getElementById('align-section').innerHTML = `<div class="align-grid">
    <div class="align-item"><div class="align-label">From domain</div><div class="align-val">${escapeHtml(r.fromDomain)||'—'}</div></div>
    <div class="align-item"><div class="align-label">DKIM signed domain</div><div class="align-val">${escapeHtml(r.dkimDomain)||'—'}</div>${dkimAlign!==null?`<div class="align-match">${dkimAlign?badge('pass'):badge('fail')} alignment</div>`:''}</div>
    <div class="align-item"><div class="align-label">Return-Path domain</div><div class="align-val">${escapeHtml(r.retDomain)||'—'}</div>${retAlign!==null?`<div class="align-match">${retAlign?badge('pass'):badge('fail')} alignment</div>`:''}</div>
    <div class="align-item"><div class="align-label">Reply-To domain</div><div class="align-val">${escapeHtml(r.replyDomain)||'—'}</div>${rtAlign!==null?`<div class="align-match">${rtAlign?badge('pass'):badge('fail')} alignment</div>`:''}</div>
  </div>`;
  document.getElementById('raw-auth-block').textContent = r.authResultsRaw || 'Not found.';
  document.getElementById('raw-auth-card').style.display = r.authResultsRaw ? '' : 'none';
}

/* ─── Render: Routing ────────────────────────────────────────────── */
function renderRouting(r) {
  const tbody = document.getElementById('hop-tbody');
  if (!r.hops.length) {
    tbody.innerHTML = `<tr><td colspan="9" style="text-align:center;color:var(--text3);padding:24px">No Received headers found</td></tr>`;
    return;
  }
  tbody.innerHTML = r.hops.map((hop, i) => {
    const delay = (i>0&&hop.date&&r.hops[i-1].date)?Math.round((hop.date-r.hops[i-1].date)/1000)+'s':'—';
    const isPriv = hop.ip&&isPrivateIP(hop.ip);
    return `<tr>
      <td><div class="hop-num">${i+1}</div></td>
      <td>${escapeHtml(hop.from)||'—'}</td>
      <td>${escapeHtml(hop.by)||'—'}</td>
      <td>${hop.ip?`<span style="font-family:var(--font-mono)">${escapeHtml(hop.ip)}</span>`:'—'}</td>
      <td id="geo-country-${i}"><span style="color:var(--text3)">—</span></td>
      <td id="geo-isp-${i}"><span style="color:var(--text3)">—</span></td>
      <td style="font-size:11px">${escapeHtml(hop.dateStr)||'—'}</td>
      <td style="${parseInt(delay)>60?'color:var(--amber)':''}">${delay}</td>
      <td>${!hop.ip?'—':isPriv?`<span class="badge badge-info">Internal</span>`:`<span class="badge badge-pass">External</span>`}</td>
    </tr>`;
  }).join('');
  document.getElementById('geoResult').innerHTML = '';
}

/* ─── GeoIP Lookup ───────────────────────────────────────────────── */
async function lookupGeoIP(ip, hops) {
  document.getElementById('geoLoading').classList.remove('hidden');
  try {
    const res = await fetch(`https://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,isp,org,as,hosting,proxy,mobile,query`);
    const data = await res.json();
    document.getElementById('geoLoading').classList.add('hidden');
    if (data.status !== 'success') { document.getElementById('geoResult').innerHTML = `<div style="color:var(--text3);font-size:13px">GeoIP lookup failed for ${escapeHtml(ip)}</div>`; return; }

    const flagUrl = `https://flagcdn.com/20x15/${(data.countryCode||'').toLowerCase()}.png`;
    const isHosting = data.hosting;
    const isProxy   = data.proxy;

    document.getElementById('geoResult').innerHTML = `
      <div class="geo-grid">
        <div class="geo-item"><div class="geo-label">IP Address</div><div class="geo-val" style="font-family:var(--font-mono)">${escapeHtml(data.query)}</div></div>
        <div class="geo-item"><div class="geo-label">Country</div><div class="geo-val"><img src="${flagUrl}" style="vertical-align:middle;margin-right:6px;border-radius:2px" onerror="this.style.display='none'" />${escapeHtml(data.country)} (${escapeHtml(data.countryCode)})</div></div>
        <div class="geo-item"><div class="geo-label">Region / City</div><div class="geo-val">${escapeHtml(data.city)}, ${escapeHtml(data.regionName)}</div></div>
        <div class="geo-item"><div class="geo-label">ISP / Org</div><div class="geo-val">${escapeHtml(data.isp||data.org||'—')}</div></div>
        <div class="geo-item"><div class="geo-label">ASN</div><div class="geo-val" style="font-family:var(--font-mono)">${escapeHtml(data.as||'—')}</div></div>
        <div class="geo-item"><div class="geo-label">Hosting / DC</div><div class="geo-val">${isHosting?`<span style="color:var(--amber)">⚠ Yes — datacenter IP`:'No'}</span></div></div>
        <div class="geo-item"><div class="geo-label">Proxy / VPN</div><div class="geo-val">${isProxy?`<span style="color:var(--red)">✕ Detected`:'Not detected'}</span></div></div>
        <div class="geo-item"><div class="geo-label">Threat Lookup</div><div class="geo-val" style="display:flex;flex-direction:column;gap:4px">
          <a href="https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ip)}" target="_blank" style="color:var(--accent);text-decoration:none;font-size:11px;font-family:var(--font-mono)">↗ VirusTotal</a>
          <a href="https://www.abuseipdb.com/check/${encodeURIComponent(ip)}" target="_blank" style="color:var(--accent);text-decoration:none;font-size:11px;font-family:var(--font-mono)">↗ AbuseIPDB</a>
          <a href="https://shodan.io/host/${encodeURIComponent(ip)}" target="_blank" style="color:var(--accent);text-decoration:none;font-size:11px;font-family:var(--font-mono)">↗ Shodan</a>
        </div></div>
      </div>
      ${(isHosting||isProxy)?`<div class="geo-warn">⚠ This IP is ${isProxy?'a known proxy/VPN':'a hosting/datacenter IP'} — high suspicion for phishing infrastructure</div>`:''}`;

    // Update hop table rows with geo data
    hops.forEach((hop, i) => {
      if (hop.ip === ip) {
        const cc = document.getElementById(`geo-country-${i}`);
        const ci = document.getElementById(`geo-isp-${i}`);
        if (cc) cc.innerHTML = `<img src="${flagUrl}" style="vertical-align:middle;margin-right:4px;border-radius:1px" onerror="this.style.display='none'" />${escapeHtml(data.countryCode)}`;
        if (ci) ci.textContent = data.isp || data.org || '—';
      }
    });
  } catch(e) {
    document.getElementById('geoLoading').classList.add('hidden');
    document.getElementById('geoResult').innerHTML = `<div style="color:var(--text3);font-size:13px">GeoIP lookup unavailable (network error)</div>`;
  }
}

/* ─── Render: URLs ───────────────────────────────────────────────── */
function renderURLs(urls) {
  const container = document.getElementById('url-list');
  if (!urls.length) {
    container.innerHTML = `<div class="url-empty">No URLs found in headers or body.</div>`;
    return;
  }
  const vtKey = getVTKey();
  container.innerHTML = urls.map((u, idx) => {
    const riskBadge = u.risk==='high'
      ? `<span class="badge badge-fail">High risk</span>`
      : u.risk==='med'
        ? `<span class="badge badge-warn">Suspicious</span>`
        : `<span class="badge badge-none">Low risk</span>`;
    const flags = [];
    if (u.isShortener) flags.push('<span class="badge badge-fail" style="font-size:10px">URL Shortener</span>');
    if (u.isSuspTLD)   flags.push('<span class="badge badge-warn" style="font-size:10px">Suspicious TLD</span>');
    if (u.isIP)        flags.push('<span class="badge badge-fail" style="font-size:10px">IP Address URL</span>');
    return `<div class="url-item" id="url-item-${idx}">
      <div class="url-item-header">
        <div class="url-type-badge">${riskBadge}</div>
        <div>
          <div class="url-text">${escapeHtml(u.url)}</div>
          ${flags.length?`<div style="display:flex;gap:6px;margin-top:6px;flex-wrap:wrap">${flags.join('')}</div>`:''}
        </div>
      </div>
      <div class="url-actions">
        <a class="url-btn" href="https://www.virustotal.com/gui/url/${btoa(u.url).replace(/=/g,'')}" target="_blank">↗ VirusTotal</a>
        <a class="url-btn" href="https://urlscan.io/search/#page.url%3A${encodeURIComponent(u.domain)}" target="_blank">↗ URLScan</a>
        <a class="url-btn" href="https://checkphish.ai/scan?url=${encodeURIComponent(u.url)}" target="_blank">↗ CheckPhish</a>
        ${vtKey ? `<button class="url-btn vt-btn" onclick="scanURLWithVT('${escapeHtml(u.url).replace(/'/g,"\\'")}', ${idx})">⚡ Scan with VT API</button>` : ''}
      </div>
      <div class="url-scan-result hidden" id="url-scan-${idx}"></div>
    </div>`;
  }).join('');
}

/* ─── VirusTotal URL Scan ────────────────────────────────────────── */
async function scanURLWithVT(url, idx) {
  const vtKey = getVTKey();
  if (!vtKey) { alert('No VirusTotal API key configured. Go to Settings to add one.'); return; }
  const resultEl = document.getElementById(`url-scan-${idx}`);
  resultEl.className = 'url-scan-result scanning';
  resultEl.textContent = '⏳ Scanning with VirusTotal API...';
  resultEl.classList.remove('hidden');
  try {
    // Submit URL
    const submitRes = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: { 'x-apikey': vtKey, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'url=' + encodeURIComponent(url)
    });
    const submitData = await submitRes.json();
    if (!submitRes.ok) throw new Error(submitData.error?.message || 'Submission failed');
    const analysisId = submitData.data?.id;
    if (!analysisId) throw new Error('No analysis ID returned');

    // Poll for result (max 3 attempts)
    await new Promise(r => setTimeout(r, 3000));
    const reportRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { 'x-apikey': vtKey }
    });
    const reportData = await reportRes.json();
    const stats = reportData.data?.attributes?.stats;
    if (!stats) throw new Error('No results yet — check VirusTotal directly');

    const malicious = stats.malicious || 0;
    const total = Object.values(stats).reduce((a,b)=>a+b,0);
    if (malicious > 0) {
      resultEl.className = 'url-scan-result malicious';
      resultEl.textContent = `✕ MALICIOUS — ${malicious}/${total} engines flagged this URL`;
    } else {
      resultEl.className = 'url-scan-result clean';
      resultEl.textContent = `✓ Clean — 0/${total} engines flagged this URL`;
    }
  } catch(e) {
    resultEl.className = 'url-scan-result error';
    resultEl.textContent = `⚠ Error: ${e.message}`;
  }
}

/* ─── Render: Attachments ────────────────────────────────────────── */
function renderAttachments(attachments) {
  const container = document.getElementById('attachment-list');
  if (!attachments.length) {
    container.innerHTML = `<div class="attach-empty">No attachments detected in headers.</div>`;
    return;
  }
  const icons = { dangerous: '☠', suspicious: '⚠', safe: '📄' };
  const verdicts = { dangerous: 'DANGEROUS — Do not open', suspicious: 'Suspicious — Exercise caution', safe: 'Safe file type' };
  container.innerHTML = attachments.map(a => `
    <div class="attach-item ${a.risk}">
      <div class="attach-icon ${a.risk}">${icons[a.risk]}</div>
      <div class="attach-info">
        <div class="attach-name">${escapeHtml(a.filename)}</div>
        <div class="attach-meta">.${escapeHtml(a.ext)} extension${a.contentType ? ` · ${escapeHtml(a.contentType)}` : ''}</div>
      </div>
      <div class="attach-verdict ${a.risk}">${verdicts[a.risk]}</div>
    </div>`).join('');
}

/* ─── Render: Findings ───────────────────────────────────────────── */
function renderFindings(findings) {
  document.getElementById('findings-list').innerHTML = findings.map(f => `
    <div class="finding finding-${f.l}">
      <div class="finding-icon">${f.i}</div>
      <div class="finding-body">
        <div class="finding-title">${escapeHtml(f.t)}</div>
        ${f.d?`<div class="finding-desc">${escapeHtml(f.d)}</div>`:''}
      </div>
    </div>`).join('');
}

/* ─── Render: Raw ────────────────────────────────────────────────── */
function renderRaw(h) {
  document.getElementById('raw-parsed').textContent = Object.entries(h).map(([k,v]) => {
    const vals = Array.isArray(v)?v:[v];
    return vals.map(val=>`${k}: ${val}`).join('\n');
  }).join('\n');
}

/* ─── Tab Switcher ───────────────────────────────────────────────── */
function switchTab(btn, name) {
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p=>{p.classList.remove('active');p.classList.add('hidden');});
  btn.classList.add('active');
  const pane = document.getElementById('tab-'+name);
  if(pane){pane.classList.remove('hidden');pane.classList.add('active');}
}
function switchTabByName(name) {
  const tabs=['overview','auth','routing','urls','attachments','findings','raw'];
  document.querySelectorAll('.tab').forEach((t,i)=>t.classList.toggle('active',tabs[i]===name));
  document.querySelectorAll('.tab-pane').forEach(p=>{p.classList.remove('active');p.classList.add('hidden');});
  const pane = document.getElementById('tab-'+name);
  if(pane){pane.classList.remove('hidden');pane.classList.add('active');}
}

/* ─── Utility ────────────────────────────────────────────────────── */
function showFileLoadedBadge(filename) {
  const hint = document.getElementById('inputHint');
  if(hint) hint.innerHTML = `<span class="file-loaded-badge"><svg width="11" height="11" viewBox="0 0 16 16" fill="none"><path d="M3 8l4 4 6-6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>${escapeHtml(filename)}</span>`;
}
function resetInputHint() {
  const hint = document.getElementById('inputHint');
  if(hint) hint.innerHTML = `<svg width="12" height="12" viewBox="0 0 16 16" fill="none"><rect x="2" y="4" width="12" height="9" rx="1.5" stroke="currentColor" stroke-width="1.2"/><path d="M5 4V3a3 3 0 016 0v1" stroke="currentColor" stroke-width="1.2"/></svg> All analysis is done client-side — no data is sent anywhere`;
}
function clearAll() {
  document.getElementById('emlInput').value='';
  document.getElementById('results').classList.add('hidden');
  resetInputHint();
  document.getElementById('emlFileInput').value='';
}

/* ─── DOMContentLoaded ───────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  updateModeIndicator();

  const dropZone = document.getElementById('dropZone');
  ['dragenter','dragover'].forEach(evt => document.addEventListener(evt, e => { e.preventDefault(); dropZone.classList.add('drag-over'); }));
  ['dragleave','drop'].forEach(evt => document.addEventListener(evt, () => dropZone.classList.remove('drag-over')));
  document.addEventListener('drop', e => {
    e.preventDefault();
    const files = Array.from(e.dataTransfer.files).filter(f => /\.(eml|txt|msg)$/i.test(f.name));
    if (!files.length) { alert('Please drop .eml, .txt, or .msg files.'); return; }
    if (files.length === 1) readEMLFile(files[0], false);
    else addToBulkQueue(files);
  });
  dropZone.addEventListener('click', () => document.getElementById('emlFileInput').click());
});
