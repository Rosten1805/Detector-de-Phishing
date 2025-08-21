// ================= Utilidades =================
const $ = (sel)=>document.querySelector(sel);
const statusEl = $('#status');
const findingsEl = $('#findings');
const detailsEl = $('#details');
const scoreEl = $('#score');
const barEl = $('#bar');
const chipsEl = $('#summaryChips');

const MAX_BYTES = 25 * 1024 * 1024; // 25MB por archivo

const URGENCY_WORDS_ES = [
  'urgente','inmediato','último aviso','suspender','bloqueado','verifique','confirmar','restablecer','contraseña',
  'token','código','premio','ganador','factura pendiente','pago rechazado','impuesto','hacienda','aeat','correos',
  'paquete','aduana','seguro','transferencia','banco','santander','bbva','caixa','iban','otp','sms','confirmación',
  'actualice sus datos','evitar sanción'
];
const URGENCY_WORDS_EN = [
  'urgent','immediately','last notice','suspend','blocked','verify','confirm','reset','password','token','code',
  'prize','winner','pending invoice','payment failed','tax','customs','delivery','bank','transfer','otp','account',
  'update your details'
];

const SUSP_TLDS = ['.xyz','.top','.gq','.tk','.cf','.ru','.work','.zip','.mov','.rest','.country','.mom','.fit','.cam','.buzz','.click','.loan','.men','.live','.shop','.info'];
const SHORTENERS = ['bit.ly','tinyurl.com','t.co','goo.gl','is.gd','ow.ly','buff.ly','rebrand.ly','cutt.ly','tiny.one'];
const KNOWN_BRANDS = ['amazon','apple','microsoft','google','facebook','instagram','paypal','santander','bbva','caixabank','correos','aeat','dgt','endesa','iberdrola','movistar','orange','vodafone'];

const textFromFile = async (file) => {
  if (file.size > MAX_BYTES) throw new Error(`El archivo ${file.name} supera 25MB`);
  const ext = (file.name.split('.').pop() || '').toLowerCase();
  if (file.type === 'application/pdf' || ext === 'pdf') {
    return await readPdfText(file);
  }
  if (file.type.startsWith('image/') || ['jpg','jpeg','png','webp'].includes(ext)){
    return await ocrImage(file);
  }
  if (file.type.startsWith('text/') || ['txt','eml'].includes(ext)){
    return await file.text();
  }
  throw new Error(`Formato no soportado: ${file.type || ext}`);
};

// ---- PDF -> texto usando pdf.js
async function readPdfText(file){
  const buf = await file.arrayBuffer();
  const loadingTask = pdfjsLib.getDocument({data: buf});
  const pdf = await loadingTask.promise;
  let out = '';
  for (let p=1; p<=pdf.numPages; p++){
    const page = await pdf.getPage(p);
    const content = await page.getTextContent();
    out += content.items.map(i=>i.str).join(' ') + "\n";
  }
  return out;
}

// ---- Imagen -> texto usando Tesseract.js (OCR)
async function ocrImage(file){
  status(`OCR en progreso: ${file.name}`);
  const { createWorker } = Tesseract;
  const worker = await createWorker('spa+eng', 1);
  const imgUrl = URL.createObjectURL(file);
  try{
    const { data:{ text } } = await worker.recognize(imgUrl);
    await worker.terminate();
    URL.revokeObjectURL(imgUrl);
    return text;
  }catch(e){
    console.warn('Fallo OCR con spa+eng, se intenta eng', e);
    try{
      const worker2 = await createWorker('eng', 1);
      const { data:{ text } } = await worker2.recognize(imgUrl);
      await worker2.terminate();
      URL.revokeObjectURL(imgUrl);
      return text;
    }catch(err){
      URL.revokeObjectURL(imgUrl);
      throw err;
    }
  }
}

// ---- Extracción de entidades
function extractEntities(text){
  const urls = Array.from(new Set((text.match(/https?:\/\/[^\s)]+/gi)||[])))
    .map(u=>u.replace(/[\)\]\.,]+$/,''));
  const emails = Array.from(new Set((text.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi)||[])));
  const domains = new Set();
  for(const u of urls){
    try{ domains.add(new URL(u).hostname.toLowerCase()); }catch{}
  }
  for(const e of emails){
    const d = e.split('@')[1]?.toLowerCase(); if(d) domains.add(d);
  }
  // Punycode/IDN
  const idn = Array.from(domains).map(d=>({
    domain:d,
    isIDN:/[^\x00-\x7F]/.test(d) || d.includes('xn--'),
    unicode: (d.includes('xn--')? punycode.toUnicode(d): d)
  }));
  return { urls, emails, domains:[...domains], idn };
}

// ---- Heurísticas de riesgo
function analyze(text){
  const lower = text.toLowerCase();
  const { urls, emails, domains, idn } = extractEntities(lower);
  const findings = [];
  let risk = 0;

  // 1 Palabras de urgencia
  const urgHits = [...URGENCY_WORDS_ES, ...URGENCY_WORDS_EN].filter(w=>lower.includes(w));
  if (urgHits.length){
    risk += Math.min(urgHits.length * 2, 10);
    findings.push({lvl:'warn', msg:`Lenguaje de urgencia/manipulación detectado: ${uniq(urgHits).slice(0,10).join(', ')}${urgHits.length>10?'…':''}`});
  }

  // 2 URLs y acortadores
  if (urls.length===0){
    findings.push({lvl:'warn', msg:'No se detectaron URLs explícitas. Los phish a veces ocultan enlaces en imágenes.'});
  }
  const shortHits = urls.filter(u=> SHORTENERS.some(s=> u.includes(s)));
  if (shortHits.length){ risk += 8; findings.push({lvl:'bad', msg:`Uso de acortadores: ${shortHits.join(' , ')}`}); }

  // 3 TLDs sospechosos y guiones
  for(const d of domains){
    const tld = (d.match(/(\.[a-z0-9-]+)$/) || ['',''])[1];
    if (SUSP_TLDS.includes(tld)){ risk += 8; findings.push({lvl:'bad', msg:`TLD poco confiable: ${d}`}); }
    if ((d.match(/-/g)||[]).length>=2){ risk += 4; findings.push({lvl:'warn', msg:`Dominio con múltiples guiones: ${d}`}); }
    if (d.split('.').length>=4){ risk += 3; findings.push({lvl:'warn', msg:`Subdominio profundo que puede intentar suplantar: ${d}`}); }
  }

  // 4 IDN / Punycode
  const idnHits = idn.filter(x=>x.isIDN);
  if (idnHits.length){
    risk += 8; findings.push({lvl:'bad', msg:`Dominios IDN/punycode (posible homógrafo): ${idnHits.map(x=>x.domain+ (x.unicode && x.unicode!==x.domain?` → ${x.unicode}`:'')).join(' , ')}`});
  }

  // 5 Marca vs dominio
  for(const d of domains){
    for(const brand of KNOWN_BRANDS){
      if (similar(d, brand) && !d.includes(brand+'.com') && !d.endsWith(`.${brand}`)){
        risk += 6; findings.push({lvl:'bad', msg:`Dominio parecido a marca conocida: ${d} ≈ ${brand}`});
      }
    }
  }

  // 6 Solicitudes sensibles
  const sensitive = /(dni|nif|tarjeta|cvv|iban|clave|contraseña|token|otp|verifica|confirm(a|e)|transferencia|pago)/i;
  if (sensitive.test(text)){ risk += 6; findings.push({lvl:'bad', msg:'Solicitud de datos sensibles (p. ej., tarjeta/contraseña/OTP).'}); }

  // 7 Remitente y Reply-To
  const fromMatch = text.match(/from:\s*(.*?)(?:\n|\r|$)/i);
  const replyTo = text.match(/reply-to:\s*(.*?)(?:\n|\r|$)/i);
  if (fromMatch){
    findings.push({lvl:'ok', msg:`Remitente detectado: ${fromMatch[1].trim()}`});
    const mail = (fromMatch[1].match(/[\w.+-]+@[\w.-]+/g)||[])[0];
    const nameOnly = fromMatch[1].replace(/[\w.+-]+@[\w.-]+/g,'').replace(/[<>\"']/g,'').trim();
    if (mail && nameOnly){
      const host = mail.split('@')[1].toLowerCase();
      if (nameOnly && host && !nameOnly.toLowerCase().includes(host.split('.')[0])){
        risk += 3; findings.push({lvl:'warn', msg:`Nombre mostrado no coincide con el dominio del remitente (${nameOnly} vs ${host})`});
      }
    }
  }
  if (replyTo){
    const a = (replyTo[1].match(/[\w.+-]+@[\w.-]+/g)||[])[0];
    const b = (fromMatch?.[1].match(/[\w.+-]+@[\w.-]+/g)||[])[0];
    if (a && b && a.split('@')[1]!==b.split('@')[1]){
      risk += 5; findings.push({lvl:'bad', msg:`Reply-To distinto del From: ${a} ≠ ${b}`});
    }
  }

  // 8 Texto con ruido
  const letters = (text.match(/[a-záéíóúñ]/gi)||[]).length;
  const nonLetters = (text.match(/[^\sa-záéíóúñ]/gi)||[]).length;
  if (letters && nonLetters/letters > 0.6){
    risk += 2; findings.push({lvl:'warn', msg:'Texto desordenado con exceso de símbolos/ruido (posible imagen con enlaces).'});
  }

  // Normalizar riesgo
  const bounded = Math.max(0, Math.min(100, Math.round(10 + risk * 4)));
  const verdict = bounded>=70? {label:'⚠️ Alto', cls:'bad'} : bounded>=40? {label:'🟡 Medio', cls:'warn'} : {label:'🟢 Bajo', cls:'ok'};

  return { score: bounded, verdict, urls, emails, domains, idn, findings };
}

function uniq(arr){ return Array.from(new Set(arr)); }

function similar(domain, brand){
  const sld = domain.split('.').slice(-2)[0] || domain;
  if (sld.includes(brand)) return true;
  return levenshtein(sld, brand) <= 2;
}

function levenshtein(a,b){
  const m=[]; for(let i=0;i<=b.length;i++){m[i]=[i];}
  for(let j=0;j<=a.length;j++){m[0][j]=j;}
  for(let i=1;i<=b.length;i++){
    for(let j=1;j<=a.length;j++){
      m[i][j] = Math.min(
        m[i-1][j] + 1,
        m[i][j-1] + 1,
        m[i-1][j-1] + (a[j-1]===b[i-1]?0:1)
      );
    }
  }
  return m[b.length][a.length];
}

function status(msg){ statusEl.textContent = msg; }

function renderResult(r, text){
  scoreEl.textContent = `${r.verdict.label}`;
  scoreEl.className = `score ${r.verdict.cls}`;
  barEl.style.width = `${r.score}%`;

  chipsEl.innerHTML = '';
  const chip = (t)=>{ const s=document.createElement('span'); s.className='chip'; s.textContent=t; chipsEl.appendChild(s); };
  chip(`Puntaje: ${r.score}/100`);
  chip(`${r.urls.length} URL${r.urls.length!==1?'s':''}`);
  chip(`${r.emails.length} correo${r.emails.length!==1?'s':''}`);
  chip(`${r.domains.length} dominio${r.domains.length!==1?'s':''}`);

  findingsEl.innerHTML = '';
  for(const f of r.findings){
    const el = document.createElement('div'); el.className='item';
    el.innerHTML = `<span class="tag ${f.lvl}">${f.lvl.toUpperCase()}</span><div>${escapeHtml(f.msg)}</div>`;
    findingsEl.appendChild(el);
  }

  const det = [];
  det.push('--- TEXTO ANALIZADO (primeros 4000 caracteres) ---');
  det.push(text.slice(0,4000));
  det.push('\n--- ENTIDADES ---');
  det.push(`URLs (hasta 20):\n- ${r.urls.slice(0,20).join('\n- ') || '(ninguna)'}`);
  det.push(`\nCorreos:\n- ${r.emails.join('\n- ') || '(ninguno)'}`);
  det.push(`\nDominios:\n- ${r.domains.join('\n- ') || '(ninguno)'}`);
  det.push('\nIDN/Punycode:');
  for(const x of r.idn){ det.push(`- ${x.domain}${x.unicode && x.unicode!==x.domain?` → ${x.unicode}`:''}`); }
  detailsEl.textContent = det.join('\n');
}

function escapeHtml(s){
  return s.replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

// ================= Eventos UI =================
const fileEl = $('#file');
const drop = $('#drop');
let queue = [];

drop.addEventListener('dragover', e=>{ e.preventDefault(); drop.style.borderColor='var(--accent)'; });
drop.addEventListener('dragleave', e=>{ drop.style.borderColor='rgba(255,255,255,.18)'; });
drop.addEventListener('drop', e=>{
  e.preventDefault(); drop.style.borderColor='rgba(255,255,255,.18)';
  const files = [...e.dataTransfer.files];
  queue.push(...files); status(`${queue.length} archivo(s) listos`);
});
fileEl.addEventListener('change', e=>{ queue.push(...fileEl.files); status(`${queue.length} archivo(s) listos`); });

$('#clearBtn').addEventListener('click', ()=>{
  queue = []; fileEl.value = ''; $('#manualText').value='';
  findingsEl.innerHTML=''; detailsEl.textContent=''; chipsEl.innerHTML='';
  scoreEl.textContent='—'; scoreEl.className='score'; barEl.style.width='0%'; status('Listo');
});

$('#analyzeBtn').addEventListener('click', async ()=>{
  try{
    status('Procesando…');
    let textParts = [];
    for (const f of queue){
      const t = await textFromFile(f);
      textParts.push(`\n\n[Archivo: ${f.name}]\n${t}`);
    }
    const manual = $('#manualText').value?.trim();
    if (manual) textParts.push(`\n\n[Texto pegado]\n${manual}`);
    const allText = textParts.join('\n').trim();
    if (!allText){ alert('Añade al menos un archivo o texto.'); status('Listo'); return; }
    const result = analyze(allText);
    renderResult(result, allText);
    status('Análisis completado');
  }catch(err){
    console.error(err); status('Error'); alert('Se produjo un error: ' + err.message);
  }
});
