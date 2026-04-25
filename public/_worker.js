// Hielluo Cloudflare Pages Worker

const FIREBASE_PROJECT_ID = 'hielluo';

const COUNTRY_MAP = {
  "afghanistan":"AF","albania":"AL","algeria":"DZ","angola":"AO","argentina":"AR",
  "armenia":"AM","australia":"AU","austria":"AT","azerbaijan":"AZ","bangladesh":"BD",
  "belarus":"BY","belgium":"BE","bolivia":"BO","brazil":"BR","bulgaria":"BG",
  "cambodia":"KH","cameroon":"CM","canada":"CA","chile":"CL","china":"CN",
  "colombia":"CO","costa rica":"CR","croatia":"HR","cuba":"CU","czech republic":"CZ",
  "denmark":"DK","dominican republic":"DO","ecuador":"EC","egypt":"EG","ethiopia":"ET",
  "finland":"FI","france":"FR","ghana":"GH","greece":"GR","guatemala":"GT",
  "haiti":"HT","honduras":"HN","hungary":"HU","india":"IN","indonesia":"ID",
  "iran":"IR","iraq":"IQ","ireland":"IE","israel":"IL","italy":"IT","japan":"JP",
  "jordan":"JO","kazakhstan":"KZ","kenya":"KE","kuwait":"KW","malaysia":"MY",
  "mexico":"MX","morocco":"MA","mozambique":"MZ","myanmar":"MM","nepal":"NP",
  "netherlands":"NL","new zealand":"NZ","nigeria":"NG","norway":"NO","pakistan":"PK",
  "panama":"PA","peru":"PE","philippines":"PH","poland":"PL","portugal":"PT",
  "qatar":"QA","romania":"RO","russia":"RU","saudi arabia":"SA","senegal":"SN",
  "serbia":"RS","singapore":"SG","somalia":"SO","south africa":"ZA","south korea":"KR",
  "south sudan":"SS","spain":"ES","sri lanka":"LK","sudan":"SD","sweden":"SE",
  "switzerland":"CH","syria":"SY","tanzania":"TZ","thailand":"TH","tunisia":"TN",
  "turkey":"TR","uganda":"UG","ukraine":"UA","united arab emirates":"AE",
  "united kingdom":"GB","uk":"GB","united states":"US","usa":"US","us":"US",
  "uruguay":"UY","venezuela":"VE","vietnam":"VN","yemen":"YE","zambia":"ZM","zimbabwe":"ZW",
};

const INDICATORS = {
  "NY.GDP.MKTP.CD": "GDP (current US$)",
  "NY.GDP.PCAP.CD": "GDP per capita (current US$)",
  "SP.POP.TOTL": "Population",
  "FP.CPI.TOTL.ZG": "Inflation rate (%)",
  "SL.UEM.TOTL.ZS": "Unemployment rate (%)",
  "NE.EXP.GNFS.ZS": "Exports (% of GDP)",
  "NE.IMP.GNFS.ZS": "Imports (% of GDP)",
  "GC.DOD.TOTL.GD.ZS": "Central government debt (% of GDP)",
};

const MODEL_MAP = { 'genesis-1.0': 'gemini-2.5-flash' };

// ── Utilities ────────────────────────────────────────────────────────────────

function b64urlDecode(str) {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64.padEnd(base64.length + (4 - base64.length % 4) % 4, '=');
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function b64urlEncode(bytes) {
  let binary = '';
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function b64urlEncodeStr(str) {
  return b64urlEncode(new TextEncoder().encode(str));
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function sseResponse(stream) {
  return new Response(stream, {
    headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', ...corsHeaders() },
  });
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders() },
  });
}

// ── Firebase ─────────────────────────────────────────────────────────────────

async function verifyIdToken(idToken) {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('Invalid token format');
  const [headerB64, payloadB64, sigB64] = parts;
  const header = JSON.parse(new TextDecoder().decode(b64urlDecode(headerB64)));
  const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(payloadB64)));
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) throw new Error('Token expired');
  if (payload.aud !== FIREBASE_PROJECT_ID) throw new Error('Invalid audience');
  if (!payload.sub) throw new Error('No subject');
  const jwkRes = await fetch('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com');
  const { keys } = await jwkRes.json();
  const jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error('Public key not found');
  const publicKey = await crypto.subtle.importKey(
    'jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']
  );
  const valid = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5', publicKey,
    b64urlDecode(sigB64),
    new TextEncoder().encode(`${headerB64}.${payloadB64}`)
  );
  if (!valid) throw new Error('Invalid signature');
  return payload.sub;
}

async function createCustomToken(uid, serviceAccount) {
  const now = Math.floor(Date.now() / 1000);
  const headerStr = b64urlEncodeStr(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payloadStr = b64urlEncodeStr(JSON.stringify({
    iss: serviceAccount.client_email,
    sub: serviceAccount.client_email,
    aud: 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
    iat: now, exp: now + 3600, uid,
  }));
  const signingInput = `${headerStr}.${payloadStr}`;
  const pemBody = serviceAccount.private_key
    .replace(/\\n/g, '\n')
    .replace(/-----BEGIN PRIVATE KEY-----\n?/, '')
    .replace(/\n?-----END PRIVATE KEY-----/, '')
    .replace(/\n/g, '');
  const keyData = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));
  const privateKey = await crypto.subtle.importKey(
    'pkcs8', keyData, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5', privateKey, new TextEncoder().encode(signingInput)
  );
  return `${signingInput}.${b64urlEncode(new Uint8Array(sig))}`;
}

// ── World Bank ────────────────────────────────────────────────────────────────

function extractCountries(text) {
  const lower = text.toLowerCase();
  const found = [];
  const names = Object.keys(COUNTRY_MAP).sort((a, b) => b.length - a.length);
  for (const name of names) {
    if (found.length >= 3) break;
    const re = new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`);
    if (re.test(lower)) {
      const code = COUNTRY_MAP[name];
      if (!found.some(([, c]) => c === code)) found.push([name, code]);
    }
  }
  return found;
}

async function fetchWorldBankData(countryCode) {
  const results = {};
  await Promise.all(Object.entries(INDICATORS).map(async ([indicator, label]) => {
    try {
      const r = await fetch(`https://api.worldbank.org/v2/country/${countryCode}/indicator/${indicator}?format=json&mrv=1&per_page=1`);
      const data = await r.json();
      if (Array.isArray(data) && data[1]?.[0]?.value != null) {
        const { value, date } = data[1][0];
        results[label] = `${typeof value === 'number' ? value.toLocaleString() : value} (${date})`;
      }
    } catch {}
  }));
  return results;
}

async function buildWorldBankContext(message) {
  const countries = extractCountries(message);
  if (!countries.length) return '';
  const sections = await Promise.all(countries.map(async ([name, code]) => {
    const data = await fetchWorldBankData(code);
    if (!Object.keys(data).length) return null;
    const lines = [`**${name[0].toUpperCase() + name.slice(1)} (World Bank data)**`];
    for (const [label, val] of Object.entries(data)) lines.push(`- ${label}: ${val}`);
    return lines.join('\n');
  }));
  const valid = sections.filter(Boolean);
  return valid.length ? 'Latest World Bank data:\n\n' + valid.join('\n\n') : '';
}

// ── Streaming helpers ─────────────────────────────────────────────────────────

function makeSSEStream(handler) {
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const enc = new TextEncoder();
  const send = (obj) => writer.write(enc.encode(`data: ${JSON.stringify(obj)}\n\n`));
  handler(send).catch(e => send({ error: e.message })).finally(() => writer.close());
  return readable;
}

async function streamFromSSE(response, onChunk) {
  const reader = response.body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    const lines = buf.split('\n');
    buf = lines.pop() || '';
    for (const line of lines) {
      if (!line.startsWith('data:')) continue;
      try { await onChunk(JSON.parse(line.slice(5).trim())); } catch {}
    }
  }
}

// ── Route handlers ────────────────────────────────────────────────────────────

async function handleArgentauriusChat(request, env) {
  const data = await request.json().catch(() => null);
  if (!data?.message?.trim()) return jsonResponse({ error: 'Message required' }, 400);
  const userMessage = data.message.trim();
  const history = data.history || [];
  const wbContext = await buildWorldBankContext(userMessage);
  const messages = [{
    role: 'system',
    content: 'You are Argentaurius, an expert AI banker and financial analyst. You have deep knowledge of global economics, banking, finance, investment, monetary policy, and international development. Use World Bank data and authoritative sources to give precise, data-driven answers. Be professional, insightful, and thorough.',
  }];
  for (const msg of history) messages.push({ role: msg.role === 'user' ? 'user' : 'assistant', content: msg.content });
  if (wbContext) {
    messages.push({ role: 'user', content: wbContext });
    messages.push({ role: 'assistant', content: 'I have the latest World Bank data available. I\'ll incorporate it into my response.' });
  }
  messages.push({ role: 'user', content: userMessage });
  const stream = makeSSEStream(async (send) => {
    const res = await fetch('https://api.cohere.com/v2/chat', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${env.COHERE_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: 'command-r-08-2024', messages, stream: true }),
    });
    if (!res.ok) { await send({ error: await res.text() }); return; }
    await streamFromSSE(res, async (event) => {
      if (event.type === 'content-delta' && event.delta?.text) await send({ chunk: event.delta.text });
    });
    await send({ done: true });
  });
  return sseResponse(stream);
}

async function handleGenesisChat(request, env) {
  const data = await request.json().catch(() => null);
  if (!data?.message?.trim()) return jsonResponse({ error: 'Message required' }, 400);
  const userMessage = data.message.trim();
  const history = data.history || [];
  const modelAlias = data.model || 'genesis-1.0';
  const model = MODEL_MAP[modelAlias] || 'gemini-2.5-flash';
  const contents = [
    ...history.map(m => ({ role: m.role === 'user' ? 'user' : 'model', parts: [{ text: m.content }] })),
    { role: 'user', parts: [{ text: userMessage }] },
  ];
  const stream = makeSSEStream(async (send) => {
    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:streamGenerateContent?key=${env.GEMINI_API_KEY}&alt=sse`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents,
          systemInstruction: { parts: [{ text: 'You are Genesis, a helpful, thoughtful, and capable AI assistant. Give clear, accurate, and well-structured responses. Use markdown formatting where it helps clarity.' }] },
        }),
      }
    );
    if (!res.ok) { await send({ error: await res.text() }); return; }
    await streamFromSSE(res, async (event) => {
      const text = event.candidates?.[0]?.content?.parts?.[0]?.text;
      if (text) await send({ chunk: text });
    });
    await send({ done: true });
  });
  return sseResponse(stream);
}

function handleGenesisModels() {
  return jsonResponse({ models: Object.keys(MODEL_MAP) });
}

async function handleCustomToken(request, env) {
  const body = await request.json().catch(() => null);
  const idToken = body?.idToken;
  if (!idToken) return jsonResponse({ error: 'Missing idToken' }, 400);
  try {
    const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
    const uid = await verifyIdToken(idToken);
    const customToken = await createCustomToken(uid, sa);
    return jsonResponse({ customToken });
  } catch (e) {
    return jsonResponse({ error: e.message }, 401);
  }
}

// ── Main router ───────────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname, origin } = url;
    const method = request.method;

    if (method === 'OPTIONS') return new Response(null, { headers: corsHeaders() });

    if (method === 'POST' && pathname === '/argentaurius/chat') return handleArgentauriusChat(request, env);
    if (method === 'POST' && pathname === '/genesis/chat') return handleGenesisChat(request, env);
    if (pathname === '/genesis/models') return handleGenesisModels();
    if (method === 'POST' && pathname === '/auth/custom-token') return handleCustomToken(request, env);

    // Clean URL → index.html routing
    if (pathname === '/argentaurius' || pathname === '/argentaurius/') {
      return env.ASSETS.fetch(new Request(`${origin}/argentaurius/index.html`));
    }
    if (pathname === '/genesis' || pathname === '/genesis/') {
      return env.ASSETS.fetch(new Request(`${origin}/genesis/index.html`));
    }

    return env.ASSETS.fetch(request);
  },
};
