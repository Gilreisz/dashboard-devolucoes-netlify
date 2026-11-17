// Netlify Function: lê o Google Sheets do AppSheet e devolve os registros em JSON.
// Variáveis de ambiente (Netlify > Site configuration > Environment variables):
//   GOOGLE_SERVICE_ACCOUNT_JSON  -> conteúdo completo do arquivo .json da conta de serviço
//   SHEET_ID                     -> ID ou link completo da planilha
//   SHEET_TAB                    -> aba das devoluções (padrão: Página1)
//   SHEET_TAB_RECEB              -> aba dos recebimentos (padrão: Recebimento)
//   GOOGLE_CLIENT_ID             -> ID do cliente OAuth (login com Google)
//   ALLOWED_DOMAIN               -> domínio liberado (padrão: zeb.mx; aceita vários separados por vírgula)
import crypto from "node:crypto";

const CACHE_SEGUNDOS = 15 * 60; // os dados da planilha ficam guardados por 15 min
let CACHE = { t: 0, corpo: null };

class ErroHttp extends Error { constructor(status, msg) { super(msg); this.status = status; } }

// ---------- Login: confere o token do Google e o domínio do e-mail ----------
let CERTS = { exp: 0, keys: {} };
async function chavesGoogle(forcar) {
  if (!forcar && Date.now() < CERTS.exp) return CERTS.keys;
  const r = await fetch("https://www.googleapis.com/oauth2/v3/certs");
  if (!r.ok) throw new Error("Não consegui baixar as chaves do Google (" + r.status + ").");
  const j = await r.json();
  const keys = {};
  for (const k of j.keys) keys[k.kid] = crypto.createPublicKey({ key: k, format: "jwk" });
  const m = /max-age=(\d+)/.exec(r.headers.get("cache-control") || "");
  CERTS = { exp: Date.now() + (m ? Number(m[1]) : 3600) * 1000, keys };
  return keys;
}

export function dominiosPermitidos() {
  return (process.env.ALLOWED_DOMAIN || "zeb.mx").split(",").map((d) => d.trim().toLowerCase().replace(/^@/, "")).filter(Boolean);
}

export async function verificarUsuario(req) {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) throw new ErroHttp(500, "Configure GOOGLE_CLIENT_ID no Netlify.");
  const dominios = dominiosPermitidos();
  const tok = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
  if (!tok) throw new ErroHttp(401, "Entre com seu e-mail @" + dominios[0] + ".");
  const [h, p, sig] = tok.split(".");
  if (!h || !p || !sig) throw new ErroHttp(401, "Login inválido. Entre novamente.");
  let head, pay;
  try { head = JSON.parse(Buffer.from(h, "base64url")); pay = JSON.parse(Buffer.from(p, "base64url")); }
  catch { throw new ErroHttp(401, "Login inválido. Entre novamente."); }
  let keys = await chavesGoogle(false);
  if (!keys[head.kid]) keys = await chavesGoogle(true);
  const key = keys[head.kid];
  if (!key || head.alg !== "RS256") throw new ErroHttp(401, "Login inválido. Entre novamente.");
  const ok = crypto.verify("RSA-SHA256", Buffer.from(h + "." + p), key, Buffer.from(sig, "base64url"));
  if (!ok) throw new ErroHttp(401, "Login inválido. Entre novamente.");
  if (pay.aud !== clientId) throw new ErroHttp(401, "Login de outro aplicativo. Entre novamente.");
  if (!["accounts.google.com", "https://accounts.google.com"].includes(pay.iss)) throw new ErroHttp(401, "Login inválido. Entre novamente.");
  if (!pay.exp || pay.exp * 1000 < Date.now()) throw new ErroHttp(401, "Sua sessão expirou. Entre novamente.");
  const email = String(pay.email || "").toLowerCase();
  if (!pay.email_verified || !dominios.some((d) => email.endsWith("@" + d)))
    throw new ErroHttp(403, "Acesso permitido só para e-mails @" + dominios.join(", @") + ". Você entrou como " + (email || "conta sem e-mail") + ".");
  return email;
}

const b64url = (buf) =>
  Buffer.from(buf).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");

async function tokenGoogle(sa) {
  const agora = Math.floor(Date.now() / 1000);
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64url(
    JSON.stringify({
      iss: sa.client_email,
      scope: "https://www.googleapis.com/auth/spreadsheets.readonly",
      aud: "https://oauth2.googleapis.com/token",
      iat: agora,
      exp: agora + 3600,
    })
  );
  const assinatura = crypto.createSign("RSA-SHA256").update(`${header}.${payload}`).sign(sa.private_key);
  const jwt = `${header}.${payload}.${b64url(assinatura)}`;
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion: jwt }),
  });
  if (!r.ok) throw new Error(`Falha no login do Google (${r.status}): ${await r.text()}`);
  return (await r.json()).access_token;
}

// Datas: número serial do Sheets ou texto "dd/mm/aaaa hh:mm(:ss)". Saída sem fuso: "aaaa-mm-ddThh:mm:ss"
function data(v) {
  if (v === undefined || v === null || v === "") return null;
  if (typeof v === "number") {
    const d = new Date(Math.round((v - 25569) * 86400000));
    return isNaN(d) ? null : d.toISOString().slice(0, 19);
  }
  const m = String(v).trim().match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2}))?)?/);
  if (m) {
    const p = (x) => String(x || 0).padStart(2, "0");
    return `${m[3]}-${p(m[2])}-${p(m[1])}T${p(m[4])}:${p(m[5])}:${p(m[6])}`;
  }
  const d = new Date(v);
  return isNaN(d) ? null : d.toISOString().slice(0, 19);
}

function numero(v) {
  if (typeof v === "number") return v;
  if (v === undefined || v === null || v === "") return 0;
  let s = String(v).trim();
  if (s.includes(",")) s = s.replace(/\./g, "").replace(",", ".");
  const n = Number(s);
  return isNaN(n) ? 0 : n;
}

const texto = (v) => (v === undefined || v === null ? "" : String(v).trim().replace(/\s+/g, " "));

export function converter(valores) {
  const cab = (valores[0] || []).map((c) => texto(c));
  const idx = (nome) => cab.indexOf(nome);
  const col = {
    id: idx("ID DE REGISTRO"),
    chegada: idx("DATA DE CHEGADA"),
    nfe: idx("NFe"),
    qtd: idx("QTD"),
    item: idx("ITEM"),
    transp: idx("TRANSPORTADORA"),
    resp: idx("Responsável"),
    estoque: idx("Estoque"),
    retrab: idx("Retrabalho estoque saudável"),
    descarte: idx("Motivo descarte"),
    internal: idx("DATA INTERNALIZADA"),
    xml: idx("ENVIO DO XML") >= 0 ? idx("ENVIO DO XML") : idx("DateXML"),
    motivo: idx("Motivo Devolução"),
    razao: idx("Razão"),
  };
  const faltando = Object.entries(col).filter(([, i]) => i < 0).map(([k]) => k);
  if (faltando.includes("id") || faltando.includes("chegada"))
    throw new Error("Colunas 'ID DE REGISTRO' e 'DATA DE CHEGADA' não encontradas na aba.");
  const g = (lin, k) => (col[k] < 0 ? "" : lin[col[k]]);

  const out = [];
  for (const lin of valores.slice(1)) {
    const id = texto(g(lin, "id"));
    const chegada = data(g(lin, "chegada"));
    if (!id || !chegada) continue;
    const item = texto(g(lin, "item")).toUpperCase();
    out.push({
      id,
      chegada,
      internalizada: data(g(lin, "internal")),
      xml: data(g(lin, "xml")),
      nfe: texto(g(lin, "nfe")).replace(/\.0+$/, ""),
      qtd: numero(g(lin, "qtd")),
      item,
      familia: (item.match(/^[A-Z]+/) || ["OUTROS"])[0],
      transportadora: texto(g(lin, "transp")) || "Não informado",
      responsavel: texto(g(lin, "resp")).toUpperCase() || "NÃO INFORMADO",
      destino: texto(g(lin, "estoque")) || "Sem destino",
      motivo: texto(g(lin, "motivo")) || "Não informado",
      razao: texto(g(lin, "razao")),
      descarte: texto(g(lin, "descarte")),
      retrabalho: texto(g(lin, "retrab")),
    });
  }
  return out;
}

export function converterReceb(valores) {
  const cab = (valores[0] || []).map((c) => texto(c));
  const idx = (nome) => cab.findIndex((c) => c.toLowerCase() === nome.toLowerCase());
  const col = {
    id: idx("ORDER ID"), nf: idx("Nota fiscal"), forn: idx("Fornecedor"), emissao: idx("Data Emissão"),
    chegada: idx("Data de chegada"), xml: idx("Envio XML"), registro: idx("Data Registro"),
    internal: idx("Data Internalizada"), vol: idx("Volumes"), status: idx("Status do recebimento"),
    resp: idx("Responsável recebimento"), po: idx("PO"),
  };
  if (col.id < 0 || col.chegada < 0) throw new Error("Aba de recebimento sem as colunas 'ORDER ID' e 'Data de chegada'.");
  const g = (lin, k) => (col[k] < 0 ? "" : lin[col[k]]);
  const out = [];
  for (const lin of valores.slice(1)) {
    const id = texto(g(lin, "id"));
    const chegada = data(g(lin, "chegada"));
    if (!id || !chegada) continue;
    out.push({
      id,
      nf: texto(g(lin, "nf")).replace(/\.0+$/, ""),
      fornecedor: texto(g(lin, "forn")).toUpperCase() || "NÃO INFORMADO",
      emissao: data(g(lin, "emissao")),
      chegada,
      xml: data(g(lin, "xml")),
      registro: data(g(lin, "registro")),
      internalizada: data(g(lin, "internal")),
      volumes: numero(g(lin, "vol")),
      status: texto(g(lin, "status")) || "Sem status",
      responsavel: texto(g(lin, "resp")) || "Não informado",
      po: texto(g(lin, "po")),
    });
  }
  return out;
}

async function lerAba(token, id, aba) {
  const url =
    `https://sheets.googleapis.com/v4/spreadsheets/${id}/values/${encodeURIComponent(aba)}` +
    `?valueRenderOption=UNFORMATTED_VALUE&dateTimeRenderOption=SERIAL_NUMBER`;
  const r = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
  if (!r.ok) throw new Error(`Erro ao ler a aba "${aba}" (${r.status}): ${await r.text()}`);
  return (await r.json()).values || [];
}

export default async (req) => {
  try {
    await verificarUsuario(req);
    const forcar = new URL(req.url).searchParams.has("t");
    if (!forcar && CACHE.corpo && Date.now() - CACHE.t < CACHE_SEGUNDOS * 1000) return resposta(CACHE.corpo);
    const sa = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON || "{}");
    const bruto = process.env.SHEET_ID || "";
    const id = (bruto.match(/\/d\/([a-zA-Z0-9_-]+)/) || [null, bruto])[1];
    const aba = process.env.SHEET_TAB || "Página1";
    if (!sa.private_key || !id) throw new Error("Configure GOOGLE_SERVICE_ACCOUNT_JSON e SHEET_ID no Netlify.");

    const abaReceb = process.env.SHEET_TAB_RECEB || "Recebimento";
    const token = await tokenGoogle(sa);
    const [dev, rec] = await Promise.allSettled([lerAba(token, id, aba), lerAba(token, id, abaReceb)]);
    if (dev.status === "rejected") throw dev.reason;
    let recebimentos = [], erroReceb = null;
    if (rec.status === "fulfilled") {
      try { recebimentos = converterReceb(rec.value); } catch (e) { erroReceb = String(e.message || e); }
    } else erroReceb = String(rec.reason?.message || rec.reason);

    const corpo = JSON.stringify({ atualizadoEm: new Date().toISOString(), registros: converter(dev.value), recebimentos, erroReceb });
    CACHE = { t: Date.now(), corpo };
    return resposta(corpo);
  } catch (e) {
    return new Response(JSON.stringify({ erro: String(e.message || e), login: e.status === 401 || e.status === 403 }), {
      status: e.status || 500,
      headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
    });
  }
};

// Nunca deixar a CDN guardar: os dados só saem para quem fez login
function resposta(corpo) {
  return new Response(corpo, { headers: { "content-type": "application/json; charset=utf-8", "cache-control": "private, no-store" } });
}

export const config = { path: "/api/dados" };
