// Netlify Function: lê o Google Sheets do AppSheet e devolve os registros em JSON.
// Variáveis de ambiente (Netlify > Site configuration > Environment variables):
//   GOOGLE_SERVICE_ACCOUNT_JSON  -> conteúdo completo do arquivo .json da conta de serviço
//   SHEET_ID                     -> ID ou link completo da planilha
//   SHEET_TAB                    -> aba das devoluções (padrão: Página1)
//   SHEET_TAB_RECEB              -> aba dos recebimentos (padrão: Recebimento)
import crypto from "node:crypto";

const CACHE_SEGUNDOS = 15 * 60; // a CDN do Netlify guarda a resposta por 15 min

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

export default async () => {
  try {
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
    return new Response(corpo, {
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "public, max-age=0, must-revalidate",
        "netlify-cdn-cache-control": `public, durable, s-maxage=${CACHE_SEGUNDOS}, stale-while-revalidate=120`,
      },
    });
  } catch (e) {
    return new Response(JSON.stringify({ erro: String(e.message || e) }), {
      status: 500,
      headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
    });
  }
};

export const config = { path: "/api/dados" };
