// Informa ao site qual é o ID do cliente do Google e o domínio liberado (dados públicos, sem segredo)
export default async () => {
  const dominio = (process.env.ALLOWED_DOMAIN || "zeb.mx").split(",")[0].trim().replace(/^@/, "").toLowerCase();
  return new Response(JSON.stringify({ clientId: process.env.GOOGLE_CLIENT_ID || "", dominio }), {
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
};

export const config = { path: "/api/config" };
