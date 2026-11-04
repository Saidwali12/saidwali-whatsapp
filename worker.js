
const cors = {
  "Access-Control-Allow-Origin": "https://saidwali12.github.io",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

function response(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...cors,
      "Content-Type": "application/json; charset=utf-8"
    }
  });
}

async function hash(value) {
  const result = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return [...new Uint8Array(result)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

async function makeToken(userId, secret) {
  const header = btoa(JSON.stringify({
    alg: "HS256",
    typ: "JWT"
  })).replace(/=/g, "");

  const payload = btoa(JSON.stringify({
    sub: userId,
    exp: Math.floor(Date.now() / 1000) + 2592000
  })).replace(/=/g, "");

  const message = header + "." + payload;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(message)
  );

  const encoded = btoa(
    String.fromCharCode(...new Uint8Array(signature))
  ).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");

  return message + "." + encoded;
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }

    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return response({
        ok: true,
        service: "Saidwali WhatsApp API",
        database: "D1"
      });
    }

    if (request.method !== "POST") {
      return response({ error: "Not found" }, 404);
    }

    const data = await readBody(request);

    if (url.pathname === "/auth/request-code") {
      const phone = String(data.phone || "");

      if (!/^\+[1-9]\d{7,14}$/.test(phone)) {
        return response({ error: "د موبایل شمېره ناسمه ده." }, 400);
      }

      if (env.DEMO_MODE !== "true") {
        return response({
          error: "د SMS خدمت لا نه دی فعال شوی."
        }, 503);
      }

      const code = "123456";
      const expires = Date.now() + 300000;

      await env.DB.prepare(`
        INSERT INTO otp_codes
        (phone, code_hash, expires_at, attempts)
        VALUES (?, ?, ?, 0)
        ON CONFLICT(phone) DO UPDATE SET
        code_hash=excluded.code_hash,
        expires_at=excluded.expires_at,
        attempts=0
      `).bind(phone, await hash(code), expires).run();

      return response({
        ok: true,
        mode: "demo",
        demoCode: code,
        expiresIn: 300
      });
    }

    if (url.pathname === "/auth/verify") {
      const phone = String(data.phone || "");
      const code = String(data.code || "");

      if (!/^\+[1-9]\d{7,14}$/.test(phone) ||
          !/^\d{6}$/.test(code)) {
        return response({ error: "شمېره یا کوډ ناسم دی." }, 400);
      }

      const otp = await env.DB.prepare(
        "SELECT * FROM otp_codes WHERE phone = ?"
      ).bind(phone).first();

      if (!otp ||
          otp.expires_at < Date.now() ||
          otp.attempts >= 5 ||
          await hash(code) !== otp.code_hash) {

        if (otp) {
          await env.DB.prepare(
            "UPDATE otp_codes SET attempts=attempts+1 WHERE phone=?"
          ).bind(phone).run();
        }

        return response({
          error: "کوډ ناسم دی یا وخت یې پای ته رسېدلی."
        }, 401);
      }

      let user = await env.DB.prepare(
        "SELECT id, phone FROM users WHERE phone=?"
      ).bind(phone).first();

      if (!user) {
        user = {
          id: crypto.randomUUID(),
          phone
        };

        await env.DB.prepare(
          "INSERT INTO users (id, phone, created_at) VALUES (?, ?, ?)"
        ).bind(user.id, phone, Date.now()).run();
      }

      await env.DB.prepare(
        "DELETE FROM otp_codes WHERE phone=?"
      ).bind(phone).run();

      const token = await makeToken(user.id, env.JWT_SECRET);

      await env.DB.prepare(`
        INSERT INTO sessions
        (token_hash, user_id, expires_at, created_at)
        VALUES (?, ?, ?, ?)
      `).bind(
        await hash(token),
        user.id,
        Date.now() + 2592000000,
        Date.now()
      ).run();

      return response({
        ok: true,
        token,
        user
      });
    }

    return response({ error: "Not found" }, 404);
  }
};
