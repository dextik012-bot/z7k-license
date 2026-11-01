export default {
  async fetch(request, env) {
    const headers = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers });
    }

    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({ status: "online" }, { headers });
    }

    if (url.pathname !== "/activate" || request.method !== "POST") {
      return Response.json({ error: "Not found" }, {
        status: 404,
        headers
      });
    }

    try {
      const { key, deviceId } = await request.json();

      if (!key || !deviceId) {
        return Response.json({ error: "Missing data" }, {
          status: 400,
          headers
        });
      }

      const hash = async (value) => {
        const data = new TextEncoder().encode(value);
        const result = await crypto.subtle.digest("SHA-256", data);
        return [...new Uint8Array(result)]
          .map(b => b.toString(16).padStart(2, "0"))
          .join("");
      };

      const keyHash = await hash(key.trim().toUpperCase());
      const deviceHash = await hash(deviceId);

      const license = await env.DB
        .prepare("SELECT * FROM licenses WHERE key_hash = ? AND revoked = 0")
        .bind(keyHash)
        .first();

      if (!license) {
        return Response.json({ error: "Invalid key" }, {
          status: 403,
          headers
        });
      }

      if (!license.device_hash) {
        await env.DB.prepare(
          "UPDATE licenses SET device_hash = ?, activated_at = ? WHERE key_hash = ? AND device_hash IS NULL"
        ).bind(deviceHash, Date.now(), keyHash).run();

        const updated = await env.DB.prepare(
          "SELECT device_hash FROM licenses WHERE key_hash = ?"
        ).bind(keyHash).first();

        if (updated.device_hash !== deviceHash) {
          return Response.json({ error: "Key already used" }, {
            status: 403,
            headers
          });
        }
      } else if (license.device_hash !== deviceHash) {
        return Response.json({ error: "Key already used on another device" }, {
          status: 403,
          headers
        });
      }

      return Response.json({ success: true }, { headers });

    } catch (error) {
      return Response.json({ error: "Server error" }, {
        status: 500,
        headers
      });
    }
  }
};
