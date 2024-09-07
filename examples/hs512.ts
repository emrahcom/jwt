// -----------------------------------------------------------------------------
// Request JWT:
//   curl http://0.0.0.0:8000/
//
// Decode JWT:
//   curl -d "your_jwt" http://0.0.0.0:8000/
// -----------------------------------------------------------------------------

import { create, getNumericDate, verify } from "jsr:@emrahcom/jwt";
import type { Header, Payload } from "jsr:@emrahcom/jwt";

const key = await crypto.subtle.generateKey(
  { name: "HMAC", hash: "SHA-512" },
  true,
  ["sign", "verify"],
);
const payload: Payload = {
  iss: "joe",
  exp: getNumericDate(300),
};
const header: Header = {
  alg: "HS512",
  typ: "JWT",
};

async function handleRequest(request: Request) {
  if (request.method === "GET") {
    return new Response(await create(header, payload, key) + "\n");
  } else {
    try {
      const jwt = await request.text();
      const payload = await verify(jwt, key);
      return Response.json(payload);
    } catch {
      return new Response("Invalid JWT\n", { status: 401 });
    }
  }
}

Deno.serve(handleRequest);
