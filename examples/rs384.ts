// -----------------------------------------------------------------------------
// Run:
//   deno run --allow-net rs384.ts
//
// Request JWT:
//   curl http://0.0.0.0:8000/
//
// Decode JWT:
//   curl -d "your_jwt" http://0.0.0.0:8000/
// -----------------------------------------------------------------------------

import { create, getNumericDate, verify } from "@emrahcom/jwt";
import type { Header, Payload } from "@emrahcom/jwt";

// If you dont have deno.json and @emrahcom/jwt is not in its import list
// then use these import lines:
// import { create, getNumericDate, verify } from "jsr:@emrahcom/jwt@^0.4.6";
// import type { Header, Payload } from "jsr:@emrahcom/jwt@^0.4.6";

const { privateKey, publicKey } = await crypto.subtle.generateKey(
  {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 4096,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-384",
  },
  true,
  ["verify", "sign"],
);

const payload: Payload = {
  sub: "1234567890",
  name: "John Doe",
  admin: true,
  iat: getNumericDate(0),
};

const header: Header = {
  alg: "RS384",
  typ: "JWT",
};

async function handleRequest(request: Request) {
  if (request.method === "GET") {
    const jwt = await create(header, payload, privateKey);
    return new Response(jwt + "\n");
  } else if (request.method === "POST") {
    try {
      const jwt = await request.text();
      const verifiedPayload = await verify(jwt, publicKey);
      return Response.json(verifiedPayload);
    } catch {
      return new Response("Invalid JWT\n", { status: 401 });
    }
  }

  return new Response("Method not allowed\n", { status: 405 });
}

Deno.serve(handleRequest);
