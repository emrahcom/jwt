// -----------------------------------------------------------------------------
// Request JWT:
//   curl http://0.0.0.0:8000/
//
// Decode JWT:
//   curl -d "your_jwt" http://0.0.0.0:8000/
// -----------------------------------------------------------------------------

import { create, getNumericDate, verify } from "jsr:@emrahcom/jwt";
import type { Header, Payload } from "jsr:@emrahcom/jwt";

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
    return new Response(await create(header, payload, privateKey) + "\n");
  } else {
    try {
      const jwt = await request.text();
      const payload = await verify(jwt, publicKey);
      return Response.json(payload);
    } catch {
      return new Response("Invalid JWT\n", { status: 401 });
    }
  }
}

Deno.serve(handleRequest);
