// -----------------------------------------------------------------------------
// Run:
//   deno run --allow-net hs512.ts
//
// Request JWT:
//   curl http://0.0.0.0:8000/
//
// Decode JWT:
//   curl -d "your_jwt" http://0.0.0.0:8000/
// -----------------------------------------------------------------------------

// Check the commented import options if you dont have deno.json
import { create, getNumericDate, verify } from "@emrahcom/jwt";
import type { Header, Payload } from "@emrahcom/jwt";

// If you dont have deno.json and @emrahcom/jwt is not in its import list
// then use these import lines:
//import { create, getNumericDate, verify } from "jsr:@emrahcom/jwt@^0.4.6";
//import type { Header, Payload } from "jsr:@emrahcom/jwt@^0.4.6";

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
    const jwt = await create(header, payload, key);
    return new Response(jwt + "\n");
  } else if (request.method === "POST") {
    try {
      const jwt = await request.text();
      const verifiedPayload = await verify(jwt, key);
      return Response.json(verifiedPayload);
    } catch {
      return new Response("Invalid JWT\n", { status: 401 });
    }
  }

  return new Response("Method not allowed\n", { status: 405 });
}

Deno.serve(handleRequest);
