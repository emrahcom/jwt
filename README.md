# JWT

Create and verify JSON Web Tokens (JSON).

## API

Please use the native
[Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey)
to generate a **secure** `CryptoKey`.

```typescript
const key = await crypto.subtle.generateKey(
  { name: "HMAC", hash: "SHA-512" },
  true,
  ["sign", "verify"],
);
```

Or to generate a **secure** `CryptoKey` using a secret.

```typescript
const secret = "MYSECRET";
const encoder = new TextEncoder();
const keyData = encoder.encode(secret);
const key = await crypto.subtle.importKey(
  "raw",
  keyData,
  { name: "HMAC", hash: "SHA-512" },
  true,
  ["sign", "verify"],
);
```

### create

Takes `Header`, `Payload` and `CryptoKey` and returns the url-safe encoded
`jwt`.

```typescript
import { create } from "jsr:@emrahcom/jwt";

const jwt = await create({ alg: "HS512", typ: "JWT" }, { foo: "bar" }, key);
```

### verify

Takes `jwt`, `CryptoKey` and `VerifyOptions` and returns the `Payload` of the
`jwt` if the `jwt` is valid. Otherwise it throws an `Error`.

```typescript
import { verify } from "jsr:@emrahcom/jwt";

const payload = await verify(jwt, key); // { foo: "bar" }
```

### decode

Takes a `jwt` and returns a 3-tuple
`[header: unknown, payload: unknown, signature: Uint8Array]` if the `jwt` has a
valid _serialization_. Otherwise it throws an `Error`. This function does
**not** verify the digital signature.

```typescript
import { decode } from "jsr:@emrahcom/jwt";

const [header, payload, signature] = decode(jwt);
```

### getNumericDate

This helper function simplifies setting a
[NumericDate](https://tools.ietf.org/html/rfc7519#page-6). It takes either a
`Date` object or a `number` (in seconds) and returns the number of seconds from
1970-01-01T00:00:00Z UTC until the specified UTC date/time.

```typescript
import { getNumericDate } from "jsr:@emrahcom/jwt";

// A specific date:
const exp = getNumericDate(new Date("2025-07-01"));
// One hour from now:
const nbf = getNumericDate(60 * 60);
```

## Algorithms

The following signature and MAC algorithms have been implemented:

- HS256 (HMAC SHA-256)
- HS384 (HMAC SHA-384)
- HS512 (HMAC SHA-512)
- RS256 (RSASSA-PKCS1-v1_5 SHA-256)
- RS384 (RSASSA-PKCS1-v1_5 SHA-384)
- RS512 (RSASSA-PKCS1-v1_5 SHA-512)
- PS256 (RSASSA-PSS SHA-256)
- PS384 (RSASSA-PSS SHA-384)
- PS512 (RSASSA-PSS SHA-512)
- ES256 (ECDSA using P-256 and SHA-256)
- ES384 (ECDSA using P-384 and SHA-384)
- ES512 (ECDSA using P-521 and SHA-512) (Not supported yet!)
- none ([_Unsecured JWTs_](https://tools.ietf.org/html/rfc7519#section-6)).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file
for details.

This project is a fork of [Zaubrik/djwt](https://github.com/Zaubrik/djwt)
