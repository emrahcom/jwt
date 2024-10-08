import { encodeBase64Url } from "@std/encoding/base64url";
import { getAlgorithm } from "./algorithm.ts";
import { encoder, isNull } from "./util.ts";

import type { Algorithm } from "./algorithm.ts";

export async function verify(
  signature: Uint8Array,
  key: CryptoKey | null,
  alg: Algorithm,
  signingInput: string,
): Promise<boolean> {
  return isNull(key) ? signature.length === 0 : await crypto.subtle.verify(
    getAlgorithm(alg),
    key,
    signature,
    encoder.encode(signingInput),
  );
}

export async function create(
  alg: Algorithm,
  key: CryptoKey | null,
  signingInput: string,
): Promise<string> {
  return isNull(key) ? "" : encodeBase64Url(
    new Uint8Array(
      await crypto.subtle.sign(
        getAlgorithm(alg),
        key,
        encoder.encode(signingInput),
      ),
    ),
  );
}
